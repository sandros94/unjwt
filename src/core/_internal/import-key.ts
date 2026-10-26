import type {
  JWK,
  JWKSet,
  JWK_oct,
  JWKAlgorithm,
  JWKCacheAdapter,
  ImportedKey,
} from "../types/index.ts";
import { decodeSegment } from "./headers.ts";
import { stringKeyError } from "./keys.ts";
import { hasMisplacedSecret, isCryptoKey, isJWK, isJWKSet } from "../../utils/guards.ts";
import { jwkAlgServes, jwkKtyServes } from "../../utils/algorithms.ts";
import { JWTError } from "../../error.ts";
import { jwkTokey, assertOctKeyLength } from "../_crypto/index.ts";

/**
 * The default JWK import cache, keyed by JWK object identity and `alg`. A copied JWK misses it.
 * A JWK mutated in place keeps returning the old `CryptoKey`: rotate a key by replacing the object.
 */
export class WeakMapJWKCache implements JWKCacheAdapter {
  private readonly _map = new WeakMap<object, Record<string, CryptoKey>>();

  get(jwk: JWK, alg: JWKAlgorithm): CryptoKey | undefined {
    return this._map.get(jwk)?.[alg];
  }

  set(jwk: JWK, alg: JWKAlgorithm, key: CryptoKey): void {
    let entry = this._map.get(jwk);
    if (!entry) {
      this._map.set(jwk, { [alg]: key });
    } else {
      entry[alg] = key;
    }
  }
}

let _activeCache: JWKCacheAdapter | false = new WeakMapJWKCache();

/**
 * Replaces the JWK import cache `importKey` uses, or disables it with `false`.
 *
 * A cache shared across JWK objects keys on the RFC 7638 thumbprint, the pair half (`d` present)
 * and `alg`. The thumbprint covers public members only, and one `kid` may name different keys.
 * `get` and `set` may return promises.
 *
 * @example
 * ```ts
 * const cacheKey = async (jwk: JWK, alg: JWKAlgorithm) =>
 *   `${await thumbprint(jwk)}:${"d" in jwk ? "private" : "public"}:${alg}`;
 * const map = new Map<string, CryptoKey>();
 * configureJWKCache({
 *   get: async (jwk, alg) => map.get(await cacheKey(jwk, alg)),
 *   set: async (jwk, alg, key) => {
 *     map.set(await cacheKey(jwk, alg), key);
 *   },
 * });
 * ```
 */
export function configureJWKCache(cache: JWKCacheAdapter | false): void {
  _activeCache = cache;
}

/** Resets the JWK import cache to a fresh `WeakMapJWKCache`. */
export function clearJWKCache(): void {
  _activeCache = new WeakMapJWKCache();
}

/**
 * Imports the secret of an `oct` JWK as a `CryptoKey` under `algorithm` and `usage`.
 * @throws `ERR_JWK_INVALID` if `algorithm` or `usage` is absent, or the secret is too short for the HMAC hash or the JWK `alg`.
 */
export async function importKey(
  key: JWK_oct,
  options: {
    asCryptoKey: true;
    /** The Web Crypto algorithm to import the key as, such as `{ name: "AES-GCM", length: 256 }`. */
    algorithm: Parameters<typeof crypto.subtle.importKey>[2];
    usage: KeyUsage[];
    /** Whether the key is extractable. @default false */
    extractable?: boolean;
  },
): Promise<CryptoKey>;
/**
 * Imports key material. A `CryptoKey` or `Uint8Array` is returned as is, an `oct` JWK as its raw
 * bytes, an asymmetric JWK as a `CryptoKey` under its own `alg` or the requested one.
 *
 * A JWK's `alg` is authoritative (RFC 7517 §4.4). An `oct` JWK with a content encryption `alg`
 * also serves `"dir"`. A JWK without `alg` must have a `kty` that can serve the requested `alg`.
 * An `oct` secret must be long enough for its `alg`. A non-`oct` JWK must not have a `k` member.
 * `expect` and `extractable` apply to asymmetric keys only. Passing `extractable` skips the import cache.
 *
 * @throws `ERR_JWK_INVALID` if `key` is a string or not key material, or breaks one of the rules above.
 */
export async function importKey<K extends CryptoKey | JWK | Uint8Array<ArrayBuffer>>(
  key: K,
  options?:
    | JWKAlgorithm
    | {
        /** The algorithm to import under. Required for an asymmetric JWK without `alg`. */
        alg?: JWKAlgorithm;
        /** The pair half the key must be. The other half is `ERR_JWK_INVALID`. */
        expect?: "public" | "private";
        /** Whether the `CryptoKey` is extractable. A JWK `ext: false` overrides it. @default false for private keys, true for public keys */
        extractable?: boolean;
      },
): Promise<ImportedKey<K>>;
export async function importKey(
  key: CryptoKey | JWK | Uint8Array<ArrayBuffer>,
  algOrOptions?:
    | JWKAlgorithm
    | {
        asCryptoKey?: true;
        algorithm?: Parameters<typeof crypto.subtle.importKey>[2];
        usage?: KeyUsage[];
        extractable?: boolean;
        alg?: JWKAlgorithm;
        expect?: "public" | "private";
      },
): Promise<CryptoKey | Uint8Array<ArrayBuffer>> {
  const alg = typeof algOrOptions === "string" ? algOrOptions : (algOrOptions?.alg ?? undefined);
  const expect = typeof algOrOptions === "object" ? (algOrOptions.expect ?? undefined) : undefined;
  const extractable =
    typeof algOrOptions === "object" && !algOrOptions.asCryptoKey
      ? algOrOptions.extractable
      : undefined;

  if (typeof key === "string") {
    throw stringKeyError();
  }

  if (key instanceof Uint8Array) {
    return key;
  }

  if (isCryptoKey(key)) {
    assertIntentOnCryptoKey(key, expect);
    return key;
  }

  if (isJWK(key)) {
    if (hasMisplacedSecret(key)) {
      throw new JWTError(
        `JWK "k" is defined only for "oct" keys, not "${key.kty}".`,
        "ERR_JWK_INVALID",
      );
    }
    assertJWKAlgAuthority(key, alg);
    if (key.kty === "oct" && typeof key.k === "string") {
      const rawBytes = decodeSegment(key.k, { family: "JWK", what: '"k"' });
      assertOctKeyLength(rawBytes, alg ?? key.alg);
      if (typeof algOrOptions === "object" && algOrOptions.asCryptoKey) {
        const { algorithm, usage, extractable: rawExtractable = false } = algOrOptions;
        if (!algorithm || !usage) {
          throw new JWTError(
            "asCryptoKey option requires `algorithm` and `usage` to be provided.",
            "ERR_JWK_INVALID",
          );
        }
        if (typeof algorithm === "object" && algorithm.name === "HMAC") {
          const hash: unknown = "hash" in algorithm ? algorithm.hash : undefined;
          const hashName =
            typeof hash === "string"
              ? hash
              : typeof hash === "object" &&
                  hash !== null &&
                  "name" in hash &&
                  typeof hash.name === "string"
                ? hash.name
                : undefined;
          const minBytes = Number.parseInt(hashName?.slice(-3) ?? "", 10) / 8;
          if (minBytes && rawBytes.length < minBytes) {
            throw new JWTError(
              `HMAC with ${hashName} requires a key of at least ${minBytes} bytes (got ${rawBytes.length})`,
              "ERR_JWK_INVALID",
            );
          }
        }
        return crypto.subtle.importKey("raw", rawBytes, algorithm, rawExtractable, usage);
      }
      return rawBytes;
    } else {
      const effectiveAlg = key.alg || alg;
      if (!effectiveAlg) {
        throw new JWTError(
          "Algorithm must be provided when importing non-oct JWK",
          "ERR_JWK_INVALID",
        );
      }
      assertIntentOnJWK(key, expect);
      const cache = extractable === undefined ? _activeCache : false;
      if (cache) {
        const cached = await cache.get(key, effectiveAlg);
        if (cached) return cached;
      }
      const cryptoKey = await jwkTokey(key, { extractable, alg });
      if (cache) await cache.set(key, effectiveAlg, cryptoKey);
      return cryptoKey;
    }
  }

  throw new JWTError("Invalid key type provided to importKey", "ERR_JWK_INVALID");
}

/** RFC 7517 §4.4: a JWK's `alg` is authoritative, except an `oct` CEK used by `dir`. Without `alg`, `kty` must serve the request. */
function assertJWKAlgAuthority(jwk: JWK, alg: JWKAlgorithm | undefined): void {
  if (!alg) return;
  if (jwk.alg) {
    if (jwkAlgServes({ kty: jwk.kty, alg: jwk.alg }, alg)) return;
    throw new JWTError(
      `JWK "alg" is "${jwk.alg}" but the operation requires "${alg}".`,
      "ERR_JWK_INVALID",
    );
  }
  if (jwkKtyServes(jwk.kty, alg)) return;
  throw new JWTError(`JWK "kty" is "${jwk.kty}", which cannot serve "${alg}".`, "ERR_JWK_INVALID");
}

function assertIntentOnJWK(jwk: JWK, expect: "public" | "private" | undefined): void {
  if (expect === undefined || jwk.kty === "oct") return;
  const hasPrivateScalar = "d" in jwk && typeof (jwk as { d?: unknown }).d === "string";
  if (expect === "public" && hasPrivateScalar) {
    throw new JWTError("Private JWK passed where a public key is expected.", "ERR_JWK_INVALID");
  }
  if (expect === "private" && !hasPrivateScalar) {
    throw new JWTError("Public JWK passed where a private key is expected.", "ERR_JWK_INVALID");
  }
}

function assertIntentOnCryptoKey(key: CryptoKey, expect: "public" | "private" | undefined): void {
  if (expect === undefined || key.type === "secret") return;
  if (expect === "public" && key.type === "private") {
    throw new JWTError(
      "Private CryptoKey passed where a public key is expected.",
      "ERR_JWK_INVALID",
    );
  }
  if (expect === "private" && key.type === "public") {
    throw new JWTError(
      "Public CryptoKey passed where a private key is expected.",
      "ERR_JWK_INVALID",
    );
  }
}

/**
 * Returns the JWKs of a JWK Set without its non-JWK entries, narrowed by `filter` when given.
 *
 * @throws `ERR_JWK_INVALID` if `jwkSet` is not a JWK Set.
 */
export function getJWKsFromSet(jwkSet: JWKSet, filter?: (jwk: JWK) => boolean): JWK[] {
  if (!jwkSet || !isJWKSet(jwkSet)) {
    throw new JWTError("Invalid JWK Set provided", "ERR_JWK_INVALID");
  }

  const keys = jwkSet.keys.filter((key) => isJWK(key));

  return filter ? keys.filter(filter) : keys;
}
