import { textEncoder } from "unsecure/utils";
import type {
  JWK,
  ContentEncryptionAlgorithm,
  JWEEncryptOptions,
  JWEKeyManagementHeaderParameters,
  JWK_EC_Public,
  JWK_EC_Private,
  JWK_OKP_Public,
  JWK_OKP_Private,
  JWKAlgorithm,
  KeyManagementAlgorithm,
} from "../types/index.ts";
import { JWTError } from "../../error.ts";
import { isPBES2Algorithm, jwkAlgServes } from "../../utils/algorithms.ts";
import { hasSymmetricSecret, isCryptoKey, isCryptoKeyPair, isJWK } from "../../utils/guards.ts";
import { MAX_PARTY_INFO_BYTES } from "./limits.ts";
import { asKeyLookupError } from "./errors.ts";

/** RFC 7518 §4.6.1.2 / §4.6.1.3 — `apu` / `apv` are bytes within `MAX_PARTY_INFO_BYTES`. */
export function assertProducerPartyInfo(name: "apu" | "apv", value: unknown): void {
  if (!(value instanceof Uint8Array)) {
    throw new JWTError(
      `"${name === "apu" ? "partyUInfo" : "partyVInfo"}" (${name}) must be a Uint8Array.`,
      "ERR_INVALID_OPTION",
    );
  }
  if (value.length > MAX_PARTY_INFO_BYTES) {
    throw new JWTError(
      `"${name === "apu" ? "partyUInfo" : "partyVInfo"}" (${name}) must not exceed ${MAX_PARTY_INFO_BYTES} bytes (got ${value.length}).`,
      "ERR_INVALID_OPTION",
    );
  }
}

export type JWKSetOperation = "sig" | "enc";

/** RFC 7517 §4.3 — `key_ops` values that serve each operation. */
const JWK_SET_KEY_OPS: Readonly<Record<JWKSetOperation, readonly string[]>> =
  /* @__PURE__ */ Object.freeze({
    sig: ["verify"],
    enc: ["unwrapKey", "decrypt", "deriveBits", "deriveKey"],
  });

/** JWK Set candidate filter by `kid`/`alg`/`use`/`key_ops`; entries carrying `k` only with `allowSymmetric`. */
export function buildJWKSetFilter(
  header: { kid?: string; alg?: JWKAlgorithm } | undefined,
  options: { op: JWKSetOperation; allowSymmetric?: boolean },
): (k: JWK) => boolean {
  const kid = header?.kid;
  const alg = header?.alg;
  const { op, allowSymmetric } = options;
  const use = op;
  const keyOps = JWK_SET_KEY_OPS[op];
  return (k) => {
    if (!isJWK(k)) return false;
    if (!allowSymmetric && hasSymmetricSecret(k)) return false;
    if (kid && k.kid !== kid) return false;
    if (k.alg && !(alg && jwkAlgServes({ kty: k.kty, alg: k.alg }, alg))) return false;
    if (k.use !== undefined && k.use !== use) return false;
    const ops = k.key_ops;
    if (ops !== undefined && !(Array.isArray(ops) && ops.some((o) => keyOps.includes(o)))) {
      return false;
    }
    return true;
  };
}

/** Normalize a caller's ECDH-ES ephemeral key into `{ epk, epkPrivateKey }`. */
export function parseEphemeralKey(
  ephemeralKey: NonNullable<JWEEncryptOptions["ecdh"]>["ephemeralKey"],
): {
  epk: CryptoKey | JWK_EC_Public | JWK_OKP_Public;
  epkPrivateKey: CryptoKey | JWK_EC_Private | JWK_OKP_Private;
} {
  if (isCryptoKeyPair(ephemeralKey)) {
    return { epk: ephemeralKey.publicKey, epkPrivateKey: ephemeralKey.privateKey };
  }
  if (
    typeof ephemeralKey === "object" &&
    ephemeralKey !== null &&
    "publicKey" in ephemeralKey &&
    "privateKey" in ephemeralKey
  ) {
    if (!ephemeralKey.publicKey || !ephemeralKey.privateKey) {
      throw new JWTError(
        "ECDH-ES custom ephemeral key must include both publicKey and privateKey.",
        "ERR_JWK_INVALID",
      );
    }
    return { epk: ephemeralKey.publicKey, epkPrivateKey: ephemeralKey.privateKey };
  }
  if (isCryptoKey(ephemeralKey)) {
    if (ephemeralKey.type !== "private") {
      throw new JWTError(
        "ECDH-ES custom ephemeral CryptoKey must include private key material.",
        "ERR_JWK_INVALID",
      );
    }
    return { epk: ephemeralKey, epkPrivateKey: ephemeralKey };
  }
  if (isJWK(ephemeralKey)) {
    if (!("d" in ephemeralKey) || typeof ephemeralKey.d !== "string") {
      throw new JWTError(
        'ECDH-ES custom ephemeral JWK must include private parameter "d".',
        "ERR_JWK_INVALID",
      );
    }
    return {
      epk: ephemeralKey,
      epkPrivateKey: ephemeralKey,
    };
  }
  throw new JWTError("Unsupported ECDH-ES ephemeral key material provided.", "ERR_JWK_INVALID");
}

/** RFC 7518 §4.6.1.2 / §4.6.1.3 — ECDH-ES agreement params; an empty `apu` / `apv` is omitted. */
export function buildECDHAgreementParams(
  ecdh: JWEEncryptOptions["ecdh"],
): Pick<JWEKeyManagementHeaderParameters, "apu" | "apv" | "epk" | "epkPrivateKey"> {
  const params: Pick<JWEKeyManagementHeaderParameters, "apu" | "apv" | "epk" | "epkPrivateKey"> =
    {};
  if (!ecdh) return params;
  const { partyUInfo, partyVInfo, ephemeralKey } = ecdh;
  if (partyUInfo !== undefined) {
    assertProducerPartyInfo("apu", partyUInfo);
    if (partyUInfo.length > 0) params.apu = partyUInfo;
  }
  if (partyVInfo !== undefined) {
    assertProducerPartyInfo("apv", partyVInfo);
    if (partyVInfo.length > 0) params.apv = partyVInfo;
  }
  if (ephemeralKey) {
    const { epk, epkPrivateKey } = parseEphemeralKey(ephemeralKey);
    params.epk = epk;
    params.epkPrivateKey = epkPrivateKey;
  }
  return params;
}

export function stringKeyError(): JWTError {
  return new JWTError(
    "Key must be a JWK, CryptoKey or Uint8Array, not a string.",
    "ERR_JWK_INVALID",
  );
}

/** RFC 7518 §4.8.1 — a string key is a UTF-8 PBES2 password, refused under any other `alg`. */
export function resolvePasswordKey<K>(
  alg: KeyManagementAlgorithm,
  key: K | string,
): K | Uint8Array<ArrayBuffer> {
  if (typeof key !== "string") return key;
  if (!isPBES2Algorithm(alg)) throw stringKeyError();
  return textEncoder.encode(key);
}

export type ResolvedKeyInput<K> = K extends (...args: never[]) => infer R
  ? NonNullable<Awaited<R>>
  : K;

/** Run a key-lookup function; a throw or no key is `ERR_JWK_KEY_NOT_FOUND`. */
export async function resolveKeyInput<K>(
  key: K,
  options: { header: unknown; token: string; what: string },
): Promise<ResolvedKeyInput<K>>;
export async function resolveKeyInput(
  key: unknown,
  options: { header: unknown; token: string; what: string },
): Promise<unknown> {
  if (typeof key !== "function") return key;
  const { header, token, what } = options;
  let resolved: unknown;
  try {
    resolved = await key(header, token);
  } catch (error) {
    throw asKeyLookupError(error, what);
  }
  if (resolved === undefined || resolved === null) {
    throw new JWTError(`Key lookup returned no key for ${what}.`, "ERR_JWK_KEY_NOT_FOUND");
  }
  return resolved;
}

/** RFC 7518 §4.5 — a `dir` JWK's `alg` is `dir` or the token's `enc`. */
export function assertDirectKeyRole(
  key: unknown,
  enc: ContentEncryptionAlgorithm | undefined,
): void {
  if (!isJWK(key) || typeof key.alg !== "string" || key.alg === "dir") return;
  if (enc !== undefined && key.alg === enc) return;
  throw new JWTError(
    `JWK "alg" is "${key.alg}" but "dir" requires "dir" or the token's "enc".`,
    "ERR_JWK_INVALID",
  );
}
