import type {
  ContentEncryptionAlgorithm,
  JWEDecryptJWK,
  JWKSet,
  KeyManagementAlgorithm,
} from "../../core/types/index.ts";
import {
  isAsymmetricJWK,
  isCryptoKey,
  isJWK,
  isJWKSet,
  isSymmetricJWK,
} from "../../utils/guards.ts";
import type { JWTError } from "../../error.ts";
import { assertKeyMaterial, invalidConfigError, invalidKeyError } from "./contract.ts";
import { isKeyPair } from "./codec.ts";
import { quoteTokenValue } from "../../utils/_internal/text.ts";
import { type SessionKeyEntry, servedAlgorithms } from "./key-algorithms.ts";
import { JWE_KEY_ALGORITHMS, assertIssuingKey, directEncryptions } from "./key-algorithms-jwe.ts";

/** An `oct` JWK that JWE key management accepts. */
export type JWESessionOctJWK = Extract<JWEDecryptJWK, { kty: "oct" }>;

/** One symmetric key: an `oct` JWK, or a secret `CryptoKey`. To encrypt, a key without `alg` (any `CryptoKey`) requires a pinned `jwe.encryptOptions.alg` and `enc`. */
export type JWESessionSecret = JWESessionOctJWK | CryptoKey;

/**
 * A symmetric key that encrypts and decrypts, or a rotation set: `current` encrypts (its `kid` is written to the header) and decrypts,
 * and `keys` decrypt too. A token that names a `kid` is tried with the keys of that `kid` alone, one that names none with every key;
 * of those, the keys that serve its `alg` are tried in order, `current` first. An asymmetric key throws `ERR_SESSION_KEY_INVALID`:
 * its public half encrypts, so anyone holding that half could forge a session the server accepts. Use `defineJWSSession` for a key pair.
 */
export type JWESessionKey =
  | JWESessionSecret
  | {
      /** Encrypts every token, and decrypts. */
      current: JWESessionSecret;
      /**
       * Decrypt too, `current` need not be repeated: `oct` JWKs and secret `CryptoKey`s, or a JWK Set of `oct` JWKs.
       * At most `jwe.decryptOptions.limits.keyCandidates` keys, `current` included, may lack a `kid`, as any `CryptoKey` does.
       */
      keys: JWESessionSecret[] | JWKSet<JWESessionOctJWK[]>;
    };

/** A key that decrypts: its `kid`, the algorithms it serves and, should it serve `dir`, the `enc` values it decrypts. */
export interface JWESessionEntry {
  key: JWESessionSecret;
  kid: string | undefined;
  algorithms: readonly KeyManagementAlgorithm[];
  encryptions: readonly ContentEncryptionAlgorithm[];
}

/**
 * Resolves and checks the configured keys: `current`, which encrypts, and every key that decrypts, `current` first.
 * `algorithms` is what they serve together, the `alg` values an incoming token may carry. `rotation` is set for a `{ current, keys }` set.
 * @throws `ERR_SESSION_CONFIG_INVALID` if more keys without `kid` than `keyCandidates` decrypt, unless a key lookup opens tokens.
 */
export function resolveSessionKeys(
  key: unknown,
  options: {
    alg: KeyManagementAlgorithm | undefined;
    enc: ContentEncryptionAlgorithm | undefined;
    listed: KeyManagementAlgorithm[] | undefined;
    keyCandidates: number;
    lookup: boolean;
    prefix: string;
  },
): {
  current: JWESessionSecret;
  entries: JWESessionEntry[];
  rotation: boolean;
  algorithms: KeyManagementAlgorithm[];
} {
  const { alg, enc, listed, keyCandidates, lookup, prefix } = options;
  const { current, previous } = sessionKeys(key, prefix);
  const subject = previous ? 'The session key "current"' : "The session key";
  assertIssuingKey(current, { alg, enc, subject, prefix });
  const named: (SessionKeyEntry & { key: JWESessionSecret })[] = [
    { key: current, subject, pin: alg },
  ];
  previous?.forEach((entry, index) => {
    if (entry === current) return;
    const kid = kidOf(entry) === undefined ? "" : ` (kid ${quoteTokenValue(kidOf(entry))})`;
    named.push({ key: entry, subject: `The session key "keys[${index}]"${kid}` });
  });
  const kidless = named.filter((entry) => kidOf(entry.key) === undefined).length;
  if (!lookup && kidless > keyCandidates) {
    throw invalidConfigError(
      `${prefix} ${kidless} session keys carry no "kid", over the limit of ${keyCandidates} ("jwe.decryptOptions.limits.keyCandidates"): give each JWK a "kid", drop former keys, or raise the limit.`,
    );
  }
  const served = servedAlgorithms(named, {
    algorithms: JWE_KEY_ALGORITHMS,
    listed,
    listPath: "jwe.decryptOptions.algorithms",
    lookup,
    prefix,
  });
  return {
    current,
    entries: named.map((entry, index) => ({
      key: entry.key,
      kid: kidOf(entry.key),
      algorithms: served.each[index],
      encryptions:
        entry.key === current && alg === "dir" && enc ? [enc] : directEncryptions(entry.key),
    })),
    rotation: previous !== undefined,
    algorithms: served.all,
  };
}

export function rotationSet(key: unknown): { current: unknown; keys?: unknown } | undefined {
  return isObject(key) && "current" in key ? key : undefined;
}

/** The configured key and rotation keys. Asymmetric material throws: its public half encrypts, so its holder could forge sessions. */
function sessionKeys(
  key: unknown,
  prefix: string,
): { current: JWESessionSecret; previous?: JWESessionSecret[] } {
  assertKeyMaterial(key, { prefix });
  const set = rotationSet(key);
  if (!set) return { current: sessionSecret(key, { prefix, what: "" }) };

  const previous: unknown = isJWKSet(set.keys) ? set.keys.keys : set.keys;
  if (!Array.isArray(previous)) {
    throw invalidKeyError(
      `${prefix} Invalid JWE session key: "keys" must be a list of "oct" JWKs and secret CryptoKeys, or a JWK Set of "oct" JWKs.`,
      key,
    );
  }
  return {
    current: sessionSecret(set.current, { prefix, what: '"current"' }),
    previous: previous.map((entry: unknown) =>
      sessionSecret(entry, { prefix, what: 'each of "keys"' }),
    ),
  };
}

function sessionSecret(key: unknown, options: { prefix: string; what: string }): JWESessionSecret {
  if (isOctJWK(key)) return key;
  if (isCryptoKey(key) && key.type === "secret") return key;
  const expected = options.what
    ? `${options.what} must be an "oct" JWK or a secret CryptoKey`
    : 'expected an "oct" JWK, a secret CryptoKey or { current, keys }';
  throw keyError(key, { prefix: options.prefix, expected });
}

function keyError(
  key: unknown,
  options: { prefix: string; expected: string },
): JWTError<"ERR_SESSION_KEY_INVALID"> {
  const asymmetric = isCryptoKey(key)
    ? key.type !== "secret"
    : isAsymmetricJWK(key) || (isObject(key) && isKeyPair(key));
  if (asymmetric) {
    return invalidKeyError(
      `${options.prefix} Invalid JWE session key: an asymmetric key seals with its public half, so anyone holding that half could mint sessions. Use an "oct" JWK, or defineJWSSession for a key pair.`,
      key,
    );
  }
  return invalidKeyError(`${options.prefix} Invalid JWE session key: ${options.expected}.`, key);
}

function kidOf(key: JWESessionSecret): string | undefined {
  return isJWK(key) ? key.kid : undefined;
}

/** An `oct` JWK. An `alg` outside JWE fails when the key is imported. */
function isOctJWK(key: unknown): key is JWESessionOctJWK {
  return isSymmetricJWK(key);
}

function isObject(value: unknown): value is object {
  return typeof value === "object" && value !== null;
}
