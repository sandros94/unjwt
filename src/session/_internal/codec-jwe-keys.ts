import type {
  ContentEncryptionAlgorithm,
  JWEDecryptJWK,
  JWKSet,
  KeyManagementAlgorithm,
} from "../../core/types/index.ts";
import { isAsymmetricJWK, isCryptoKey, isJWKSet, isSymmetricJWK } from "../../utils/guards.ts";
import type { JWTError } from "../../error.ts";
import { assertKeyMaterial, invalidKeyError } from "./contract.ts";
import { isKeyPair } from "./codec.ts";
import { type SessionOpeners, resolveKeySet, rotationSet } from "./key-set.ts";
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

/**
 * Resolves and checks the configured keys: `current`, which encrypts, and every key that decrypts, `current` first.
 * `algorithms` is what they serve together, the `alg` values an incoming token may carry. A `dir` key decrypts the pinned `enc`
 * when it is `current`, else every `enc` its length fits.
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
): SessionOpeners<JWESessionSecret, KeyManagementAlgorithm> & { current: JWESessionSecret } {
  const { alg, enc, prefix } = options;
  const { current, previous } = sessionKeys(key, prefix);
  const subject = previous ? 'The session key "current"' : "The session key";
  assertIssuingKey(current, { alg, enc, subject, prefix });
  const set = resolveKeySet(current, previous, {
    ...options,
    algorithms: JWE_KEY_ALGORITHMS,
    pin: alg,
    optionsPath: "jwe.decryptOptions",
  });
  return {
    ...set,
    current,
    entries: set.entries.map((entry) => ({
      ...entry,
      encryptions:
        entry.key === current && alg === "dir" && enc ? [enc] : directEncryptions(entry.key),
    })),
  };
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

/** An `oct` JWK. An `alg` outside JWE fails when the key is imported. */
function isOctJWK(key: unknown): key is JWESessionOctJWK {
  return isSymmetricJWK(key);
}

function isObject(value: unknown): value is object {
  return typeof value === "object" && value !== null;
}
