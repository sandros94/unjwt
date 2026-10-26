import type {
  ContentEncryptionAlgorithm,
  JWEDecryptJWK,
  JWKSet,
  KeyManagementAlgorithm,
} from "../../core/types/index.ts";
import { lengthOf } from "../../core/_crypto/_key-algorithm.ts";
import {
  PBES2_ALGORITHMS,
  inferJWEAllowedAlgorithms,
  isContentEncryptionAlgorithm,
} from "../../utils/algorithms.ts";
import { isAsymmetricJWK, isCryptoKey, isJWK, isSymmetricJWK } from "../../utils/guards.ts";
import type { JWTError } from "../../error.ts";
import { assertKeyMaterial, invalidKeyError } from "./contract.ts";
import { isKeyPair } from "./codec.ts";
import {
  type KeyAlgorithms,
  type SessionKeyEntry,
  assertPinnedKey,
  octBits,
  openingKey,
  rotationEntries,
  rotationSet,
  servedAlgorithms,
} from "./key-algorithms.ts";

/** An `oct` JWK that JWE key management accepts. */
export type JWESessionOctJWK = Extract<JWEDecryptJWK, { kty: "oct" }>;

/**
 * A symmetric key that encrypts and decrypts, an `oct` JWK or a secret `CryptoKey`, or a rotation set of `oct` JWKs: `current`
 * encrypts (its `kid` is written to the header) and decrypts, and `keys` decrypt too. A token that names a `kid` is tried with the
 * keys of that `kid` alone, one that names none with every key; of those, the keys that serve its `alg` are tried in order, `current`
 * first. To encrypt, a key without `alg` (any `CryptoKey`) requires a pinned `jwe.encryptOptions.alg` and `enc`. An asymmetric key
 * throws `ERR_SESSION_KEY_INVALID`: its public half encrypts, so anyone holding that half could forge a session the server accepts.
 * Use `defineJWSSession` for a key pair.
 */
export type JWESessionKey =
  | JWESessionOctJWK
  | CryptoKey
  | {
      /** Encrypts every token, and decrypts. */
      current: JWESessionOctJWK;
      /**
       * Decrypt too, `current` need not be repeated: `oct` JWKs, or a JWK Set of them. At most
       * `jwe.decryptOptions.limits.keyCandidates` keys, `current` included, may lack a `kid`. A `CryptoKey` goes in as a JWK
       * (`exportJWK`), or is served from `onKeyLookup`.
       */
      keys: JWESessionOctJWK[] | JWKSet<JWESessionOctJWK[]>;
    };

/** RFC 7518 §4: a JWK's `alg` names its role. Without one, an AES-KW `CryptoKey` wraps, an AES-GCM one wraps or is the CEK, a PBKDF2 one derives, and an `oct` JWK serves what its length fits. */
const JWE_KEY_ALGORITHMS: KeyAlgorithms<KeyManagementAlgorithm> = {
  own: (key) => (isJWK(key) && key.alg ? (inferJWEAllowedAlgorithms(key) ?? []) : undefined),
  carried: (key) => {
    if (isCryptoKey(key)) {
      const name = key.algorithm.name;
      if (name === "PBKDF2") return PBES2_ALGORITHMS;
      const wraps = inferJWEAllowedAlgorithms(key) ?? [];
      return name === "AES-GCM" && wraps.length > 0 ? [...wraps, "dir"] : wraps;
    }
    if (!isSymmetricJWK(key)) return [];
    const algs = aesWraps(octBits(key));
    return directEncryptions(key).length > 0 ? [...algs, "dir"] : algs;
  },
};

/**
 * Resolves and checks the configured keys: `current`, which encrypts, and the key or JWK Set that decrypts, `current` first.
 * `algorithms` is what they serve together, the `alg` values an incoming token may carry. `current` decrypts `dir` under the pinned
 * `enc` alone, any other `dir` key every `enc` its length fits.
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
  issueKey: JWESessionOctJWK | CryptoKey;
  key: JWESessionOctJWK | CryptoKey | JWKSet;
  algorithms: KeyManagementAlgorithm[];
} {
  const { alg, enc, prefix } = options;
  assertKeyMaterial(key, { prefix });
  const set = rotationSet(key);
  const entries: SessionKeyEntry<JWESessionOctJWK | CryptoKey>[] = set
    ? rotationEntries(set, {
        ...options,
        isKey: isOctJWK,
        refuse: (entry) => asymmetricKeyError(entry, prefix),
        expected: '"oct" JWK',
        pin: alg,
        optionsPath: "jwe.decryptOptions",
      })
    : [{ key: sessionSecret(key, prefix), subject: "The session key", pin: alg }];
  const [{ key: issueKey, subject }] = entries;
  assertIssuingKey(issueKey, { alg, enc, subject, prefix });
  const { keys, all } = servedAlgorithms(entries, {
    ...options,
    algorithms: JWE_KEY_ALGORITHMS,
    listPath: "jwe.decryptOptions.algorithms",
    rename: (entry, served) => (entry.pin === "dir" && served === "dir" ? enc : undefined),
  });
  return { issueKey, key: openingKey(keys, { set: set !== undefined }), algorithms: all };
}

/**
 * The key that encrypts must serve the pinned `alg`, and a `dir` key the pinned `enc`. A key that names no algorithm needs both pinned.
 * @throws `ERR_SESSION_CONFIG_INVALID` for a key that names no algorithm without a pinned `alg` and `enc`.
 * @throws `ERR_SESSION_KEY_INVALID` for a key that cannot serve the pinned `alg` or `enc`.
 */
function assertIssuingKey(
  key: unknown,
  options: {
    alg: KeyManagementAlgorithm | undefined;
    enc: ContentEncryptionAlgorithm | undefined;
    subject: string;
    prefix: string;
  },
): void {
  const { alg, enc, subject, prefix } = options;
  assertPinnedKey(key, {
    algorithms: JWE_KEY_ALGORITHMS,
    pin: alg,
    pinned: Boolean(alg && enc),
    pinPath: "jwe.encryptOptions.alg",
    hint: '"jwe.encryptOptions.alg" and "enc"',
    subject,
    prefix,
  });
  const issuing = alg ?? JWE_KEY_ALGORITHMS.own(key)?.[0];
  if (issuing !== "dir" || !enc) return;
  const encs = directEncryptions(key);
  if (encs.includes(enc)) return;
  throw invalidKeyError(
    `${prefix} ${subject} serves "dir" with ${encs.join(", ") || "no content encryption"}, not the "${enc}" that "jwe.encryptOptions.enc" pins.`,
    key,
  );
}

/** The `enc` values a `dir` key encrypts with: a JWK's own `enc` `alg`, else every one its length fits (RFC 7518 §5). */
function directEncryptions(key: unknown): readonly ContentEncryptionAlgorithm[] {
  if (isJWK(key) && typeof key.alg === "string" && isContentEncryptionAlgorithm(key.alg)) {
    return [key.alg];
  }
  if (isCryptoKey(key)) {
    const bits = lengthOf(key.algorithm) ?? 0;
    return key.algorithm.name === "AES-GCM"
      ? GCM_ENCRYPTIONS.filter((enc) => enc === `A${bits}GCM`)
      : [];
  }
  if (!isSymmetricJWK(key)) return [];
  const bits = octBits(key);
  return [...GCM_ENCRYPTIONS, ...CBC_ENCRYPTIONS].filter((enc) => encryptionBits(enc) === bits);
}

/** A symmetric key alone. Asymmetric material throws: its public half encrypts, so its holder could forge sessions. */
function sessionSecret(key: unknown, prefix: string): JWESessionOctJWK | CryptoKey {
  if (isOctJWK(key)) return key;
  if (isCryptoKey(key) && key.type === "secret") return key;
  throw (
    asymmetricKeyError(key, prefix) ??
    invalidKeyError(
      `${prefix} Invalid JWE session key: expected an "oct" JWK, a secret CryptoKey or { current, keys }.`,
      key,
    )
  );
}

function asymmetricKeyError(key: unknown, prefix: string): JWTError | undefined {
  const asymmetric = isCryptoKey(key)
    ? key.type !== "secret"
    : isAsymmetricJWK(key) || (typeof key === "object" && key !== null && isKeyPair(key));
  if (!asymmetric) return undefined;
  return invalidKeyError(
    `${prefix} Invalid JWE session key: an asymmetric key seals with its public half, so anyone holding that half could mint sessions. Use an "oct" JWK, or defineJWSSession for a key pair.`,
    key,
  );
}

/** An `oct` JWK. An `alg` outside JWE fails when the key is imported. */
function isOctJWK(key: unknown): key is JWESessionOctJWK {
  return isSymmetricJWK(key);
}

const GCM_ENCRYPTIONS: readonly ContentEncryptionAlgorithm[] = ["A128GCM", "A192GCM", "A256GCM"];

const CBC_ENCRYPTIONS: readonly ContentEncryptionAlgorithm[] = [
  "A128CBC-HS256",
  "A192CBC-HS384",
  "A256CBC-HS512",
];

/** RFC 7518 §4.4, §4.7: the wrapping algorithms of an AES key of `bits`. */
function aesWraps(bits: number): KeyManagementAlgorithm[] {
  switch (bits) {
    case 128:
      return ["A128KW", "A128GCMKW"];
    case 192:
      return ["A192KW", "A192GCMKW"];
    case 256:
      return ["A256KW", "A256GCMKW"];
    default:
      return [];
  }
}

/** RFC 7518 §5.2.3–§5.2.5, §5.3: a CBC-HMAC key is twice its AES size. */
function encryptionBits(enc: ContentEncryptionAlgorithm): number {
  const bits = Number(enc.slice(1, 4));
  return enc.includes("CBC") ? bits * 2 : bits;
}
