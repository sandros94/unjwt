import type {
  ContentEncryptionAlgorithm,
  JOSELimits,
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
import {
  isAsymmetricJWK,
  isCryptoKey,
  isJWK,
  isJWKSet,
  isSymmetricJWK,
} from "../../utils/guards.ts";
import { assertKeyMaterial, invalidKeyError } from "./contract.ts";
import {
  type ResolvedSessionKeys,
  type SessionKeyEntry,
  type SessionKeyRules,
  assertPinnedKey,
  isKeyPair,
  octBits,
  servedAlgorithms,
  sessionKeySetEntries,
} from "./key-algorithms.ts";

/** An `oct` JWK that JWE key management accepts. */
export type JWESessionOctJWK = Extract<JWEDecryptJWK, { kty: "oct" }>;

/**
 * A symmetric key that encrypts and decrypts, an `oct` JWK or a secret `CryptoKey`, or a JWK Set of `oct` JWKs. A key without `alg` (a
 * `CryptoKey`, an `oct` JWK without `alg`) requires a pinned `jwe.encryptOptions.alg` and `enc`. A JWK Set's first key encrypts and
 * every key decrypts, each checked as a lone key, the pin naming the first alone; at most `jwe.decryptOptions.limits.keyCandidates` of
 * them may lack a `kid`. An asymmetric key throws `ERR_SESSION_KEY_INVALID`: its public half encrypts, so anyone holding that half
 * could forge a session the server accepts. Use `defineJWSSession` for a key pair.
 */
export type JWESessionKey = JWESessionOctJWK | CryptoKey | JWKSet<JWESessionOctJWK[]>;

/** RFC 7518 §4: a JWK's `alg` names its role. Without one, an AES-KW `CryptoKey` wraps, an AES-GCM one wraps or is the CEK, a PBKDF2 one derives, and an `oct` JWK serves what its length fits. */
const JWE_KEY_RULES: SessionKeyRules<KeyManagementAlgorithm> = {
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
  pinPath: "jwe.encryptOptions.alg",
  hint: '"jwe.encryptOptions.alg" and "enc"',
  listPath: "jwe.decryptOptions.algorithms",
  limitPath: "jwe.decryptOptions.limits.keyCandidates",
};

/**
 * Resolves and checks the configured key, or JWK Set whose first key encrypts, and what decrypts. The key that encrypts must serve
 * the pinned `alg` and `enc`, and needs both pinned when it names no algorithm.
 */
export function resolveSessionKeys(
  key: JWESessionKey,
  options: {
    alg: KeyManagementAlgorithm | undefined;
    enc: ContentEncryptionAlgorithm | undefined;
    listed: KeyManagementAlgorithm[] | undefined;
    limits: JOSELimits | undefined;
    lookup: boolean;
    prefix: string;
  },
): ResolvedSessionKeys<JWESessionOctJWK | CryptoKey, JWESessionKey, KeyManagementAlgorithm> {
  const { alg: pin, enc, prefix } = options;
  assertKeyMaterial(key, { prefix });
  const entries = isJWKSet(key)
    ? sessionKeySetEntries(key.keys, { ...options, pin, rules: JWE_KEY_RULES })
    : [{ key: sessionSecret(key, prefix), subject: "The session key", pin }];
  assertIssuingKey(entries[0], { enc, prefix });
  const { all } = servedAlgorithms(entries, { ...options, rules: JWE_KEY_RULES });
  return { issueKey: entries[0].key, key, algorithms: all };
}

/**
 * The key that encrypts must serve the pinned `alg`, and a `dir` key the pinned `enc`. A key that names no algorithm needs both pinned.
 * @throws `ERR_SESSION_CONFIG_INVALID` for a key that names no algorithm without a pinned `alg` and `enc`.
 * @throws `ERR_SESSION_KEY_INVALID` for a key that cannot serve the pinned `alg` or `enc`.
 */
function assertIssuingKey(
  entry: SessionKeyEntry<JWESessionOctJWK | CryptoKey>,
  options: { enc: ContentEncryptionAlgorithm | undefined; prefix: string },
): void {
  const { enc, prefix } = options;
  const { key, subject, pin } = entry;
  assertPinnedKey(entry, { rules: JWE_KEY_RULES, pinned: Boolean(pin && enc), prefix });
  const issuing = pin ?? JWE_KEY_RULES.own(key)?.[0];
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
  const asymmetric = isCryptoKey(key)
    ? key.type !== "secret"
    : isAsymmetricJWK(key) || isKeyPair(key);
  throw invalidKeyError(
    asymmetric
      ? `${prefix} Invalid JWE session key: an asymmetric key seals with its public half, so anyone holding that half could mint sessions. Use an "oct" JWK, or defineJWSSession for a key pair.`
      : `${prefix} Invalid JWE session key: expected an "oct" JWK, a JWK Set of them or a secret CryptoKey.`,
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
