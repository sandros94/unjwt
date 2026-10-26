import type { ContentEncryptionAlgorithm, KeyManagementAlgorithm } from "../../core/types/index.ts";
import { lengthOf } from "../../core/_crypto/_key-algorithm.ts";
import {
  PBES2_ALGORITHMS,
  inferJWEAllowedAlgorithms,
  isContentEncryptionAlgorithm,
} from "../../utils/algorithms.ts";
import { isCryptoKey, isJWK, isSymmetricJWK } from "../../utils/guards.ts";
import { invalidKeyError } from "./contract.ts";
import { type KeyAlgorithms, assertPinnedKey, octBits } from "./key-algorithms.ts";

/** RFC 7518 §4: a JWK's `alg` names its role. Without one, an AES-KW `CryptoKey` wraps, an AES-GCM one wraps or is the CEK, a PBKDF2 one derives, and raw bytes serve what their length fits. */
export const JWE_KEY_ALGORITHMS: KeyAlgorithms<KeyManagementAlgorithm> = {
  family: "JWE",
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

/** The `enc` values a `dir` key encrypts with: a JWK's own `enc` `alg`, else every one its length fits (RFC 7518 §5). */
export function directEncryptions(key: unknown): readonly ContentEncryptionAlgorithm[] {
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

/**
 * The key that encrypts must serve the pinned `alg`, and a `dir` key the pinned `enc`. A key that names no algorithm needs both pinned.
 * @throws `ERR_SESSION_CONFIG_INVALID` for a key that names no algorithm without a pinned `alg` and `enc`.
 * @throws `ERR_SESSION_KEY_INVALID` for a key that cannot serve the pinned `alg` or `enc`.
 */
export function assertIssuingKey(
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
