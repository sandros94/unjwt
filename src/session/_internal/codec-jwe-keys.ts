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
import {
  isAsymmetricJWK,
  isCryptoKey,
  isJWK,
  isJWKSet,
  isSymmetricJWK,
} from "../../utils/guards.ts";
import type { JWTError } from "../../error.ts";
import { assertKeyMaterial, invalidKeyError } from "./contract.ts";
import { isKeyPair } from "./codec.ts";
import { quoteTokenValue } from "../../utils/_internal/text.ts";
import {
  type KeyAlgorithms,
  type SessionKeyEntry,
  assertPinnedKey,
  octBits,
  servedAlgorithms,
} from "./key-algorithms.ts";

/** An `oct` JWK that JWE key management accepts. */
export type JWESessionOctJWK = Extract<JWEDecryptJWK, { kty: "oct" }>;

/** One symmetric key: an `oct` JWK, or a secret `CryptoKey`. To encrypt, a key without `alg` (any `CryptoKey`) requires a pinned `jwe.encryptOptions.alg` and `enc`. */
export type JWESessionSecret = JWESessionOctJWK | CryptoKey;

/**
 * A symmetric key that encrypts and decrypts, or a rotation set: `current` encrypts (its `kid` is written to the header) and decrypts,
 * and `keys` decrypt too, picked by the token's `kid`. An asymmetric key throws `ERR_SESSION_KEY_INVALID`: its public half encrypts,
 * so anyone holding that half could forge a session the server accepts. Use `defineJWSSession` for a key pair.
 */
export type JWESessionKey =
  | JWESessionSecret
  | {
      /** Encrypts every token, and decrypts. */
      current: JWESessionSecret;
      /** Decrypt too, `current` need not be repeated. With a `CryptoKey` `current`, a token whose `kid` names none of them is decrypted with `current`. */
      keys: JWESessionOctJWK[] | JWKSet<JWESessionOctJWK[]>;
    };

/** The configured key and rotation keys. Asymmetric material throws: its public half encrypts, so its holder could forge sessions. */
export function sessionKeys(
  key: unknown,
  prefix: string,
): { current: JWESessionSecret; previous?: JWESessionOctJWK[] } {
  assertKeyMaterial(key, { prefix });
  const set = rotationSet(key);
  if (!set) return { current: sessionSecret(key, { prefix, what: "" }) };

  const previous: unknown = isJWKSet(set.keys) ? set.keys.keys : set.keys;
  if (!Array.isArray(previous)) {
    throw invalidKeyError(
      `${prefix} Invalid JWE session key: "keys" must be a list or a JWK Set of "oct" JWKs.`,
      key,
    );
  }
  return {
    current: sessionSecret(set.current, { prefix, what: '"current"' }),
    previous: previous.map((entry: unknown) => {
      if (isOctJWK(entry)) return entry;
      throw keyError(entry, { prefix, expected: '"keys" must hold "oct" JWKs' });
    }),
  };
}

/** A key that decrypts, with the algorithms it serves. */
export interface JWESessionEntry {
  key: JWESessionSecret;
  algorithms: readonly KeyManagementAlgorithm[];
}

/**
 * Resolves and checks the configured keys: `current`, which encrypts, and every key that decrypts, `current` first.
 * `algorithms` is what they serve together, the `alg` values an incoming token may carry.
 */
export function resolveSessionKeys(
  key: unknown,
  options: {
    alg: KeyManagementAlgorithm | undefined;
    enc: ContentEncryptionAlgorithm | undefined;
    listed: KeyManagementAlgorithm[] | undefined;
    lookup: boolean;
    prefix: string;
  },
): {
  current: JWESessionSecret;
  previous: JWESessionOctJWK[] | undefined;
  entries: JWESessionEntry[];
  algorithms: KeyManagementAlgorithm[];
} {
  const { alg, enc, listed, lookup, prefix } = options;
  const { current, previous } = sessionKeys(key, prefix);
  const subject = previous ? 'The session key "current"' : "The session key";
  assertIssuingKey(current, { alg, enc, subject, prefix });
  const named: (SessionKeyEntry & { key: JWESessionSecret })[] = [
    { key: current, subject, pin: alg },
  ];
  previous?.forEach((entry, index) => {
    if (entry === current) return;
    const kid = entry.kid === undefined ? "" : ` (kid ${quoteTokenValue(entry.kid)})`;
    named.push({ key: entry, subject: `The session key "keys[${index}]"${kid}` });
  });
  const served = servedAlgorithms(named, {
    algorithms: JWE_KEY_ALGORITHMS,
    listed,
    listPath: "jwe.decryptOptions.algorithms",
    lookup,
    prefix,
  });
  return {
    current,
    previous,
    entries: named.map((entry, index) => ({ key: entry.key, algorithms: served.each[index] })),
    algorithms: served.all,
  };
}

/**
 * The key that encrypts must serve the pinned `alg`, and a `dir` key the pinned `enc`. A key that names no algorithm needs both pinned.
 * @throws `ERR_SESSION_CONFIG_INVALID` for a key that names no algorithm without a pinned `alg` and `enc`.
 * @throws `ERR_SESSION_KEY_INVALID` for a key that cannot serve the pinned `alg` or `enc`.
 */
export function assertIssuingKey(
  key: JWESessionSecret,
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

export function rotationSet(key: unknown): { current: unknown; keys?: unknown } | undefined {
  return isObject(key) && "current" in key ? key : undefined;
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
