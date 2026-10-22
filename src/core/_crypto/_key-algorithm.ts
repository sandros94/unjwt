import { JWTError } from "../error.ts";
import type {
  JWK_AES_Algorithm,
  JWK_ECDSA,
  JWK_PBES2,
  JWK_RSA_ENC,
  JWSHashedAlgorithm,
  KeyWrapAlgorithmOf,
  KeyWrappingAlgorithm,
} from "../types/index.ts";

export type SHA = "SHA-1" | "SHA-256" | "SHA-384" | "SHA-512";

type HashDigits = "256" | "384" | "512";
type AesBits = "128" | "192" | "256";

/** The digest named by the last three characters of `HS*`/`RS*`/`PS*`/`ES*`. */
type JWSHashOf<A extends JWSHashedAlgorithm> = A extends `${string}${infer D extends HashDigits}`
  ? `SHA-${D}`
  : never;

/** The PRF named by `PBES2-HS<n>+…`. */
type PBES2HashOf<A extends JWK_PBES2> = A extends `PBES2-HS${infer D extends HashDigits}+${string}`
  ? `SHA-${D}`
  : never;

/** The AES key size named by `A<n>…`, as a number. */
type AesBitsOf<A extends JWK_AES_Algorithm> = A extends `A${infer B extends AesBits}${string}`
  ? B extends "128"
    ? 128
    : B extends "192"
      ? 192
      : 256
  : never;

/** The curve each ECDSA algorithm is defined over — RFC 7518 §3.4. */
export const ECDSA_CURVES: Readonly<Record<JWK_ECDSA, "P-256" | "P-384" | "P-521">> =
  /* @__PURE__ */ Object.freeze({ ES256: "P-256", ES384: "P-384", ES512: "P-521" });

/** The digest an `HS*`/`RS*`/`PS*`/`ES*` algorithm is defined with: its last three characters. */
export function jwsHashOf<A extends JWSHashedAlgorithm>(alg: A): JWSHashOf<A> {
  // oxlint-disable-next-line typescript/no-unsafe-type-assertion -- `JWSHashOf` proves the suffix; `slice` cannot carry it
  return `SHA-${alg.slice(-3)}` as JWSHashOf<A>;
}

const RSA_OAEP_HASH: Readonly<Record<JWK_RSA_ENC, SHA>> = /* @__PURE__ */ Object.freeze({
  "RSA-OAEP": "SHA-1",
  "RSA-OAEP-256": "SHA-256",
  "RSA-OAEP-384": "SHA-384",
  "RSA-OAEP-512": "SHA-512",
});

/** RFC 7518 §4.3 — bare `RSA-OAEP` is SHA-1, `RSA-OAEP-<n>` is SHA-<n>. */
export function rsaOaepHashOf(alg: JWK_RSA_ENC): SHA {
  return RSA_OAEP_HASH[alg];
}

/** RFC 7518 §4.8 — the PRF each PBES2 algorithm runs PBKDF2 with: `PBES2-HS<n>+…`. */
export function pbes2HashOf<A extends JWK_PBES2>(alg: A): PBES2HashOf<A> {
  // oxlint-disable-next-line typescript/no-unsafe-type-assertion -- `PBES2HashOf` proves the digits; `slice` cannot carry them
  return `SHA-${alg.slice(8, 11)}` as PBES2HashOf<A>;
}

const SHA_BITS: Readonly<Record<SHA, 1 | 256 | 384 | 512>> = /* @__PURE__ */ Object.freeze({
  "SHA-1": 1,
  "SHA-256": 256,
  "SHA-384": 384,
  "SHA-512": 512,
});

/** The digest size in bits, as `hashBitsOf` reads it back from a Web Crypto key (`SHA-1` → 1). */
export function shaBitsOf(sha: SHA): 1 | 256 | 384 | 512 {
  return SHA_BITS[sha];
}

/** The AES key size an `A<n>…` algorithm runs on; for `A*CBC-HS*` the AES half of the composite key. */
export function aesBitsOf<A extends JWK_AES_Algorithm>(alg: A): AesBitsOf<A> {
  // oxlint-disable-next-line typescript/no-unsafe-type-assertion -- `AesBitsOf` proves the digits; `parseInt` cannot carry them
  return Number.parseInt(alg.slice(1, 4), 10) as AesBitsOf<A>;
}

/** The AES-KW algorithm a `PBES2-*` or `ECDH-ES+*` algorithm wraps the CEK with: its last six characters. */
export function innerKeyWrapAlg<A extends KeyWrappingAlgorithm>(alg: A): KeyWrapAlgorithmOf<A> {
  // oxlint-disable-next-line typescript/no-unsafe-type-assertion -- `KeyWrapAlgorithmOf` proves the suffix; `slice` cannot carry it
  return alg.slice(-6) as KeyWrapAlgorithmOf<A>;
}

export function namedCurveOf(algorithm: KeyAlgorithm): string | undefined {
  return "namedCurve" in algorithm && typeof algorithm.namedCurve === "string"
    ? algorithm.namedCurve
    : undefined;
}

/** The curve a key agrees on: its EC `namedCurve`, or `X25519` for an X25519 key. */
export function cryptoKeyCurve(key: CryptoKey): string | undefined {
  const { algorithm } = key;
  return namedCurveOf(algorithm) ?? (algorithm.name === "X25519" ? algorithm.name : undefined);
}

export function hashNameOf(algorithm: KeyAlgorithm): string | undefined {
  if (!("hash" in algorithm)) return undefined;
  const { hash } = algorithm;
  return typeof hash === "object" &&
    hash !== null &&
    "name" in hash &&
    typeof hash.name === "string"
    ? hash.name
    : undefined;
}

export function lengthOf(algorithm: KeyAlgorithm): number | undefined {
  return "length" in algorithm && typeof algorithm.length === "number"
    ? algorithm.length
    : undefined;
}

export function modulusLengthOf(algorithm: KeyAlgorithm): number | undefined {
  return "modulusLength" in algorithm && typeof algorithm.modulusLength === "number"
    ? algorithm.modulusLength
    : undefined;
}

export function hashBitsOf(hash: KeyAlgorithm): number {
  return Number.parseInt(hash.name.slice(4), 10);
}

export interface KeyAlgorithmByName {
  "AES-GCM": AesKeyAlgorithm;
  "AES-KW": AesKeyAlgorithm;
  "HMAC": HmacKeyAlgorithm;
  "RSASSA-PKCS1-v1_5": RsaHashedKeyAlgorithm;
  "RSA-PSS": RsaHashedKeyAlgorithm;
  "RSA-OAEP": RsaHashedKeyAlgorithm;
  "ECDSA": EcKeyAlgorithm;
  "Ed25519": KeyAlgorithm;
  "PBKDF2": KeyAlgorithm;
}

export function isAlgorithm<N extends keyof KeyAlgorithmByName>(
  algorithm: KeyAlgorithm,
  name: N,
): algorithm is KeyAlgorithmByName[N] {
  return algorithm.name === name;
}

export function unusableKey(name: string | number, prop = "algorithm.name"): JWTError {
  return new JWTError(
    `CryptoKey does not support this operation, its ${prop} must be ${name}`,
    "ERR_JWK_INVALID",
  );
}

export function checkKeyUsage(key: CryptoKey, usage?: KeyUsage): void {
  if (usage && !key.usages.includes(usage)) {
    throw new JWTError(
      `CryptoKey does not support this operation, its usages must include ${usage}.`,
      "ERR_JWK_INVALID",
    );
  }
}
