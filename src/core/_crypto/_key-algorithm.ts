import { JWTError } from "../error";

/** The curve each ECDSA algorithm is defined over — RFC 7518 §3.4. */
export const ECDSA_CURVES: Readonly<Record<string, "P-256" | "P-384" | "P-521">> =
  /* @__PURE__ */ Object.freeze({ ES256: "P-256", ES384: "P-384", ES512: "P-521" });

/** The digest an `HS*`/`RS*`/`PS*`/`ES*` algorithm names in its last three characters. */
export function jwsHashOf(alg: string): string {
  return `SHA-${alg.slice(-3)}`;
}

/** RFC 7518 §4.3 — bare `RSA-OAEP` is SHA-1, `RSA-OAEP-<n>` is SHA-<n>. */
export function rsaOaepHashOf(alg: string): string {
  return `SHA-${Number.parseInt(alg.slice(9), 10) || 1}`;
}

export function aesBitsOf(alg: string): number {
  return Number.parseInt(alg.slice(1, 4), 10);
}

/** The AES-KW algorithm a `PBES2-*` or `ECDH-ES+*` algorithm wraps the CEK with. */
export function innerKeyWrapAlg(alg: string): string {
  return alg.slice(-6);
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
