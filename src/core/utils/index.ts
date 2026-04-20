import type {
  JWK,
  JWKSet,
  JWK_oct,
  JWK_Public,
  JWK_Private,
  JWK_EC_Public,
  JWK_EC_Private,
  JWK_OKP_Public,
  JWK_OKP_Private,
  JWK_RSA_Public,
  JWK_RSA_Private,
} from "../types";

export { secureRandomBytes } from "unsecure/random";
export { safeJsonParse, sanitizeObject, sanitizeObjectCopy } from "unsecure/sanitize";
export {
  textEncoder,
  textDecoder,
  base64Encode,
  base64Decode,
  base64UrlEncode,
  base64UrlDecode,
} from "unsecure/utils";

export * from "./algorithms";
export * from "./jwt";
export type * from "./types";

/** Concatenate multiple `Uint8Array`s into a single contiguous buffer. */
export function concatUint8Arrays(
  ...arrays: Readonly<Uint8Array<ArrayBuffer>[]>
): Uint8Array<ArrayBuffer> {
  const totalLength = arrays.reduce((length, arr) => length + arr.length, 0);
  const result = new Uint8Array(totalLength);

  let offset = 0;
  for (const arr of arrays) {
    result.set(arr, offset);
    offset += arr.length;
  }

  return result;
}

/** Wrap a value in an array; returns the array unchanged if already an array. */
export function maybeArray<T>(item: T | T[]): T[] {
  return Array.isArray(item) ? item : [item];
}

/** Type guard for {@link JWK} — checks for an object with a string `kty`. */
export function isJWK(key: any): key is JWK {
  return (
    typeof key === "object" && key !== null && "kty" in key && typeof (key as JWK).kty === "string"
  );
}

/** Type guard for {@link JWKSet} — checks for an object with a `keys` array. */
export function isJWKSet(key: any): key is JWKSet {
  return key && typeof key === "object" && "keys" in key && Array.isArray((key as JWKSet).keys);
}

/** Asserts that `key` is a `CryptoKey`; throws `TypeError` otherwise. */
export function assertCryptoKey(key: unknown): asserts key is CryptoKey {
  if (!isCryptoKey(key)) {
    throw new Error("CryptoKey instance expected");
  }
}

/**
 * Type guard for `CryptoKey`. Uses `Symbol.toStringTag` instead of `instanceof`
 * so it works across worker / realm boundaries where `CryptoKey` identities differ.
 */
export function isCryptoKey(key: unknown): key is CryptoKey {
  // @ts-expect-error indexing CryptoKey via Symbol.toStringTag isn't in the type.
  return key?.[Symbol.toStringTag] === "CryptoKey";
}

/** Type guard for `CryptoKeyPair` — both `publicKey` and `privateKey` must be CryptoKeys. */
export const isCryptoKeyPair = (key: any): key is CryptoKeyPair =>
  key && typeof key === "object" && isCryptoKey(key.publicKey) && isCryptoKey(key.privateKey);

/** Returns true if the JWK is a symmetric (oct) key. */
export function isSymmetricJWK(key: unknown): key is Extract<JWK, JWK_oct> {
  return isJWK(key) && key.kty === "oct" && typeof (key as JWK_oct).k === "string";
}

/** Returns true if the JWK is an asymmetric (RSA, EC, OKP) key. */
export function isAsymmetricJWK(key: unknown): key is Exclude<JWK, JWK_oct> {
  return !isSymmetricJWK(key);
}

/**
 * Type guard that checks if the provided JWK contains private key material.
 * It relies purely on the presence of private components (e.g. "d"), not on the alg value.
 */
export function isPrivateJWK(key: unknown): key is JWK_Private {
  if (!isJWK(key)) return false;
  if (key.kty === "EC") {
    return typeof (key as Partial<JWK_EC_Private>).d === "string";
  }
  if (key.kty === "OKP") {
    return typeof (key as Partial<JWK_OKP_Private>).d === "string";
  }
  if (key.kty === "RSA") {
    return typeof (key as Partial<JWK_RSA_Private>).d === "string";
  }
  return false;
}

/**
 * Type guard that checks if the provided JWK is a public (asymmetric) key.
 * This checks for the presence of public components and absence of private material.
 */
export function isPublicJWK(key: unknown): key is JWK_Public {
  if (!isJWK(key)) return false;
  if (key.kty === "EC") {
    const ec = key as Partial<JWK_EC_Public & JWK_EC_Private>;
    return (
      typeof ec.x === "string" &&
      typeof ec.y === "string" &&
      typeof (ec as Partial<JWK_EC_Private>).d !== "string"
    );
  }
  if (key.kty === "OKP") {
    const okp = key as Partial<JWK_OKP_Public & JWK_OKP_Private>;
    return typeof okp.x === "string" && typeof (okp as Partial<JWK_OKP_Private>).d !== "string";
  }
  if (key.kty === "RSA") {
    const rsa = key as Partial<JWK_RSA_Public & JWK_RSA_Private>;
    return (
      typeof rsa.n === "string" &&
      typeof rsa.e === "string" &&
      typeof (rsa as Partial<JWK_RSA_Private>).d !== "string"
    );
  }
  return false;
}
