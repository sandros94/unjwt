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
import { JWTError } from "../error";

/** Whether `key` is a JWK whose `kty` this library models (`oct`, `RSA`, `EC`, `OKP`). */
export function isJWK(key: unknown): key is JWK {
  return (
    typeof key === "object" &&
    key !== null &&
    "kty" in key &&
    (key.kty === "oct" || key.kty === "RSA" || key.kty === "EC" || key.kty === "OKP")
  );
}

/** Whether `key` is an object with a `keys` array. */
export function isJWKSet(key: unknown): key is JWKSet {
  return typeof key === "object" && key !== null && "keys" in key && Array.isArray(key.keys);
}

/** Whether `value` is a plain object (prototype `Object.prototype` or `null`). */
export function isPlainObject(value: unknown): value is Record<string, unknown> {
  if (typeof value !== "object" || value === null) return false;
  const prototype: unknown = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

/** Throws `ERR_INVALID_OPTION` when `value` is not a plain object. */
export function assertPlainObject(
  value: unknown,
  name: string,
): asserts value is Record<string, unknown> {
  if (!isPlainObject(value)) {
    throw new JWTError(`"${name}" must be an object.`, "ERR_INVALID_OPTION");
  }
}

/** Asserts that `key` is a `CryptoKey`; throws `ERR_JWK_INVALID` otherwise. */
export function assertCryptoKey(key: unknown): asserts key is CryptoKey {
  if (!isCryptoKey(key)) {
    throw new JWTError("CryptoKey instance expected", "ERR_JWK_INVALID");
  }
}

/** Whether `key` is a `CryptoKey`, checked via `Symbol.toStringTag` to work across realms. */
export function isCryptoKey(key: unknown): key is CryptoKey {
  // @ts-expect-error indexing CryptoKey via Symbol.toStringTag isn't in the type.
  return key?.[Symbol.toStringTag] === "CryptoKey";
}

/** Whether `key` is a `CryptoKeyPair` of two CryptoKeys. */
export const isCryptoKeyPair = (key: unknown): key is CryptoKeyPair =>
  typeof key === "object" &&
  key !== null &&
  "publicKey" in key &&
  "privateKey" in key &&
  isCryptoKey(key.publicKey) &&
  isCryptoKey(key.privateKey);

/** Whether the JWK is symmetric (`oct`); its `k` is always secret. */
export function isSymmetricJWK<T>(key: T): key is Extract<T, JWK_oct>;
export function isSymmetricJWK(key: unknown): key is JWK_oct;
export function isSymmetricJWK(key: unknown): boolean {
  return isJWK(key) && key.kty === "oct" && typeof key.k === "string";
}

/** Whether the JWK is asymmetric (RSA, EC, OKP). */
export function isAsymmetricJWK<T>(key: T): key is Exclude<T, JWK_oct>;
export function isAsymmetricJWK(key: unknown): key is Exclude<JWK, JWK_oct>;
export function isAsymmetricJWK(key: unknown): boolean {
  return !isSymmetricJWK(key);
}

/**
 * Whether the JWK holds asymmetric private material (`d`). It is `false` for `oct` keys,
 * so `!isPrivateJWK(key)` is not a "safe to publish" check; use `isPublicJWK`.
 */
export function isPrivateJWK<T>(
  key: T,
): key is Extract<T, JWK_EC_Private | JWK_OKP_Private | JWK_RSA_Private>;
export function isPrivateJWK(key: unknown): key is JWK_Private;
export function isPrivateJWK(key: unknown): boolean {
  if (!isJWK(key) || key.kty === "oct") return false;
  return "d" in key && typeof key.d === "string";
}

/** Whether the JWK is an asymmetric public key without `d`: the "safe to publish" check. */
export function isPublicJWK<T>(
  key: T,
): key is Exclude<Extract<T, JWK_EC_Public | JWK_OKP_Public | JWK_RSA_Public>, JWK_Private>;
export function isPublicJWK(key: unknown): key is JWK_Public;
export function isPublicJWK(key: unknown): boolean {
  if (!isJWK(key) || key.kty === "oct" || ("d" in key && typeof key.d === "string")) {
    return false;
  }
  if (key.kty === "EC") return typeof key.x === "string" && typeof key.y === "string";
  if (key.kty === "OKP") return typeof key.x === "string";
  return typeof key.n === "string" && typeof key.e === "string";
}
