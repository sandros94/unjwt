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

/**
 * Type guard for {@link JWK} — an object whose `kty` this library models
 * (`"oct"`/`"RSA"`/`"EC"`/`"OKP"`).
 */
export function isJWK(key: unknown): key is JWK {
  return (
    typeof key === "object" &&
    key !== null &&
    "kty" in key &&
    (key.kty === "oct" || key.kty === "RSA" || key.kty === "EC" || key.kty === "OKP")
  );
}

/** Type guard for {@link JWKSet} — checks for an object with a `keys` array. */
export function isJWKSet(key: unknown): key is JWKSet {
  return typeof key === "object" && key !== null && "keys" in key && Array.isArray(key.keys);
}

/** Asserts that `key` is a `CryptoKey`; throws `ERR_JWK_INVALID` otherwise. */
export function assertCryptoKey(key: unknown): asserts key is CryptoKey {
  if (!isCryptoKey(key)) {
    throw new JWTError("CryptoKey instance expected", "ERR_JWK_INVALID");
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
export const isCryptoKeyPair = (key: unknown): key is CryptoKeyPair =>
  typeof key === "object" &&
  key !== null &&
  "publicKey" in key &&
  "privateKey" in key &&
  isCryptoKey(key.publicKey) &&
  isCryptoKey(key.privateKey);

/**
 * Returns true if the JWK is a symmetric (oct) key.
 *
 * NOTE: a symmetric JWK's `k` is always secret key material. {@link isPrivateJWK}
 * returns `false` for `oct` keys (it only detects asymmetric `d`), so use this
 * guard — not `!isPrivateJWK(key)` — when deciding whether a JWK is safe to
 * publish.
 *
 * The `T` inference preserves the caller's narrowed alg type — passing a
 * `JWK_oct<"HS256">` refines to `JWK_oct<"HS256">`, not `JWK_oct<string>`.
 */
export function isSymmetricJWK<T>(key: T): key is Extract<T, JWK_oct>;
export function isSymmetricJWK(key: unknown): key is JWK_oct;
export function isSymmetricJWK(key: unknown): boolean {
  return isJWK(key) && key.kty === "oct" && typeof key.k === "string";
}

/**
 * Returns true if the JWK is an asymmetric (RSA, EC, OKP) key.
 *
 * The `T` inference preserves the caller's narrowed alg type — passing a
 * `JWK_EC<"ES256">` refines to `JWK_EC<"ES256">`, not `JWK_EC<string>`,
 * and so on for RSA and OKP.
 */
export function isAsymmetricJWK<T>(key: T): key is Exclude<T, JWK_oct>;
export function isAsymmetricJWK(key: unknown): key is Exclude<JWK, JWK_oct>;
export function isAsymmetricJWK(key: unknown): boolean {
  return !isSymmetricJWK(key);
}

/**
 * Type guard that checks if the provided JWK contains *asymmetric* private key
 * material. It relies purely on the presence of private components (e.g. "d"),
 * not on the alg value.
 *
 * WARNING: this returns `false` for symmetric (`oct`) keys — their `k` is secret
 * material too, but it is not a `d` component. `!isPrivateJWK(key)` is therefore
 * NOT a "safe to share" check: it passes every `oct` key. To filter keys that
 * are safe to publish, use {@link isPublicJWK} (true only for asymmetric public
 * keys); to detect any secret material, combine with {@link isSymmetricJWK}.
 *
 * Preserves narrow alg types from the caller.
 */
export function isPrivateJWK<T>(
  key: T,
): key is Extract<T, JWK_EC_Private | JWK_OKP_Private | JWK_RSA_Private>;
export function isPrivateJWK(key: unknown): key is JWK_Private;
export function isPrivateJWK(key: unknown): boolean {
  if (!isJWK(key) || key.kty === "oct") return false;
  return "d" in key && typeof key.d === "string";
}

/**
 * Type guard that checks if the provided JWK is a public (asymmetric) key:
 * public components present, no private `d`. Returns `false` for `oct` keys
 * (which are always secret), making it the correct "safe to publish" predicate.
 *
 * Preserves narrow alg types from the caller.
 */
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
