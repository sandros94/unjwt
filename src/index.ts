export type * from "./core/types";

export { JWTError, isJWTError, UnsecureError, isUnsecureError } from "./core/error";
export type { JWTErrorCode, JWTErrorCauseMap, UnsecureErrorCode } from "./core/error";

export {
  sign,
  verify,
  signMulti,
  verifyMulti,
  verifyMultiAll,
  generalToFlattenedJWS,
} from "./core/jws";
export { encrypt, decrypt, encryptMulti, decryptMulti, generalToFlattened } from "./core/jwe";
export {
  generateKey,
  generateJWK,
  importKey,
  exportKey,
  wrapKey,
  unwrapKey,
  deriveKeyFromPassword,
  deriveJWKFromPassword,
  importPEM,
  exportPEM,
  importFromPEM,
  exportToPEM,
  getJWKFromSet,
  getJWKsFromSet,
  deriveSharedSecret,
  WeakMapJWKCache,
  configureJWKCache,
  clearJWKCache,
} from "./core/jwk";
export {
  isJWK,
  isJWKSet,
  assertCryptoKey,
  isCryptoKey,
  isCryptoKeyPair,
  isSymmetricJWK,
  isAsymmetricJWK,
  isPrivateJWK,
  isPublicJWK,
  validateJwtClaims,
  computeDurationInSeconds,
  computeExpiresInSeconds,
  computeMaxTokenAgeSeconds,
} from "./core/utils";
