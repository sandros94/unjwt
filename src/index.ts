export type * from "./core/types/index.ts";

export { JWTError, isJWTError, UnsecureError, isUnsecureError } from "./core/error.ts";
export type {
  JWTErrorCode,
  KnownJWTErrorCode,
  JWTErrorCauseMap,
  UnsecureErrorCode,
} from "./core/error.ts";

export {
  sign,
  verify,
  signMulti,
  verifyMulti,
  verifyMultiAll,
  generalToFlattenedJWS,
} from "./core/jws.ts";
export { encrypt, decrypt, encryptMulti, decryptMulti, generalToFlattened } from "./core/jwe.ts";
export { DEFAULT_JOSE_LIMITS } from "./core/_internal.ts";
export {
  generateKey,
  generateJWK,
  thumbprint,
  importKey,
  exportKey,
  wrapKey,
  unwrapKey,
  deriveKeyFromPassword,
  deriveJWKFromPassword,
  importPEM,
  exportPEM,
  getJWKsFromSet,
  deriveSharedSecret,
  WeakMapJWKCache,
  configureJWKCache,
  clearJWKCache,
} from "./core/jwk.ts";

export * from "./core/utils/index.ts";
