export type * from "./core/types/index.ts";

export { JWTError, isJWTError, UnsecureError, isUnsecureError } from "./error.ts";
export type {
  JWTErrorCode,
  KnownJWTErrorCode,
  JWTErrorCauseMap,
  UnsecureErrorCode,
} from "./error.ts";

export {
  sign,
  verify,
  signMulti,
  verifyMulti,
  verifyMultiAll,
  generalToFlattenedJWS,
} from "./core/jws/index.ts";
export {
  encrypt,
  decrypt,
  encryptMulti,
  decryptMulti,
  generalToFlattened,
} from "./core/jwe/index.ts";
export { DEFAULT_JOSE_LIMITS } from "./core/_internal/limits.ts";
export {
  generateKey,
  generateJWK,
  thumbprint,
  importKey,
  exportJWK,
  wrapKey,
  unwrapKey,
  deriveKeyFromPassword,
  deriveJWKFromPassword,
  importPEM,
  exportPEM,
  getJWKsFromSet,
  deriveSharedSecret,
  toPublicJWK,
  WeakMapJWKCache,
  configureJWKCache,
  clearJWKCache,
} from "./core/jwk/index.ts";

export * from "./utils/index.ts";
