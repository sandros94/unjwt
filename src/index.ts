export type * from "./core/types";

export { JWTError, isJWTError, UnsecureError, isUnsecureError } from "./core/error";
export type {
  JWTErrorCode,
  KnownJWTErrorCode,
  JWTErrorCauseMap,
  UnsecureErrorCode,
} from "./core/error";

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
// The whole `unjwt/utils` surface — base64url codecs, type guards, claim
// validation, algorithm inference — is re-exported as named exports, so the
// root entry point carries no less than the subpath it mirrors.
export * from "./core/utils";
