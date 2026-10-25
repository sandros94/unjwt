import {
  type ParsePayloadOptions,
  type ComputeJwtTimeClaimsOptions as _ComputeJwtTimeClaimsOptions,
  applyTypDefault as _applyTypDefault,
  parsePayloadBytes,
  parsePayloadSegment,
  getPlaintextBytes as _getPlaintextBytes,
  computeJwtTimeClaims as _computeJwtTimeClaims,
  validateCriticalHeadersJWS as _validateCriticalHeadersJWS,
  validateCriticalHeadersJWE as _validateCriticalHeadersJWE,
  assertCritShape as _assertCritShape,
} from "../core/_internal/jwt.ts";

export { UnsecureError, isUnsecureError, type UnsecureErrorCode } from "../error.ts";

export { secureRandomBytes } from "unsecure/random";
export { safeJsonParse, sanitizeObject, sanitizeObjectCopy } from "unsecure/sanitize";
export { textEncoder, textDecoder } from "unsecure/utils";

export * from "./base64.ts";
export { digestUrl, type DigestHash } from "./digest.ts";
export { concatUint8Arrays, maybeArray } from "./array.ts";
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
} from "./guards.ts";

export { inferJWSAllowedAlgorithms, inferJWEAllowedAlgorithms } from "./algorithms.ts";
export { isJWTContent, computeDurationInSeconds, validateJwtClaims } from "./jwt.ts";
export type * from "./types.ts";

/** @deprecated Use `ParsePayloadOptions` from `unjwt/internal`; removed in v0.9.0. */
export type DecodePayloadOptions = ParsePayloadOptions;
/** @deprecated Use `ComputeJwtTimeClaimsOptions` from `unjwt/internal`; removed in v0.9.0. */
export type ComputeJwtTimeClaimsOptions = _ComputeJwtTimeClaimsOptions;
/** @deprecated Use `applyTypDefault` from `unjwt/internal`; removed in v0.9.0. */
export const applyTypCtyDefaults: typeof _applyTypDefault = _applyTypDefault;
/** @deprecated Use `parsePayloadBytes` from `unjwt/internal`; removed in v0.9.0. */
export const decodePayloadFromBytes: typeof parsePayloadBytes = parsePayloadBytes;
/** @deprecated Use `parsePayloadSegment` from `unjwt/internal`; removed in v0.9.0. */
export const decodePayloadFromB64UrlSegment: typeof parsePayloadSegment = parsePayloadSegment;
/** @deprecated Use `getPlaintextBytes` from `unjwt/internal`; removed in v0.9.0. */
export const getPlaintextBytes: typeof _getPlaintextBytes = _getPlaintextBytes;
/** @deprecated Use `computeJwtTimeClaims` from `unjwt/internal`; removed in v0.9.0. */
export const computeJwtTimeClaims: typeof _computeJwtTimeClaims = _computeJwtTimeClaims;
/** @deprecated Use `validateCriticalHeadersJWS` from `unjwt/internal`; removed in v0.9.0. */
export const validateCriticalHeadersJWS: typeof _validateCriticalHeadersJWS =
  _validateCriticalHeadersJWS;
/** @deprecated Use `validateCriticalHeadersJWE` from `unjwt/internal`; removed in v0.9.0. */
export const validateCriticalHeadersJWE: typeof _validateCriticalHeadersJWE =
  _validateCriticalHeadersJWE;
/** @deprecated Use `assertCritShape` from `unjwt/internal`; removed in v0.9.0. */
export const assertCritShape: typeof _assertCritShape = _assertCritShape;
