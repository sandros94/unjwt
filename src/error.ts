import { UnsecureError, type UnsecureErrorCode } from "unsecure/errors";

/**
 * The error class the `unjwt/utils` encoding, JSON and random primitives throw.
 * A {@link JWTError} keeps it as `cause` when a token segment or key field fails to decode.
 *
 * Use this export with `instanceof`. A separately installed copy of the class is a different class and never matches.
 */
export { UnsecureError, type UnsecureErrorCode };

/**
 * Every error code unjwt throws, as a closed union.
 *
 * Prefixes follow the specs:
 *   ERR_JWT_*: RFC 7519 claim validation
 *   ERR_JWS_*: RFC 7515 signatures
 *   ERR_JWE_*: RFC 7516 encryption
 *   ERR_JWK_*: RFC 7517 keys
 *   ERR_DPOP_*: RFC 9449 proofs
 *   ERR_SESSION_*: sessions
 *
 * {@link isJWTError} takes this type, so a misspelled code such as `"ERR_JWS_INVALD"` is a type error.
 * Use {@link JWTErrorCode} for a value that may hold a code outside this union.
 */
export type KnownJWTErrorCode =
  // JWT claim validation (RFC 7519)
  | "ERR_JWT_EXPIRED" // `exp` has passed or `iat` is older than `maxTokenAge`
  | "ERR_JWT_NBF" // `nbf` is in the future
  | "ERR_JWT_CLAIM_INVALID" // `iss`, `sub` or `aud` mismatch, or a malformed claim
  | "ERR_JWT_CLAIM_MISSING" // a required claim is absent
  // JWS (RFC 7515)
  | "ERR_JWS_INVALID" // malformed token, header or option
  | "ERR_JWS_INVALID_SERIALIZATION" // not a General or Flattened JSON JWS
  | "ERR_JWS_SIGNATURE_INVALID" // no signature verified with the key
  | "ERR_JWS_ALG_NOT_ALLOWED" // `alg` not allowed, not supported, or not fit for the key
  | "ERR_JWS_ALG_MISSING" // `sign` has no `alg` and the key names none
  | "ERR_JWS_SIGNER_ALG_INFERENCE" // a signer's key gives no `alg` to infer
  | "ERR_JWS_NO_MATCHING_SIGNER" // no signature matches the key under `strictSignerMatch`
  | "ERR_JWS_HEADER_PARAMS_NOT_DISJOINT" // a signer's protected and unprotected headers share a name
  | "ERR_JWS_B64_INCONSISTENT" // signers disagree on `b64` (RFC 7797 §3)
  // JWE (RFC 7516)
  | "ERR_JWE_INVALID" // malformed token, header or option
  | "ERR_JWE_INVALID_SERIALIZATION" // not a General or Flattened JSON JWE
  | "ERR_JWE_DECRYPTION_FAILED" // key unwrap or content decryption failed
  | "ERR_JWE_ALG_NOT_ALLOWED" // `alg` or `enc` not allowed, not supported, or not fit for the key
  | "ERR_JWE_ALG_MISSING" // `encrypt` has no `alg` and none can be inferred
  | "ERR_JWE_ALG_FORBIDDEN_IN_MULTI" // `dir` or bare `ECDH-ES` given to `encryptMulti`
  | "ERR_JWE_ENC_MISSING" // `dir` with no `enc` in the options or the key
  | "ERR_JWE_RECIPIENT_ALG_INFERENCE" // a recipient's key gives no `alg` to infer
  | "ERR_JWE_NO_MATCHING_RECIPIENT" // no recipient matches the key under `strictRecipientMatch`
  | "ERR_JWE_HEADER_PARAMS_NOT_DISJOINT" // protected, shared and per-recipient headers share a name
  // JWK (RFC 7517)
  | "ERR_JWK_INVALID" // key missing, malformed, or of the wrong type for the operation
  | "ERR_JWK_KEY_NOT_FOUND" // no usable key: empty JWK Set, failed key lookup, or key limit reached
  | "ERR_JWK_UNSUPPORTED" // an algorithm or key format unjwt does not support
  // DPoP (RFC 9449)
  | "ERR_DPOP_INVALID" // proof form, header, key, algorithm or signature rejected
  | "ERR_DPOP_CLAIM_INVALID" // proof claims fail the time, target or token-binding checks
  | "ERR_DPOP_NONCE_INVALID" // the expected nonce is missing or different
  | "ERR_DPOP_REPLAY" // the replay callback rejected the proof or threw
  // Sessions
  | "ERR_SESSION_TOKEN_INVALID" // the incoming session token failed verification or decryption
  | "ERR_SESSION_READ_FAILED" // `onKeyLookup` threw, or returned a key that cannot be used, while the incoming session token was read
  | "ERR_SESSION_READONLY_EVENT" // `update` with no writable cookie, or `update`/`clear` after the response is sent
  | "ERR_SESSION_KEY_INVALID" // session key missing, of the wrong shape, or a password string
  | "ERR_SESSION_CONFIG_INVALID" // the session config is invalid
  // Caller input that is not token or key material
  | "ERR_INVALID_OPTION"; // an option value is malformed or out of range

/**
 * A {@link JWTError} `code`: any {@link KnownJWTErrorCode} or any other string.
 * A `JWTError` built outside unjwt can hold a code outside the union.
 */
export type JWTErrorCode = KnownJWTErrorCode | (string & {});

/**
 * The structured `cause` of each code that has one.
 * {@link isJWTError} narrows `cause` to this shape for the listed codes.
 */
export interface JWTErrorCauseMap {
  /** The token's `jti` (when a string), `iat` and `exp` claims. */
  ERR_JWT_EXPIRED: { jti?: string; iat?: number; exp?: number };
}

/**
 * The error class of the JWS, JWE, JWK, DPoP and session operations.
 * `code` names the condition. Narrow on it with {@link isJWTError}.
 *
 * The `unjwt/utils` primitives throw {@link UnsecureError} instead.
 *
 * @example
 * import { verify, isJWTError } from "unjwt/jws";
 *
 * try {
 *   await verify(token, key);
 * } catch (err) {
 *   if (isJWTError(err, "ERR_JWT_EXPIRED")) {
 *     console.log(err.cause.jti); // string | undefined
 *   }
 * }
 */
export class JWTError<TCode extends JWTErrorCode = JWTErrorCode> extends Error {
  readonly code: TCode;
  override readonly cause?: unknown;

  constructor(message: string, code: TCode, cause?: unknown) {
    super(message);
    this.name = "JWTError";
    this.code = code;
    this.cause = cause;
  }
}

/**
 * Returns `true` when `error` is a {@link JWTError}, and with `code`, only when its `code` is that one.
 *
 * With a code listed in {@link JWTErrorCauseMap}, `cause` narrows to that shape.
 * With any other code, `code` narrows and `cause` stays `unknown`.
 * `code` is a {@link KnownJWTErrorCode}, so a misspelled code is a type error.
 *
 * @example
 * if (isJWTError(err, "ERR_JWT_EXPIRED")) {
 *   err.cause.jti // string | undefined  ✓
 * }
 */
export function isJWTError<T extends keyof JWTErrorCauseMap>(
  error: unknown,
  code: T,
): error is JWTError<T> & { cause: JWTErrorCauseMap[T] };
export function isJWTError<T extends KnownJWTErrorCode>(
  error: unknown,
  code: T,
): error is JWTError<T>;
export function isJWTError(error: unknown): error is JWTError;
export function isJWTError(error: unknown, code?: string): boolean {
  if (!(error instanceof JWTError)) return false;
  return code === undefined || error.code === code;
}

/**
 * Returns `true` when `error` is the {@link UnsecureError} unjwt throws, and with `code`, only when its `code` is that one.
 * Use it on the `cause` of a {@link JWTError} whose token segment or key field failed to decode.
 *
 * A separately installed copy of the class never matches.
 *
 * @example
 * import { verify, isJWTError, isUnsecureError } from "unjwt/jws";
 *
 * const error = await verify(token, key).catch((e) => e);
 * if (isJWTError(error, "ERR_JWS_INVALID") && isUnsecureError(error.cause, "MALFORMED")) {
 *   // a segment of the token is not canonical base64url
 * }
 */
export function isUnsecureError<T extends UnsecureErrorCode>(
  error: unknown,
  code: T,
): error is UnsecureError & { code: T };
export function isUnsecureError(error: unknown): error is UnsecureError;
export function isUnsecureError(error: unknown, code?: string): boolean {
  if (!(error instanceof UnsecureError)) return false;
  return code === undefined || error.code === code;
}
