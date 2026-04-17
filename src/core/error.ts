/**
 * All known error codes thrown by unjwt.
 *
 * Code naming follows the JOSE spec hierarchy:
 *   ERR_JWT_*  — RFC 7519 JSON Web Token claim validation
 *   ERR_JWS_*  — RFC 7515 JSON Web Signature
 *   ERR_JWE_*  — RFC 7516 JSON Web Encryption
 *   ERR_JWK_*  — RFC 7517 JSON Web Key
 */
export type JWTErrorCode =
  // JWT claim validation (RFC 7519)
  | "ERR_JWT_EXPIRED" // exp elapsed or maxTokenAge exceeded
  | "ERR_JWT_NBF" // nbf is in the future
  | "ERR_JWT_CLAIM_INVALID" // iss / sub / aud / custom claim mismatch
  | "ERR_JWT_CLAIM_MISSING" // required claim absent
  // JWS (RFC 7515)
  | "ERR_JWS_INVALID" // structural / format error
  | "ERR_JWS_SIGNATURE_INVALID" // cryptographic signature verification failed
  | "ERR_JWS_ALG_NOT_ALLOWED" // algorithm rejected by caller policy
  | "ERR_JWS_ALG_MISSING" // required `alg` option absent on sign
  // JWE (RFC 7516)
  | "ERR_JWE_INVALID" // structural / format / option error
  | "ERR_JWE_DECRYPTION_FAILED" // content decryption or key unwrap failed
  | "ERR_JWE_ALG_NOT_ALLOWED" // algorithm rejected by caller policy
  | "ERR_JWE_ALG_MISSING" // required `alg` option absent on encrypt
  | "ERR_JWE_ENC_MISSING" // required `enc` option absent on encrypt
  // JWK (RFC 7517)
  | "ERR_JWK_INVALID" // malformed or unsupported key material
  | "ERR_JWK_KEY_NOT_FOUND" // no matching key in a JWK Set
  | "ERR_JWK_UNSUPPORTED" // caller requested an algorithm or format the library does not support
  | (string & {}); // forward-compatible escape hatch

/**
 * Maps known error codes to their structured `cause` shapes.
 * Only codes that carry decoded context beyond the message appear here.
 * Extend this interface when new structured causes are introduced.
 */
export interface JWTErrorCauseMap {
  /** Decoded claims available at the point the lifetime check failed. */
  ERR_JWT_EXPIRED: { jti?: string; iat?: number; exp?: number };
}

/**
 * Base error class for all unjwt errors. Every error thrown by the library is
 * an instance of `JWTError`, so a single `instanceof` check is sufficient to
 * distinguish library errors from other thrown values. Use the `code` property
 * (or the `isJWTError` type guard) to narrow to a specific error condition.
 *
 * @example
 * import { JWTError, isJWTError } from "unjwt/jws";
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
 * Type guard that narrows `error` to `JWTError`.
 *
 * When called with a code that is a key of `JWTErrorCauseMap`, the return
 * type is additionally narrowed to include the structured `cause` shape for
 * that code. When called with any other `JWTErrorCode`, `code` is narrowed
 * but `cause` remains `unknown`. When called without a code, narrows only to
 * `JWTError`.
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
export function isJWTError<T extends JWTErrorCode>(error: unknown, code: T): error is JWTError<T>;
export function isJWTError(error: unknown): error is JWTError;
export function isJWTError(error: unknown, code?: string): boolean {
  if (!(error instanceof JWTError)) return false;
  return code === undefined || error.code === code;
}
