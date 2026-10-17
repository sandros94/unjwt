import { UnsecureError, type UnsecureErrorCode } from "unsecure/errors";

/**
 * The `UnsecureError` class unjwt itself throws.
 *
 * `unsecure` is inlined into unjwt's dist, so the class a consumer gets from
 * their own `unsecure` dependency is a *different* class — `instanceof` against
 * it never matches what unjwt throws. This re-export is the identity that does
 * match, both for errors thrown directly by the `unjwt/utils` primitives and
 * for the `cause` carried by a {@link JWTError}.
 */
export { UnsecureError, type UnsecureErrorCode };

/**
 * The closed union of error codes unjwt itself throws.
 *
 * Code naming follows the JOSE spec hierarchy:
 *   ERR_JWT_*  — RFC 7519 JSON Web Token claim validation
 *   ERR_JWS_*  — RFC 7515 JSON Web Signature
 *   ERR_JWE_*  — RFC 7516 JSON Web Encryption
 *   ERR_JWK_*  — RFC 7517 JSON Web Key
 *   ERR_SESSION_* — the framework session adapters
 *
 * Use this type where a typo must not compile — {@link isJWTError} takes it,
 * so `isJWTError(err, "ERR_JWS_INVALD")` is a type error rather than a check
 * that silently never matches. Use {@link JWTErrorCode} for values that may
 * legitimately carry a code this version does not know about.
 */
export type KnownJWTErrorCode =
  // JWT claim validation (RFC 7519)
  | "ERR_JWT_EXPIRED" // exp elapsed or maxTokenAge exceeded
  | "ERR_JWT_NBF" // nbf is in the future
  | "ERR_JWT_CLAIM_INVALID" // iss / sub / aud / custom claim mismatch
  | "ERR_JWT_CLAIM_MISSING" // required claim absent
  // JWS (RFC 7515)
  | "ERR_JWS_INVALID" // structural / format error
  | "ERR_JWS_INVALID_SERIALIZATION" // JSON not a valid General / Flattened shape
  | "ERR_JWS_SIGNATURE_INVALID" // cryptographic signature verification failed
  | "ERR_JWS_ALG_NOT_ALLOWED" // algorithm rejected by caller policy
  | "ERR_JWS_ALG_MISSING" // required `alg` option absent on sign
  | "ERR_JWS_SIGNER_ALG_INFERENCE" // cannot infer `alg` for a signer's JWK
  | "ERR_JWS_NO_MATCHING_SIGNER" // no signature matched the provided key
  | "ERR_JWS_HEADER_PARAMS_NOT_DISJOINT" // protected / unprotected header overlap on a signer
  | "ERR_JWS_B64_INCONSISTENT" // RFC 7797 §3 — `b64` must be identical across all signers
  // JWE (RFC 7516)
  | "ERR_JWE_INVALID" // structural / format / option error
  | "ERR_JWE_INVALID_SERIALIZATION" // JSON not a valid General / Flattened shape
  | "ERR_JWE_DECRYPTION_FAILED" // content decryption or key unwrap failed
  | "ERR_JWE_ALG_NOT_ALLOWED" // algorithm rejected by caller policy
  | "ERR_JWE_ALG_MISSING" // required `alg` option absent on encrypt
  | "ERR_JWE_ALG_FORBIDDEN_IN_MULTI" // `dir` or bare `ECDH-ES` passed to encryptMulti
  | "ERR_JWE_ENC_MISSING" // required `enc` option absent on encrypt
  | "ERR_JWE_RECIPIENT_ALG_INFERENCE" // cannot infer `alg` for a recipient's JWK
  | "ERR_JWE_NO_MATCHING_RECIPIENT" // no recipient matched the provided key
  | "ERR_JWE_HEADER_PARAMS_NOT_DISJOINT" // protected/unprotected/per-recipient header overlap
  // JWK (RFC 7517)
  | "ERR_JWK_INVALID" // malformed or unsupported key material
  | "ERR_JWK_KEY_NOT_FOUND" // no matching key in a JWK Set
  | "ERR_JWK_UNSUPPORTED" // caller requested an algorithm or format the library does not support
  // Session adapters
  | "ERR_SESSION_TOKEN_INVALID" // an incoming session token failed verification or decryption
  | "ERR_SESSION_READONLY_EVENT" // update on a context that takes no cookie, update / clear once the response was sent
  | "ERR_SESSION_KEY_INVALID" // session key missing, of the wrong shape, or a password string
  | "ERR_SESSION_CONFIG_INVALID" // a session config combination that cannot work
  // Caller input that is not token or key material
  | "ERR_INVALID_OPTION"; // an option value is malformed or out of its documented range

/**
 * A {@link JWTError} `code`: every {@link KnownJWTErrorCode}, plus any other
 * string for forward compatibility — a newer unjwt (or a caller constructing
 * its own `JWTError`) may carry a code this version's union does not list.
 */
export type JWTErrorCode = KnownJWTErrorCode | (string & {});

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
 * that code. When called with any other `KnownJWTErrorCode`, `code` is narrowed
 * but `cause` remains `unknown`. When called without a code, narrows only to
 * `JWTError`.
 *
 * `code` is a {@link KnownJWTErrorCode}, so a misspelled code fails to
 * type-check instead of silently never matching.
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
 * Type guard that narrows `error` to the bundled {@link UnsecureError}, the
 * class thrown by unjwt's codec / JSON / random primitives and carried as the
 * `cause` of a {@link JWTError} when a wire segment or key field fails to
 * decode. Pass a `code` to narrow further.
 *
 * Check against this export rather than a `UnsecureError` imported from a
 * consumer-installed `unsecure`: unjwt bundles its own copy, so the two classes
 * are distinct and `instanceof` against the latter is always `false`.
 *
 * @example
 * import { isJWTError, isUnsecureError } from "unjwt/jws";
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
