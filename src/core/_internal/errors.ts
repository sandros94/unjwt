import { sanitizeObjectCopy } from "unsecure/sanitize";
import type { JWTErrorCode } from "../../error.ts";
import { JWTError } from "../../error.ts";

/** Wraps a non-`JWTError` thrown by a key lookup as `ERR_JWK_KEY_NOT_FOUND`. */
export function asKeyLookupError(error: unknown, what: string): JWTError {
  return asJWTError(error, {
    code: "ERR_JWK_KEY_NOT_FOUND",
    message: `Key lookup failed for ${what}.`,
  });
}

/** Returns a `JWTError` as is. Wraps anything else under `message` and `code`, with the original as `cause`. */
export function asJWTError(
  error: unknown,
  options: { code: JWTErrorCode; message: string },
): JWTError {
  if (error instanceof JWTError) return error;
  return new JWTError(options.message, options.code, error);
}

/** Returns a sanitized deep copy of a JSON object. A value JSON cannot hold (a `Date`, a `Map`, a class instance) throws the given error. */
export function copyJsonObject<T>(value: T, options: { code: JWTErrorCode; message: string }): T {
  try {
    return sanitizeObjectCopy(value);
  } catch (error) {
    throw asJWTError(error, options);
  }
}

/** RFC 7516 §11.5: wraps a non-`JWTError` unwrap or decryption failure as `ERR_JWE_DECRYPTION_FAILED` with a fixed message. */
export function asDecryptionError(error: unknown): JWTError {
  return asJWTError(error, {
    code: "ERR_JWE_DECRYPTION_FAILED",
    message: "JWE decryption failed.",
  });
}
