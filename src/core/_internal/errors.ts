import { sanitizeObjectCopy } from "unsecure/sanitize";
import type { JWTErrorCode } from "../../error.ts";
import { JWTError } from "../../error.ts";

/** Wrap a non-`JWTError` thrown by a key lookup as `ERR_JWK_KEY_NOT_FOUND`. */
export function asKeyLookupError(error: unknown, what: string): JWTError {
  return asJWTError(error, {
    code: "ERR_JWK_KEY_NOT_FOUND",
    message: `Key lookup failed for ${what}.`,
  });
}

/** Pass a `JWTError` through; wrap anything else under `message` / `code` with it as `cause`. */
export function asJWTError(
  error: unknown,
  options: { code: JWTErrorCode; message: string },
): JWTError {
  if (error instanceof JWTError) return error;
  return new JWTError(options.message, options.code, error);
}

/** A sanitized deep copy of a JSON object; a value JSON cannot carry (a `Date`, a `Map`, a class instance) is the given error, the refusal as `cause`. */
export function copyJsonObject<T>(value: T, options: { code: JWTErrorCode; message: string }): T {
  try {
    return sanitizeObjectCopy(value);
  } catch (error) {
    throw asJWTError(error, options);
  }
}

/** RFC 7516 §11.5 — a failed unwrap or decryption says only that it failed. */
export function asDecryptionError(error: unknown): JWTError {
  return asJWTError(error, {
    code: "ERR_JWE_DECRYPTION_FAILED",
    message: "JWE decryption failed.",
  });
}
