// #region docs
import {
  base64UrlParse,
  base64UrlStringify,
  isUnsecureError,
  secureRandomBytes,
} from "unjwt/utils";

/** 32 random bytes as URL-safe text, for an OAuth `state` or a CSRF value. */
export function createState() {
  return base64UrlStringify(secureRandomBytes(32));
}

/** The bytes back, or `null` for anything but text `createState` could have written. */
export function readState(text: string | null) {
  if (text === null) return null;
  try {
    const bytes = base64UrlParse(text, { returnAs: "bytes" });
    return bytes.length === 32 ? bytes : null;
  } catch (error) {
    if (isUnsecureError(error, "MALFORMED")) return null;
    throw error;
  }
}
// #endregion

// #region guards
import type { JWK, JWKSet } from "unjwt/jwk";
import { isJWKSet, isPublicJWK } from "unjwt/utils";

/** The body of `/.well-known/jwks.json`: only the keys that are safe to publish. */
export function publishableKeys(stored: unknown): JWKSet {
  if (!isJWKSet(stored)) throw new TypeError("Stored keys are not a JWK Set.");
  return { keys: stored.keys.filter((key): key is JWK => isPublicJWK(key)) };
}
// #endregion
