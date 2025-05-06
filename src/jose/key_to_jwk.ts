/* eslint-disable unicorn/filename-case */

/**
 * This is a fork of Jose library's utility functions.
 * @source https://github.com/panva/jose/tree/69b7960c67e05be55fa2ec31c74b987696c20c60/src/lib/key_to_jwt.ts
 * @license MIT https://github.com/panva/jose/blob/69b7960c67e05be55fa2ec31c74b987696c20c60/LICENSE.md
 */

import type { JWK } from "../types";
import { base64UrlEncode, isCryptoKey } from "../utils";

export async function keyToJWK(key: unknown): Promise<JWK> {
  if (key instanceof Uint8Array) {
    return {
      kty: "oct",
      k: base64UrlEncode(key),
    };
  }
  if (!isCryptoKey(key)) {
    throw new TypeError(
      `Key must be ${key} one of type: CryptoKey, or Uint8Array`,
    );
  }
  if (!key.extractable) {
    throw new TypeError(
      "non-extractable CryptoKey cannot be exported as a JWK",
    );
  }
  const jwk = await crypto.subtle.exportKey("jwk", key);

  return jwk as JWK;
}
