/**
 * This is a fork of Jose library's utility functions.
 * @source https://github.com/panva/jose/tree/69b7960c67e05be55fa2ec31c74b987696c20c60/src/lib/aesgcmkw.ts
 * @license MIT https://github.com/panva/jose/blob/69b7960c67e05be55fa2ec31c74b987696c20c60/LICENSE.md
 */

import { base64UrlEncode } from "../utils";

import { encrypt, decrypt } from "./encrypt-decrypt";

export async function encryptIV(
  alg: string,
  key: unknown,
  cek: Uint8Array<ArrayBuffer>,
  iv?: Uint8Array<ArrayBuffer>,
) {
  const jweAlgorithm = alg.slice(0, 7);

  const wrapped = await encrypt(jweAlgorithm, cek, key, iv, new Uint8Array(0));

  return {
    encryptedKey: wrapped.ciphertext,
    iv: base64UrlEncode(wrapped.iv!),
    tag: base64UrlEncode(wrapped.tag!),
  };
}

export async function decryptIV(
  alg: string,
  key: unknown,
  encryptedKey: Uint8Array<ArrayBuffer>,
  iv: Uint8Array<ArrayBuffer>,
  tag: Uint8Array<ArrayBuffer>,
) {
  const jweAlgorithm = alg.slice(0, 7);
  return decrypt(jweAlgorithm, key, encryptedKey, iv, tag, new Uint8Array(0));
}
