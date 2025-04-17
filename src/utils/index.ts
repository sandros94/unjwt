import { Buffer } from "node:buffer";
import { getRandomValues } from "uncrypto";

export const textEncoder = /* @__PURE__ */ new TextEncoder();
export const textDecoder = /* @__PURE__ */ new TextDecoder();

// Base64 URL encoding function
export function base64UrlEncode(data: Uint8Array): string {
  return Buffer.from(data)
    .toString("base64")
    .replace(/=/g, "")
    .replace(/\+/g, "-")
    .replace(/\//g, "_");
}

// Base64 URL decoding function
export function base64UrlDecode(str?: string): Uint8Array {
  if (!str) {
    return new Uint8Array(0);
  }
  str = str.replace(/-/g, "+").replace(/_/g, "/");
  while (str.length % 4) str += "=";
  return Buffer.from(str, "base64");
}

// Generate a random Uint8Array of specified length
export function randomBytes(length: number): Uint8Array {
  return getRandomValues(new Uint8Array(length));
}

/**
 * Concatenates multiple Uint8Arrays
 * @param arrays Arrays to concatenate
 * @returns Concatenated array
 */
export function concatUint8Arrays(...arrays: Uint8Array[]): Uint8Array {
  const totalLength = arrays.reduce((length, arr) => length + arr.length, 0);
  const result = new Uint8Array(totalLength);

  let offset = 0;
  for (const arr of arrays) {
    result.set(arr, offset);
    offset += arr.length;
  }

  return result;
}
