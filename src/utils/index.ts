import { Buffer } from "buffer";

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
  const { buffer, byteLength, byteOffset } = Buffer.from(str, "base64");

  // Return a Uint8Array copy instead of the Buffer instance
  return new Uint8Array(buffer, byteOffset, byteLength);
}

// Generate a random Uint8Array of specified length
export function randomBytes(length: number): Uint8Array {
  return crypto.getRandomValues(new Uint8Array(length));
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

/** Encodes a string to a Uint8Array using UTF-8 */
export function stringToBytes(str: string): Uint8Array {
  const { buffer, byteLength, byteOffset } = Buffer.from(str, "utf8");

  // Return a Uint8Array copy instead of the Buffer instance
  return new Uint8Array(buffer, byteOffset, byteLength);
}

/** Decodes a Uint8Array to a string using UTF-8 */
export function bytesToString(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString("utf8");
}
