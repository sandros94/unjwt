export const textEncoder = /* @__PURE__ */ new TextEncoder();
export const textDecoder = /* @__PURE__ */ new TextDecoder();

// Base64 URL encoding function
export function base64UrlEncode(data: Readonly<Uint8Array>): string {
  return btoa(String.fromCodePoint(...data))
    .replace(/=/g, "")
    .replace(/\+/g, "-")
    .replace(/\//g, "_");
}

// Base64 URL decoding function
export function base64UrlDecode(str?: Readonly<string>): Uint8Array {
  if (!str) {
    return new Uint8Array(0);
  }
  str = str.replace(/-/g, "+").replace(/_/g, "/");
  while (str.length % 4) str += "=";
  return Uint8Array.from(atob(str), (b) => b.codePointAt(0)!);
}

// Generate a random Uint8Array of specified length
export function randomBytes(length: Readonly<number>): Uint8Array {
  return crypto.getRandomValues(new Uint8Array(length));
}

/**
 * Concatenates multiple Uint8Arrays
 * @param arrays Arrays to concatenate
 * @returns Concatenated array
 */
export function concatUint8Arrays(
  ...arrays: Readonly<Uint8Array[]>
): Uint8Array {
  const totalLength = arrays.reduce((length, arr) => length + arr.length, 0);
  const result = new Uint8Array(totalLength);

  let offset = 0;
  for (const arr of arrays) {
    result.set(arr, offset);
    offset += arr.length;
  }

  return result;
}
