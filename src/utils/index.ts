import type { JWK, JWKSet } from "../types";

export const textEncoder = /* @__PURE__ */ new TextEncoder();
export const textDecoder = /* @__PURE__ */ new TextDecoder();

/* Base64 encoding function */
export function base64Encode(data: Uint8Array<ArrayBuffer> | string): string {
  const encodedData =
    data instanceof Uint8Array ? data : textEncoder.encode(data);

  // @ts-expect-error check if toBase64 is available
  if (Uint8Array.prototype.toBase64) {
    // @ts-expect-error
    return encodedData.toBase64();
  }

  return btoa(String.fromCodePoint(...encodedData));
}

/* Base64 URL encoding function */
export function base64UrlEncode(data: Uint8Array<ArrayBuffer> | string): string {
  const encodedData =
    data instanceof Uint8Array ? data : textEncoder.encode(data);

  // @ts-expect-error check if toBase64 is available
  if (Uint8Array.prototype.toBase64) {
    // @ts-expect-error
    return encodedData.toBase64({ alphabet: "base64url", omitPadding: true });
  }

  return btoa(String.fromCodePoint(...encodedData))
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=/g, "");
}

/* Base64 decoding function */
export function base64Decode(str: string | undefined): string;
export function base64Decode<T extends boolean | undefined>(
  str?: string | undefined,
  toString?: T,
): T extends false ? Uint8Array<ArrayBuffer> : string;
export function base64Decode(
  str?: string | undefined,
  toString?: boolean | undefined,
): Uint8Array<ArrayBuffer> | string {
  const decodeToString = toString !== false;

  if (!str) {
    return decodeToString ? "" : new Uint8Array(0);
  }

  // @ts-expect-error check if fromBase64 is available
  const data: Uint8Array<ArrayBuffer> = Uint8Array.fromBase64
    ? // @ts-expect-error
      Uint8Array.fromBase64(str)
    : Uint8Array.from(atob(str), (b) => b.codePointAt(0)!);

  return decodeToString ? textDecoder.decode(data) : data;
}

/* Base64 URL decoding function */
export function base64UrlDecode(str: string | undefined): string;
export function base64UrlDecode<T extends boolean | undefined>(
  str?: string | undefined,
  toString?: T,
): T extends false ? Uint8Array<ArrayBuffer> : string;
export function base64UrlDecode(
  str?: string | undefined,
  toString?: boolean | undefined,
): Uint8Array<ArrayBuffer> | string {
  const decodeToString = toString !== false;

  if (!str) {
    return decodeToString ? "" : new Uint8Array(0);
  }

  let data: Uint8Array<ArrayBuffer>;

  // @ts-expect-error check if fromBase64 is available
  if (Uint8Array.fromBase64) {
    // @ts-expect-error
    data = Uint8Array.fromBase64(str, { alphabet: "base64url" });
  } else {
    str = str.replace(/-/g, "+").replace(/_/g, "/");
    while (str.length % 4) str += "=";
    data = Uint8Array.from(atob(str), (b) => b.codePointAt(0)!);
  }

  return decodeToString ? textDecoder.decode(data) : data;
}

/* Generate a random Uint8Array<ArrayBuffer> of specified length */
export function randomBytes(length: Readonly<number>): Uint8Array<ArrayBuffer> {
  return crypto.getRandomValues(new Uint8Array(length));
}

/**
 * Concatenates multiple Uint8Arrays
 * @param arrays Arrays to concatenate
 * @returns Concatenated array
 */
export function concatUint8Arrays(
  ...arrays: Readonly<Uint8Array<ArrayBuffer>[]>
): Uint8Array<ArrayBuffer> {
  const totalLength = arrays.reduce((length, arr) => length + arr.length, 0);
  const result = new Uint8Array(totalLength);

  let offset = 0;
  for (const arr of arrays) {
    result.set(arr, offset);
    offset += arr.length;
  }

  return result;
}

export function maybeArray<T>(item: T | T[]): T[] {
  return Array.isArray(item) ? item : [item];
}

/* Type guard for JWK */
export function isJWK(key: any): key is JWK {
  return (
    typeof key === "object" &&
    key !== null &&
    "kty" in key &&
    typeof (key as JWK).kty === "string"
  );
}

/* Type guard for JWK Set */
export function isJWKSet(key: any): key is JWKSet {
  return (
    key &&
    typeof key === "object" &&
    "keys" in key &&
    Array.isArray((key as JWKSet).keys)
  );
}

export function assertCryptoKey(key: unknown): asserts key is CryptoKey {
  if (!isCryptoKey(key)) {
    throw new Error("CryptoKey instance expected");
  }
}

/* Type guard for CryptoKey */
export function isCryptoKey(key: unknown): key is CryptoKey {
  // @ts-expect-error
  return key?.[Symbol.toStringTag] === "CryptoKey";
}

export const isCryptoKeyPair = (key: any): key is CryptoKeyPair =>
  key &&
  typeof key === "object" &&
  isCryptoKey(key.publicKey) &&
  isCryptoKey(key.privateKey);
