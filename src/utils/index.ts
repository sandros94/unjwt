import type { JWK, DeriveKeyBitsOptions, DerivedKeyBitsResult } from "../types";

export const textEncoder = /* @__PURE__ */ new TextEncoder();
export const textDecoder = /* @__PURE__ */ new TextDecoder();

/* Base64 URL encoding function */
export function base64UrlEncode(data: Uint8Array | string): string {
  const encodedData =
    data instanceof Uint8Array ? data : textEncoder.encode(data);
  return btoa(String.fromCodePoint(...encodedData))
    .replace(/=/g, "")
    .replace(/\+/g, "-")
    .replace(/\//g, "_");
}

/* Base64 URL decoding function */
export function base64UrlDecode(): Uint8Array;
export function base64UrlDecode(str?: string | undefined): Uint8Array;
export function base64UrlDecode<T extends boolean | undefined>(
  str?: string | undefined,
  toString?: T,
): T extends true ? string : Uint8Array;
export function base64UrlDecode<T extends boolean | undefined>(
  str?: string | undefined,
  toString?: T,
): Uint8Array | string {
  const decodeToString = toString === true;

  if (!str) {
    return decodeToString ? "" : new Uint8Array(0);
  }
  str = str.replace(/-/g, "+").replace(/_/g, "/");
  while (str.length % 4) str += "=";
  const data = Uint8Array.from(atob(str), (b) => b.codePointAt(0)!);

  return decodeToString ? textDecoder.decode(data) : data;
}

/* Generate a random Uint8Array of specified length */
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

/**
 * Derives raw key bits from a password using PBKDF2.
 *
 * This function generates the raw cryptographic material. You will typically
 * need to import these bits using `importKey` for the specific cryptographic
 * algorithm you intend to use (e.g., "HS256" for signing, "AES-GCM" for encryption).
 *
 * @param password The password to derive the key from.
 * @param options Options controlling the derivation process, including the desired key length.
 * @returns A Promise resolving to an object containing the derived bits, salt, and iterations.
 */
export async function deriveKeyBitsFromPassword(
  password: string | Uint8Array,
  options: DeriveKeyBitsOptions & { keyLength: number },
): Promise<DerivedKeyBitsResult> {
  const {
    keyLength,
    salt = randomBytes(16),
    iterations = 2048,
    hash = "SHA-256",
  } = options;

  if (!keyLength || keyLength <= 0) {
    throw new Error("keyLength must be a positive number.");
  }
  if (salt.length === 0) {
    throw new Error("Salt cannot be empty.");
  }
  if (iterations <= 0) {
    throw new Error("Iterations must be positive.");
  }

  const passwordBuffer =
    typeof password === "string" ? textEncoder.encode(password) : password;

  // 1. Import the password as a base key for PBKDF2
  const baseKey = await crypto.subtle.importKey(
    "raw",
    passwordBuffer,
    { name: "PBKDF2" },
    false,
    ["deriveBits"],
  );

  // 2. Define PBKDF2 parameters
  const pbkdf2Params: Pbkdf2Params = {
    name: "PBKDF2",
    hash: hash,
    salt: salt,
    iterations: iterations,
  };

  // 3. Derive the key bits
  const derivedBits = await crypto.subtle.deriveBits(
    pbkdf2Params,
    baseKey,
    keyLength,
  );

  return { derivedBits, salt, iterations, keyLength, hash };
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
