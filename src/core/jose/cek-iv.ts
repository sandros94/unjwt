/**
 * This is a fork of Jose library's utility functions.
 * @source https://github.com/panva/jose/tree/69b7960c67e05be55fa2ec31c74b987696c20c60/src/lib/cek.ts
 * @source https://github.com/panva/jose/tree/69b7960c67e05be55fa2ec31c74b987696c20c60/src/lib/iv.ts
 * @license MIT https://github.com/panva/jose/blob/69b7960c67e05be55fa2ec31c74b987696c20c60/LICENSE.md
 */

const IV_BIT_LENGTHS: Record<string, number> = {
  A128GCM: 96,
  A128GCMKW: 96,
  A192GCM: 96,
  A192GCMKW: 96,
  A256GCM: 96,
  A256GCMKW: 96,
  "A128CBC-HS256": 128,
  "A192CBC-HS384": 128,
  "A256CBC-HS512": 128,
};

const CEK_BIT_LENGTHS: Record<string, number> = {
  A128GCM: 128,
  A192GCM: 192,
  A256GCM: 256,
  "A128CBC-HS256": 256,
  "A192CBC-HS384": 384,
  "A256CBC-HS512": 512,
};

export function bitLengthIV(alg: string) {
  const length = IV_BIT_LENGTHS[alg];
  if (length === undefined) {
    throw new Error(`Unsupported JWE Algorithm: ${alg}`);
  }
  return length;
}
export function generateIV(alg: string): Uint8Array<ArrayBuffer> {
  return crypto.getRandomValues(new Uint8Array(bitLengthIV(alg) >> 3));
}

export function checkIvLength(enc: string, iv: Uint8Array<ArrayBuffer>) {
  if (iv.length << 3 !== bitLengthIV(enc)) {
    throw new Error("Invalid Initialization Vector length");
  }
}

export function bitLengthCEK(alg: string) {
  const length = CEK_BIT_LENGTHS[alg];
  if (length === undefined) {
    throw new Error(`Unsupported JWE Algorithm: ${alg}`);
  }
  return length;
}

export function generateCEK(alg: string): Uint8Array<ArrayBuffer> {
  return crypto.getRandomValues(new Uint8Array(bitLengthCEK(alg) >> 3));
}

export function checkCEKLength(cek: Uint8Array<ArrayBuffer>, expected: number) {
  const actual = cek.byteLength << 3;
  if (actual !== expected) {
    throw new Error(
      `Invalid Content Encryption Key length. Expected ${expected} bits, got ${actual} bits`,
    );
  }
}
