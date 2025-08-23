/**
 * This is a fork of Jose library's utility functions.
 * @source https://github.com/panva/jose/tree/69b7960c67e05be55fa2ec31c74b987696c20c60/src/lib/cek.ts
 * @source https://github.com/panva/jose/tree/69b7960c67e05be55fa2ec31c74b987696c20c60/src/lib/iv.ts
 * @license MIT https://github.com/panva/jose/blob/69b7960c67e05be55fa2ec31c74b987696c20c60/LICENSE.md
 */

export function bitLengthIV(alg: string) {
  switch (alg) {
    case "A128GCM":
    case "A128GCMKW":
    case "A192GCM":
    case "A192GCMKW":
    case "A256GCM":
    case "A256GCMKW": {
      return 96;
    }
    case "A128CBC-HS256":
    case "A192CBC-HS384":
    case "A256CBC-HS512": {
      return 128;
    }
    default: {
      throw new Error(`Unsupported JWE Algorithm: ${alg}`);
    }
  }
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
  switch (alg) {
    case "A128GCM": {
      return 128;
    }
    case "A192GCM": {
      return 192;
    }
    case "A256GCM":
    case "A128CBC-HS256": {
      return 256;
    }
    case "A192CBC-HS384": {
      return 384;
    }
    case "A256CBC-HS512": {
      return 512;
    }
    default: {
      throw new Error(`Unsupported JWE Algorithm: ${alg}`);
    }
  }
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
