import type { JoseAlgorithm } from "./defaults"; // Import the master algorithm type

// --- JWK Function Specific Types ---

/** Structure returned for composite AES-CBC + HMAC keys. */
export type CompositeKey = {
  /** The AES-CBC encryption/decryption key. */
  encryptionKey: CryptoKey;
  /** The HMAC key for integrity/authentication. */
  macKey: CryptoKey;
};

/** Options for the generateKey function. */
export interface GenerateKeyOptions {
  /** Key usages for the generated key(s). Note: For composite keys (CBC), default usages are applied separately. */
  keyUsage?: KeyUsage[];
  /** Mark the key(s) as extractable. Defaults to true. */
  extractable?: boolean;
  /** RSA modulus length. Defaults to 2048. */
  modulusLength?: number;
  /** RSA public exponent. Defaults to 65537 (0x010001). */
  publicExponent?: Uint8Array;
}

/** Options for the importKey function. */
export interface ImportKeyOptions {
  /** Fallback algorithm identifier if not present in the JWK. */
  alg?: JoseAlgorithm; // Use the renamed comprehensive type
  /** Fallback for key extractability if not present in the JWK. Defaults to false. */
  extractable?: boolean;
  /** Fallback for key usages if not present in the JWK. If still unspecified, defaults will be inferred. */
  keyUsages?: KeyUsage[];
}

// --- Standard JWK Interfaces ---

/**
 * Forked from https://github.com/panva/jose/tree/v6.0.10
 * Copyright (c) 2018 Filip Skokan.
 * LICENSE: https://github.com/panva/jose/blob/v6.0.10/LICENSE.md
 */

/** Generic JSON Web Key Parameters. */
export interface JWKParameters {
  /** JWK "kty" (Key Type) Parameter */
  kty: string;
  /**
   * JWK "alg" (Algorithm) Parameter
   *
   * @see {@link https://github.com/panva/jose/issues/210 Algorithm Key Requirements}
   */
  alg?: string;
  /** JWK "key_ops" (Key Operations) Parameter */
  key_ops?: KeyUsage[];
  /** JWK "ext" (Extractable) Parameter */
  ext?: boolean;
  /** JWK "use" (Public Key Use) Parameter */
  use?: string;
  /** JWK "x5c" (X.509 Certificate Chain) Parameter */
  x5c?: string[];
  /** JWK "x5t" (X.509 Certificate SHA-1 Thumbprint) Parameter */
  x5t?: string;
  /** JWK "x5t#S256" (X.509 Certificate SHA-256 Thumbprint) Parameter */
  "x5t#S256"?: string;
  /** JWK "x5u" (X.509 URL) Parameter */
  x5u?: string;
  /** JWK "kid" (Key ID) Parameter */
  kid?: string;
}

/** Convenience interface for Public RSA JSON Web Keys */
export interface JWK_RSA_Public extends JWKParameters {
  /** RSA JWK "e" (Exponent) Parameter */
  e: string;
  /** RSA JWK "n" (Modulus) Parameter */
  n: string;
  oth?: RsaOtherPrimesInfo[];
}

/** Convenience interface for Private RSA JSON Web Keys */
export interface JWK_RSA_Private extends JWK_RSA_Public, JWKParameters {
  /** RSA JWK "d" (Private Exponent) Parameter */
  d: string;
  /** RSA JWK "dp" (First Factor CRT Exponent) Parameter */
  dp: string;
  /** RSA JWK "dq" (Second Factor CRT Exponent) Parameter */
  dq: string;
  /** RSA JWK "p" (First Prime Factor) Parameter */
  p: string;
  /** RSA JWK "q" (Second Prime Factor) Parameter */
  q: string;
  /** RSA JWK "qi" (First CRT Coefficient) Parameter */
  qi: string;
}

/** Convenience interface for oct JSON Web Keys */
export interface JWK_oct extends JWKParameters {
  /** Oct JWK "k" (Key Value) Parameter */
  k: string;
}

/**
 * JSON Web Key ({@link https://www.rfc-editor.org/rfc/rfc7517 JWK}). "RSA" and "oct"
 * key types are supported.
 */
export type JWK = JWK_RSA_Public | JWK_RSA_Private | JWK_oct;
