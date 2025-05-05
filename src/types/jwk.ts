import type {
  JoseAlgorithm,
  HmacWrapAlgorithm,
  Pbes2Algorithm,
} from "./defaults"; // Import the master algorithm type

// --- JWK Function Specific Types ---

export type GenerateJoseAlgorithm = Exclude<JoseAlgorithm, Pbes2Algorithm>;
export type GenerateHmacWrapAlgorithm = Exclude<
  HmacWrapAlgorithm,
  Pbes2Algorithm
>;

/** Structure returned for composite AES-CBC + HMAC keys. */
export type CompositeKey = {
  /** The AES-CBC encryption/decryption key. */
  encryptionKey: CryptoKey;
  /** The HMAC key for integrity/authentication. */
  macKey: CryptoKey;
};

/** Options for the generateKey function. */
export interface GenerateKeyOptions<
  ToJWK extends boolean | undefined = undefined,
> {
  /** Key usages for the generated key(s). Note: For composite keys (CBC), default usages are applied separately. */
  keyUsage?: KeyUsage[];
  /** Mark the key(s) as extractable. Defaults to true. */
  extractable?: boolean;
  /** RSA modulus length. Defaults to 2048. */
  modulusLength?: number;
  /** RSA public exponent. Defaults to 65537 (0x010001). */
  publicExponent?: Uint8Array;
  /** Export the generated key(s) as JWK. If true, the key(s) will be returned in JWK format. */
  toJWK?: ToJWK;
}

/** Options for the importKey function. */
export interface ImportKeyOptions {
  /** Fallback algorithm identifier if not present in the JWK. */
  alg?: JoseAlgorithm;
  /** Fallback for key extractability if not present in the JWK. Defaults to false. */
  extractable?: boolean;
  /** Fallback for key usages if not present in the JWK. If still unspecified, defaults will be inferred. */
  keyUsages?: KeyUsage[];
}

/** Options for deriving key bits from a password using PBKDF2. */
export interface DeriveKeyBitsOptions {
  /**
   * The desired length of the derived key in bits.
   * This depends on the algorithm the key will be used for (e.g., 256 for HS256 or A128GCM).
   */
  keyLength?: number;
  /**
   * The cryptographic salt. Should be unique for each password,
   * ideally cryptographically random. If not provided, a random 16-byte salt will be generated.
   * Must be stored alongside the derived key or parameters needed to re-derive it.
   */
  salt?: Uint8Array;
  /**
   * The number of iterations for the PBKDF2 algorithm.
   * Higher numbers increase security but also derivation time.
   * @default 2048
   */
  iterations?: number;
  /**
   * The hash algorithm to use in PBKDF2.
   * @default "SHA-256"
   */
  hash?: "SHA-256" | "SHA-384" | "SHA-512";
}

/** Result of deriving key bits from a password. */
export interface DerivedKeyBitsResult {
  /**
   * The raw derived key bits as an ArrayBuffer.
   * These bits need to be imported using `importKey` for a specific algorithm (e.g., "HS256", "AES-GCM").
   */
  derivedBits: ArrayBuffer;
  /**
   * The salt used during derivation. Store this value.
   */
  salt: Uint8Array;
  /**
   * The number of iterations used. Store this value.
   */
  iterations: number;
  /**
   * The hash algorithm used. Store this value.
   */
  hash: "SHA-256" | "SHA-384" | "SHA-512";
  /**
   * The length of the derived key in bits.
   */
  keyLength: number;
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

/** Public RSA JSON Web Keys */
export interface JWK_RSA_Public extends JWKParameters {
  /** RSA JWK "e" (Exponent) Parameter */
  e: string;
  /** RSA JWK "n" (Modulus) Parameter */
  n: string;
  oth?: RsaOtherPrimesInfo[];
}

/** Private RSA JSON Web Keys */
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

/** RSA JSON Web Keys */
export type JWK_RSA = JWK_RSA_Public | JWK_RSA_Private;

/** oct JSON Web Keys */
export interface JWK_oct extends JWKParameters {
  /** Oct JWK "k" (Key Value) Parameter */
  k: string;
}

/**
 * JSON Web Key ({@link https://www.rfc-editor.org/rfc/rfc7517 JWK}). "RSA" and "oct" key types are supported.
 */
export type JWK = JWK_RSA | JWK_oct;
