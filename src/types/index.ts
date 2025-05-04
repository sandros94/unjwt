export * from "./defaults";

export * from "./jwk";
export * from "./jwt";
export * from "./jws";
export * from "./jwe";

/** Options for deriving key bits from a password using PBKDF2. */
export interface DeriveKeyBitsOptions {
  /**
   * The desired length of the derived key in bits.
   * This depends on the algorithm the key will be used for (e.g., 256 for HS256 or A128GCM).
   */
  keyLength?: number; // Changed to optional
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
