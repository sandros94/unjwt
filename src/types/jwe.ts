import type { JoseHeaderParameters, JWTClaims } from "./jwt";
import type {
  JWK,
  JWK_EC_Public,
  KeyManagementAlgorithm,
  ContentEncryptionAlgorithm,
} from "./jwk";

/** Recognized JWE Header Parameters, any other Header Members may also be present. */
export interface JWEHeaderParameters extends JoseHeaderParameters {
  /**
   * `alg` (Algorithm): Header Parameter - Key Management Algorithm
   */
  alg?: string;
  /**
   * `enc` (Encryption Algorithm): Header Parameter - Content Encryption Algorithm
   */
  enc?: string;
  /**
   * `p2c` (PBES2 Count): Header Parameter
   */
  p2c?: number;
  /**
   * `p2s` (PBES2 Salt): Header Parameter. Base64URL encoded.
   */
  p2s?: string;
  /**
   * "iv" (Initialization Vector) Header Parameter for AES GCM Key Wrapping. Base64URL encoded.
   */
  iv?: string;
  /**
   * "tag" (Authentication Tag) Header Parameter for AES GCM Key Wrapping. Base64URL encoded.
   */
  tag?: string;
  /**
   * "epk" (Ephemeral Public Key) Header Parameter for ECDH-ES.
   */
  epk?: JWK_EC_Public;
  /**
   * "apu" (Agreement PartyUInfo) Header Parameter for ECDH-ES. Base64URL encoded.
   */
  apu?: string;
  /**
   * "apv" (Agreement PartyVInfo) Header Parameter for ECDH-ES. Base64URL encoded.
   */
  apv?: string;

  /** Any other JWE Header member. */
  [propName: string]: unknown;
}

/** Recognized JWE Key Management-related Header Parameters. */
export interface JWEKeyManagementHeaderParameters {
  apu?: Uint8Array;
  apv?: Uint8Array;
  /**
   * For Internal use only
   */
  p2c?: number;
  /**
   * For Internal use only
   */
  p2s?: Uint8Array;
  /**
   * For Internal use only
   */
  iv?: Uint8Array;
  /**
   * For Internal use only
   */
  epk?: CryptoKey;
}

/**
 * JWE (JSON Web Encryption) encryption options
 */
export interface JWEEncryptOptions {
  /** JWE "alg" (Algorithm) Header Parameter. Key Management Algorithm. */
  alg?: KeyManagementAlgorithm;
  /** JWE "enc" (Encryption Algorithm) Header Parameter. Content Encryption Algorithm. */
  enc?: ContentEncryptionAlgorithm;

  /** Additional JWE Protected Header parameters. */
  protectedHeader?: Omit<
    JWEHeaderParameters,
    "alg" | "enc" | "iv" | "tag" | "p2s" | "p2c" | "apu" | "apv"
  >;

  // Key Wrapping specific options (passed to jwk.wrapKey)
  /** Initialization Vector for AES-GCMKW key wrapping. Generated if not provided. */
  keyManagementIV?: Uint8Array;
  /** PBES2 Salt value (p2s). Required for PBES2 algorithms. */
  p2s?: Uint8Array;
  /** PBES2 Iteration count (p2c). Required for PBES2 algorithms. */
  p2c?: number;
  /** ECDH-ES Agreement PartyUInfo. */
  ecdhPartyUInfo?: Uint8Array;
  /** ECDH-ES Agreement PartyVInfo. */
  ecdhPartyVInfo?: Uint8Array;

  /**
   * Content Encryption Key (CEK) to use.
   * If provided, it will be used directly. Otherwise, a CEK will be generated.
   */
  cek?: Uint8Array;

  /**
   * Initialization Vector for content encryption.
   * If provided, it will be used. Otherwise, one will be generated.
   */
  contentEncryptionIV?: Uint8Array;
}

/**
 * Key lookup function for JWE decryption.
 * @param header The JWE Protected Header.
 * @returns The key material (CryptoKey, JWK, password string, or raw Uint8Array) or a Promise resolving to it.
 */
export type JWEKeyLookupFunction = (
  header: JWEHeaderParameters,
) =>
  | CryptoKey
  | JWK
  | string
  | Uint8Array
  | Promise<CryptoKey | JWK | string | Uint8Array>;

/**
 * JWE (JSON Web Encryption) decryption options
 */
export interface JWEDecryptOptions {
  /** A list of allowed JWE "alg" (Algorithm) Header Parameter values for key management. */
  algorithms?: KeyManagementAlgorithm[];
  /** A list of allowed JWE "enc" (Encryption Algorithm) Header Parameter values for content encryption. */
  encryptionAlgorithms?: ContentEncryptionAlgorithm[];
  /**
   * Critical Header Parameters to be understood and processed.
   * If the JWE contains critical headers not in this list (and not inherently understood by the library), decryption will fail.
   */
  critical?: string[];

  /** Algorithm to import the unwrapped CEK as (e.g., { name: 'AES-GCM' }). Defaults based on 'enc'. */
  unwrappedKeyAlgorithm?: Parameters<typeof crypto.subtle.importKey>[2];
  /** Key usages for the unwrapped CEK. Defaults based on 'enc' (typically ['encrypt', 'decrypt']). */
  keyUsage?: KeyUsage[];
  /** Mark the unwrapped CEK as extractable. Defaults to true. */
  extractable?: boolean;
}

/**
 * Result of a JWE decryption operation.
 */
export interface JWEDecryptResult<T = JWTClaims | string> {
  /** The decrypted payload. */
  payload: T;
  /** The JWE Protected Header. */
  protectedHeader: JWEHeaderParameters;
  /** The Content Encryption Key (CEK) used for decryption, as Uint8Array. */
  cek: Uint8Array;
  /** The Additional Authenticated Data (AAD) used, as Uint8Array. */
  aad: Uint8Array;
}
