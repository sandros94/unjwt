import type {
  JoseHeaderParameters,
  JWTClaims,
  JWTClaimValidationOptions,
} from "./jwt";
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
  apu?: Uint8Array<ArrayBuffer>;
  apv?: Uint8Array<ArrayBuffer>;
  /**
   * For Internal use only
   */
  p2c?: number;
  /**
   * For Internal use only
   */
  p2s?: Uint8Array<ArrayBuffer>;
  /**
   * For Internal use only
   */
  iv?: Uint8Array<ArrayBuffer>;
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
  /** Date to use when computing NumericDate claims, defaults to `new Date()`. */
  currentDate?: Date;
  /** Time at which the JWT should expire, if no `exp` was already provided (only when typ is JWT). */
  expiresIn?: number;

  /** Additional JWE Protected Header parameters. */
  protectedHeader?: Omit<
    JWEHeaderParameters,
    "alg" | "enc" | "iv" | "tag" | "p2s" | "p2c" | "apu" | "apv"
  >;

  // Key Wrapping specific options (passed to jwk.wrapKey)
  /** Initialization Vector for AES-GCMKW key wrapping. Generated if not provided. */
  keyManagementIV?: Uint8Array<ArrayBuffer>;
  /** PBES2 Salt value (p2s). Required for PBES2 algorithms. */
  p2s?: Uint8Array<ArrayBuffer>;
  /** PBES2 Iteration count (p2c). Required for PBES2 algorithms. */
  p2c?: number;
  /** ECDH-ES Agreement PartyUInfo. */
  ecdhPartyUInfo?: Uint8Array<ArrayBuffer>;
  /** ECDH-ES Agreement PartyVInfo. */
  ecdhPartyVInfo?: Uint8Array<ArrayBuffer>;

  /**
   * Content Encryption Key (CEK) to use.
   * If provided, it will be used directly. Otherwise, a CEK will be generated.
   */
  cek?: Uint8Array<ArrayBuffer>;

  /**
   * Initialization Vector for content encryption.
   * If provided, it will be used. Otherwise, one will be generated.
   */
  contentEncryptionIV?: Uint8Array<ArrayBuffer>;
}

/**
 * Key lookup function for JWE decryption.
 * @param header The JWE Protected Header.
 * @returns The key material (CryptoKey, JWK, password string, or raw Uint8Array) or a Promise resolving to it.
 */
export type JWEKeyLookupFunction = (
  header: JWEHeaderParameters,
  token: string,
) =>
  | CryptoKey
  | JWK
  | string
  | Uint8Array<ArrayBuffer>
  | Promise<CryptoKey | JWK | string | Uint8Array<ArrayBuffer>>;

/**
 * JWE (JSON Web Encryption) decryption options
 */
export interface JWEDecryptOptions extends JWTClaimValidationOptions {
  /** A list of allowed JWE "alg" (Algorithm) Header Parameter values for key management. */
  algorithms?: KeyManagementAlgorithm[];
  /** A list of allowed JWE "enc" (Encryption Algorithm) Header Parameter values for content encryption. */
  encryptionAlgorithms?: ContentEncryptionAlgorithm[];
  /** Algorithm to import the unwrapped CEK as (e.g., { name: 'AES-GCM' }). Defaults based on 'enc'. */
  unwrappedKeyAlgorithm?: Parameters<typeof crypto.subtle.importKey>[2];

  /** Key usages for the unwrapped CEK. Defaults based on 'enc' (typically ['encrypt', 'decrypt']). */
  keyUsage?: KeyUsage[];
  /** Mark the unwrapped CEK as extractable. Defaults to true. */
  extractable?: boolean;
  /** If true, forces the payload to be returned as a Uint8Array, otherwise type is inferred based on JWE headers. */
  forceUint8Array?: boolean;
}

/**
 * Result of a JWE decryption operation.
 */
export interface JWEDecryptResult<
  T extends JWTClaims | Uint8Array<ArrayBuffer> | string =
    | JWTClaims
    | Uint8Array<ArrayBuffer>
    | string,
> {
  /** The decrypted payload. */
  payload: T;
  /** The JWE Protected Header. */
  protectedHeader: JWEHeaderParameters;
  /** The Content Encryption Key (CEK) used for decryption, as Uint8Array. */
  cek: Uint8Array<ArrayBuffer>;
  /** The Additional Authenticated Data (AAD) used, as Uint8Array. */
  aad: Uint8Array<ArrayBuffer>;
}
