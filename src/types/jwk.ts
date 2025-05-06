// --- JWK Function Specific Types ---

/** Structure returned for composite AES-CBC + HMAC keys. */
export type CompositeKey = {
  /** The AES-CBC encryption/decryption key. */
  encryptionKey: CryptoKey;
  /** The HMAC key for integrity/authentication. */
  macKey: CryptoKey;
};

export type GenerateKeyAlgorithm = Exclude<
  JWKAlgorithm,
  "none" | "dir" | JWK_PBES2 | JWK_ECDH_ES
>;

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
  /** Export the generated key(s) as JWK. If true, the key(s) will be returned in JWK format. */
  toJWK?: boolean | undefined;
}

// Conditional return type when toJWK is true
type GenerateKeyReturnJWK<TAlg extends GenerateKeyAlgorithm> =
  TAlg extends JWK_Asymmetric_Algorithm
    ? { privateKey: JWK; publicKey: JWK }
    : JWK;

// Conditional return type when toJWK is false or undefined
type GenerateKeyReturnCrypto<TAlg extends GenerateKeyAlgorithm> =
  TAlg extends JWK_AES_CBC_HMAC
    ? Uint8Array
    : TAlg extends JWK_Asymmetric_Algorithm
      ? CryptoKeyPair
      : CryptoKey;

export type GenerateKeyReturn<
  TAlg extends GenerateKeyAlgorithm,
  TOptions extends GenerateKeyOptions,
> = TOptions["toJWK"] extends true
  ? GenerateKeyReturnJWK<TAlg>
  : GenerateKeyReturnCrypto<TAlg>;

/** Options for the deriveKeyFromPassword function. */
export interface DeriveKeyOptions {
  /** Salt value (p2s). Must be at least 8 bytes. */
  salt: Uint8Array;
  /** Iteration count (p2c). Must be a positive integer. */
  iterations: number;
  /** Key usages for the derived key. Defaults to ["wrapKey", "unwrapKey"]. */
  keyUsage?: KeyUsage[];
  /** Mark the derived key as extractable. Defaults to false. */
  extractable?: boolean;
  /** Export the derived key as JWK. If true, the key will be returned in JWK_oct format. */
  toJWK?: boolean | undefined;
}

// Conditional return type for deriveKeyFromPassword
export type DeriveKeyReturn<TOptions extends DeriveKeyOptions> =
  TOptions["toJWK"] extends true ? JWK_oct : CryptoKey;

export type KeyManagementAlgorithm =
  | JWK_RSA_ENC
  | JWK_AES_KW
  | JWK_AES_GCM
  | JWK_AES_GCM_KW
  | JWK_PBES2
  | JWK_ECDH_ES;
// TODO: | "dir";

export type ContentEncryptionAlgorithm =
  | JWK_AES_GCM
  | JWK_AES_CBC_HMAC

/** Options for the wrapKey function. */
export interface WrapKeyOptions {
  /** Initialization Vector for AES-GCMKW. Generated if not provided. */
  iv?: Uint8Array;
  /** PBES2 Salt value (p2s). Required for PBES2 algorithms. */
  p2s?: Uint8Array;
  /** PBES2 Iteration count (p2c). Required for PBES2 algorithms. */
  p2c?: number;
  /** ECDH-ES Ephemeral Public Key. Generated if not provided for ECDH-ES. */
  epk?: JWK_EC_Public; // Or CryptoKey? JWK is more common in JWE headers
  /** ECDH-ES Agreement PartyUInfo. */
  apu?: Uint8Array;
  /** ECDH-ES Agreement PartyVInfo. */
  apv?: Uint8Array;
}

/** Result of the wrapKey function. */
export interface WrapKeyResult {
  /** The wrapped key (Ciphertext). */
  encryptedKey: Uint8Array;
  /** Initialization Vector used (only for AES-GCMKW). Base64URL encoded. */
  iv?: string;
  /** Authentication Tag generated (only for AES-GCMKW). Base64URL encoded. */
  tag?: string;
  /** PBES2 Salt value used (only for PBES2). Base64URL encoded. */
  p2s?: string;
  /** PBES2 Iteration count used (only for PBES2). */
  p2c?: number;
  /** ECDH-ES Ephemeral Public Key used (only for ECDH-ES). */
  epk?: JWK_EC_Public;
  /** ECDH-ES Agreement PartyUInfo used (only for ECDH-ES). Base64URL encoded. */
  apu?: string;
  /** ECDH-ES Agreement PartyVInfo used (only for ECDH-ES). Base64URL encoded. */
  apv?: string;
}

/** Options for the unwrapKey function. */
export interface UnwrapKeyOptions {
  /** Initialization Vector (required for AES-GCMKW). Base64URL encoded or Uint8Array. */
  iv?: Uint8Array | string;
  /** Authentication Tag (required for AES-GCMKW). Base64URL encoded or Uint8Array. */
  tag?: Uint8Array | string;
  /** PBES2 Salt value (required for PBES2). Base64URL encoded or Uint8Array. */
  p2s?: Uint8Array | string;
  /** PBES2 Iteration count (required for PBES2). */
  p2c?: number;
  /** ECDH-ES Ephemeral Public Key (required for ECDH-ES). */
  epk?: JWK_EC_Public; // Or CryptoKey?
  /** ECDH-ES Agreement PartyUInfo. Base64URL encoded or Uint8Array. */
  apu?: Uint8Array | string;
  /** ECDH-ES Agreement PartyVInfo. Base64URL encoded or Uint8Array. */
  apv?: Uint8Array | string;
  /** Expected unwrapped key algorithm (e.g., 'AES-GCM', 'AES-CBC'). Used by crypto.subtle.unwrapKey. */
  unwrappedKeyAlgorithm?:
    | string
    | Algorithm
    | RsaOaepParams
    | AesCtrParams
    | AesCbcParams
    | AesGcmParams;
  /** Expected key usages for the unwrapped key. */
  keyUsage?: KeyUsage[];
  /** Mark the unwrapped key as extractable. Defaults to true. */
  extractable?: boolean;
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

/** Public EC JSON Web Keys */
export interface JWK_EC_Public extends JWKParameters {
  /** EC JWK "crv" (Curve) Parameter */
  crv: string;
  /** EC JWK "x" (X Coordinate) Parameter */
  x: string;
  /** EC JWK "y" (Y Coordinate) Parameter */
  y: string;
}

/** Private EC JSON Web Keys */
export interface JWK_EC_Private extends JWK_EC_Public, JWKParameters {
  /** EC JWK "d" (ECC Private Key) Parameter */
  d: string;
}

/** EC JSON Web Keys */
export type JWK_EC = JWK_EC_Public | JWK_EC_Private;

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
export type JWK = JWK_oct | JWK_RSA | JWK_EC;

/** JWK Key Algorithms */

export type JWK_HMAC = "HS256" | "HS384" | "HS512";
export type JWK_RSA_SIGN = "RS256" | "RS384" | "RS512";
export type JWK_RSA_PSS = "PS256" | "PS384" | "PS512";
export type JWK_ECDSA = "ES256" | "ES384" | "ES512";
export type JWK_RSA_ENC =
  | "RSA-OAEP"
  | "RSA-OAEP-256"
  | "RSA-OAEP-384"
  | "RSA-OAEP-512";
export type JWK_AES_KW = "A128KW" | "A192KW" | "A256KW";
export type JWK_AES_GCM_KW = "A128GCMKW" | "A192GCMKW" | "A256GCMKW";
export type JWK_AES_CBC_HMAC =
  | "A128CBC-HS256"
  | "A192CBC-HS384"
  | "A256CBC-HS512";
export type JWK_AES_GCM = "A128GCM" | "A192GCM" | "A256GCM";
export type JWK_PBES2 =
  | "PBES2-HS256+A128KW"
  | "PBES2-HS384+A192KW"
  | "PBES2-HS512+A256KW";
export type JWK_ECDH_ES =
  | "ECDH-ES"
  | "ECDH-ES+A128KW"
  | "ECDH-ES+A192KW"
  | "ECDH-ES+A256KW";

export type JWK_Symmetric_Algorithm = JWK_HMAC | JWK_AES_KW | JWK_AES_GCM;
export type JWK_Asymmetric_Algorithm =
  | JWK_RSA_SIGN
  | JWK_RSA_PSS
  | JWK_ECDSA
  | JWK_RSA_ENC;

export type JWKAlgorithm =
  | JWK_Symmetric_Algorithm
  | JWK_Asymmetric_Algorithm
  | JWK_AES_CBC_HMAC
  | JWK_PBES2
  | JWK_ECDH_ES
  | ("none" | "dir"); // No algorithm | Direct encryption
