// --- JWK Function Specific Types ---

/**
 * The decoded JOSE protected header received by a {@link JWKLookupFunction}.
 *
 * The most commonly inspected fields are explicitly typed; additional
 * algorithm-specific parameters (`epk`, `p2s`, `p2c`, `apu`, `apv`, …) are
 * accessible through the index signature.
 *
 * `alg` is always present on both JWS and JWE tokens. `enc` is only present
 * on JWE tokens.
 */
export type JWKLookupFunctionHeader = {
  kid?: string;
  alg?: string;
  enc?: string;
  typ?: string;
  crit?: string[];
  [propName: string]: unknown;
};

/**
 * A callback that resolves the decryption or verification key from a token's
 * decoded protected header and the raw compact token string.
 *
 * Accepted by both {@link verify} (JWS) and {@link decrypt} (JWE). When a
 * {@link JWKSet} is returned, the library tries each key whose `kid` and `alg`
 * are compatible with the header in order, stopping at the first that succeeds
 * — see {@link getJWKsFromSet} for the selection logic.
 *
 * Returning a `string` is meaningful for JWE only (PBES2 password); for JWS
 * a string return is encoded to bytes and used as a raw symmetric key.
 */
export type JWKLookupFunction = (
  header: JWKLookupFunctionHeader,
  token: string,
) =>
  | CryptoKey
  | JWK
  | JWKSet
  | string
  | Uint8Array<ArrayBuffer>
  | Promise<CryptoKey | JWK | JWKSet | string | Uint8Array<ArrayBuffer>>;

/**
 * Interface for custom JWK import cache implementations.
 *
 * The adapter receives the full JWK object so each implementation can choose
 * its own keying strategy:
 * - {@link WeakMapJWKCache} uses the object reference (GC-friendly, no string hashing needed)
 * - A `kid`-keyed cache extracts `jwk.kid` and uses it as a string key
 * - A content-hash cache hashes `jwk.k` or `jwk.n`+`jwk.e`
 *
 * @example Use a custom kid-keyed cache:
 * ```ts
 * import { configureJWKCache } from 'unjwt/jwk';
 * const map = new Map<string, CryptoKey>();
 * configureJWKCache({
 *   get: (jwk, alg) => map.get(`${jwk.kid}:${alg}`),
 *   set: (jwk, alg, key) => map.set(`${jwk.kid}:${alg}`, key),
 * });
 * ```
 */
export interface JWKCacheAdapter {
  get(jwk: JWK, alg: string): CryptoKey | undefined;
  set(jwk: JWK, alg: string, key: CryptoKey): void;
}

/** Structure returned for composite AES-CBC + HMAC keys. */
export type CompositeKey = {
  /** The AES-CBC encryption/decryption key. */
  encryptionKey: CryptoKey;
  /** The HMAC key for integrity/authentication. */
  macKey: CryptoKey;
};

export type GenerateKeyAlgorithm = Exclude<JWKAlgorithm, "none" | "dir" | JWK_PBES2>;

/** Options for the generateKey function. */
export interface GenerateKeyOptions {
  /** Key usages for the generated key(s). Note: For composite keys (CBC), default usages are applied separately. */
  keyUsage?: KeyUsage[];
  /** Mark the key(s) as extractable. Defaults to true. */
  extractable?: boolean;
  /** RSA modulus length. Defaults to 2048. */
  modulusLength?: number;
  /** RSA public exponent. Defaults to 65537 (0x010001). */
  publicExponent?: Uint8Array<ArrayBuffer>;
  /** Named curve for EC or OKP keys. Defaults to "P-256" for EC and "Ed25519" for OKP. */
  namedCurve?: "P-256" | "P-384" | "P-521" | "X25519" | "Ed25519" | "Ed448";
  /**
   * Export the generated key(s) as JWK. When `true`, keys are returned in JWK
   * format with a generated `kid`. To include additional JWK parameters
   * (e.g. a custom `kid`), use {@link generateJWK} instead.
   */
  toJWK?: boolean;
}

// Conditional return type when toJWK is true.
// `JWK_ECDH_ES` can resolve to either EC (P-256/P-384/P-521) or OKP (X25519/X448) depending on
// the runtime `namedCurve`, so its branch returns the union of both shapes.
type GenerateKeyReturnJWK<TAlg extends GenerateKeyAlgorithm> = TAlg extends JWK_Asymmetric_Algorithm
  ? TAlg extends JWK_RSA_SIGN | JWK_RSA_PSS | JWK_RSA_ENC
    ? { privateKey: JWK_RSA_Private; publicKey: JWK_RSA_Public }
    : TAlg extends JWK_ECDSA
      ? { privateKey: JWK_EC_Private; publicKey: JWK_EC_Public }
      : TAlg extends JWK_ECDH_ES
        ?
            | { privateKey: JWK_EC_Private; publicKey: JWK_EC_Public }
            | { privateKey: JWK_OKP_Private; publicKey: JWK_OKP_Public }
        : TAlg extends JWK_OKP_SIGN
          ? { privateKey: JWK_OKP_Private; publicKey: JWK_OKP_Public }
          : never
  : TAlg extends JWK_AES_CBC_HMAC | JWK_Symmetric_Algorithm
    ? JWK_oct // Composite AES-CBC+HMAC material is stored as one JWK_oct and split internally during enc/dec.
    : never;

// Conditional return type when toJWK is false or undefined.
// AES-CBC+HMAC returns raw bytes because the composite layout isn't directly importable via WebCrypto.
type GenerateKeyReturnCrypto<TAlg extends GenerateKeyAlgorithm> = TAlg extends JWK_AES_CBC_HMAC
  ? Uint8Array<ArrayBuffer>
  : TAlg extends JWK_Asymmetric_Algorithm
    ? CryptoKeyPair
    : CryptoKey;

export type GenerateKeyReturn<
  TAlg extends GenerateKeyAlgorithm,
  TOptions extends GenerateKeyOptions,
> = TOptions["toJWK"] extends true ? GenerateKeyReturnJWK<TAlg> : GenerateKeyReturnCrypto<TAlg>;

export type GenerateJWKOptions = Omit<GenerateKeyOptions, "toJWK">;

export type GenerateJWKReturn<TAlg extends GenerateKeyAlgorithm> = GenerateKeyReturnJWK<TAlg>;

/** Options for the deriveKeyFromPassword function. */
export interface DeriveKeyOptions {
  /** Salt value (p2s). Must be at least 8 bytes. */
  salt: Uint8Array<ArrayBuffer>;
  /** Iteration count (p2c). Must be a positive integer. */
  iterations: number;
  /** Key usages for the derived key. Defaults to ["wrapKey", "unwrapKey"]. */
  keyUsage?: KeyUsage[];
  /** Mark the derived key as extractable. Defaults to false. */
  extractable?: boolean;
  /**
   * Export the derived key as JWK_oct. When `true`, returns the derived key in
   * JWK format. To include additional JWK parameters (e.g. a custom `kid`),
   * use {@link deriveJWKFromPassword} instead.
   */
  toJWK?: boolean;
}

// Conditional return type for deriveKeyFromPassword
export type DeriveKeyReturn<TOptions extends DeriveKeyOptions> = TOptions["toJWK"] extends true
  ? JWK_oct
  : TOptions["toJWK"] extends object
    ? JWK_oct
    : CryptoKey;

export type KeyManagementAlgorithm =
  | JWK_RSA_ENC
  | JWK_AES_KW
  | JWK_AES_GCM
  | JWK_AES_GCM_KW
  | JWK_PBES2
  | JWK_ECDH_ES
  | "dir";

export type ContentEncryptionAlgorithm = JWK_AES_GCM | JWK_AES_CBC_HMAC;

/** Options for the wrapKey function. */
export interface WrapKeyOptions {
  /** Initialization Vector for AES-GCMKW. Generated if not provided. */
  iv?: Uint8Array<ArrayBuffer>;
  /** PBES2 Salt value (p2s). Required for PBES2 algorithms. */
  p2s?: Uint8Array<ArrayBuffer>;
  /** PBES2 Iteration count (p2c). Required for PBES2 algorithms. */
  p2c?: number;
  /** ECDH-ES specific options. */
  ecdh?: {
    /**
     * ECDH-ES ephemeral key material. A fresh ephemeral key pair is generated
     * automatically when this is not provided.
     */
    ephemeralKey?:
      | CryptoKey
      | JWK_EC_Private
      | CryptoKeyPair
      | { publicKey: CryptoKey | JWK_EC_Public; privateKey: CryptoKey | JWK_EC_Private };
    /** Agreement PartyUInfo (apu). */
    partyUInfo?: Uint8Array<ArrayBuffer>;
    /** Agreement PartyVInfo (apv). */
    partyVInfo?: Uint8Array<ArrayBuffer>;
    /**
     * Content encryption algorithm used for key-length derivation.
     * Required only when `alg` is `"ECDH-ES"` (direct key agreement).
     * Not needed for `ECDH-ES+A128KW`, `+A192KW`, or `+A256KW`.
     */
    enc?: ContentEncryptionAlgorithm;
  };
}

/** Result of the wrapKey function. */
export interface WrapKeyResult {
  /** The wrapped key (Ciphertext). */
  encryptedKey: Uint8Array<ArrayBuffer>;
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
  /**
   * Output format of the unwrapped key.
   * - `"cryptokey"` (default) — returns a `CryptoKey` ready for use with WebCrypto.
   * - `"raw"` — returns the raw key bytes as `Uint8Array` (useful for
   *   interoperability or when the algorithm is not directly importable).
   */
  format?: "cryptokey" | "raw";
  /** Initialization Vector (required for AES-GCMKW). Base64URL encoded or Uint8Array. */
  iv?: Uint8Array<ArrayBuffer> | string;
  /** Authentication Tag (required for AES-GCMKW). Base64URL encoded or Uint8Array. */
  tag?: Uint8Array<ArrayBuffer> | string;
  /** PBES2 Salt value (required for PBES2). Base64URL encoded or Uint8Array. */
  p2s?: Uint8Array<ArrayBuffer> | string;
  /** PBES2 Iteration count (required for PBES2). */
  p2c?: number;
  /** Minimum accepted PBES2 `p2c` on unwrap. Defaults to 1000 (RFC 7518 §4.8.1.2). */
  minIterations?: number;
  /** Maximum accepted PBES2 `p2c` on unwrap. Defaults to 1_000_000 to cap PBKDF2 DoS potential. */
  maxIterations?: number;
  /** ECDH-ES Ephemeral Public Key (required for ECDH-ES). */
  epk?: JWK_EC_Public | CryptoKey;
  /** ECDH-ES Agreement PartyUInfo. Base64URL encoded or Uint8Array. */
  apu?: Uint8Array<ArrayBuffer> | string;
  /** ECDH-ES Agreement PartyVInfo. Base64URL encoded or Uint8Array. */
  apv?: Uint8Array<ArrayBuffer> | string;
  /** Content Encryption Algorithm used with ECDH-ES (required for direct key agreement). */
  enc?: ContentEncryptionAlgorithm;
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
  /**
   * Non-standard JWK content encryption algorithm hint.
   * When `alg` is `"dir"`, the library reads this field to infer the
   * content encryption algorithm (`enc`) when it is not provided in options.
   */
  enc?: ContentEncryptionAlgorithm;
}

/** Public EC JSON Web Keys */
export interface JWK_EC_Public extends JWKParameters {
  /** EC JWK "kty" (Key Type) Parameter */
  kty: "EC";
  /** EC JWK "crv" (Curve) Parameter */
  crv: string;
  /** EC JWK "x" (X Coordinate) Parameter */
  x: string;
  /** EC JWK "y" (Y Coordinate) Parameter */
  y: string;
}

/** Private EC JSON Web Keys */
export interface JWK_EC_Private extends JWK_EC_Public {
  /** EC JWK "d" (ECC Private Key) Parameter */
  d: string;
}

/** EC JSON Web Keys */
export type JWK_EC = JWK_EC_Public | JWK_EC_Private;

/** Public RSA JSON Web Keys */
export interface JWK_RSA_Public extends JWKParameters {
  /** RSA JWK "kty" (Key Type) Parameter */
  kty: "RSA";
  /** RSA JWK "e" (Exponent) Parameter */
  e: string;
  /** RSA JWK "n" (Modulus) Parameter */
  n: string;
  oth?: RsaOtherPrimesInfo[];
}

/** Private RSA JSON Web Keys */
export interface JWK_RSA_Private extends JWK_RSA_Public {
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

/** Public ED JSON Web Keys */
export interface JWK_OKP_Public extends JWKParameters {
  /** ED JWK "kty" (Key Type) Parameter */
  kty: "OKP";
  /** ED JWK "crv" (Curve) Parameter */
  crv: string;
  /** ED JWK "x" (X Coordinate) Parameter */
  x: string;
}

/** Private ED JSON Web Keys */
export interface JWK_OKP_Private extends JWK_OKP_Public {
  /** ED JWK "d" (Private Key) Parameter */
  d: string;
}

/** OKP JSON Web Keys */
export type JWK_OKP = JWK_OKP_Public | JWK_OKP_Private;

/** oct JSON Web Keys */
export interface JWK_oct extends JWKParameters {
  /** Oct JWK "k" (Key Value) Parameter */
  k: string;
}

/** Symmetric JSON Web Keys */
export type JWK_Symmetric = JWK_oct;

/** Asymmetric JSON Web Keys */
export type JWK_Asymmetric = JWK_RSA | JWK_EC | JWK_OKP;

/** Public JSON Web Keys */
export type JWK_Public = JWK_RSA_Public | JWK_EC_Public | JWK_OKP_Public;

/** Private JSON Web Keys */
export type JWK_Private = JWK_RSA_Private | JWK_EC_Private | JWK_OKP_Private;

/**
 * JSON Web Key ({@link https://www.rfc-editor.org/rfc/rfc7517 JWK}). "RSA", "EC", "OKP" and "oct" key types are supported.
 */
export type JWK = JWK_oct | JWK_RSA | JWK_EC | JWK_OKP;

/**
 * A pair of public and private JSON Web Keys.
 */
export type JWK_Pair =
  | {
      publicKey: JWK_RSA_Public;
      privateKey: JWK_RSA_Private;
    }
  | {
      publicKey: JWK_EC_Public;
      privateKey: JWK_EC_Private;
    }
  | {
      publicKey: JWK_OKP_Public;
      privateKey: JWK_OKP_Private;
    };

/**
 * JSON Web Key Set ({@link https://www.rfc-editor.org/rfc/rfc7517 JWK Set}). "RSA", "EC" and "oct" key types are supported.
 */
export interface JWKSet {
  /** JWK Set "keys" Parameter */
  keys: JWK[];

  [parameter: string]: unknown;
}

/** JWK Key Algorithms */

export type JWK_HMAC = "HS256" | "HS384" | "HS512";
export type JWK_RSA_SIGN = "RS256" | "RS384" | "RS512";
export type JWK_RSA_PSS = "PS256" | "PS384" | "PS512";
export type JWK_ECDSA = "ES256" | "ES384" | "ES512";
export type JWK_RSA_ENC = "RSA-OAEP" | "RSA-OAEP-256" | "RSA-OAEP-384" | "RSA-OAEP-512";
export type JWK_AES_KW = "A128KW" | "A192KW" | "A256KW";
export type JWK_AES_CBC_HMAC = "A128CBC-HS256" | "A192CBC-HS384" | "A256CBC-HS512";
export type JWK_AES_GCM = "A128GCM" | "A192GCM" | "A256GCM";
export type JWK_AES_GCM_KW = "A128GCMKW" | "A192GCMKW" | "A256GCMKW";
export type JWK_PBES2 = "PBES2-HS256+A128KW" | "PBES2-HS384+A192KW" | "PBES2-HS512+A256KW";
export type JWK_ECDH_ES = "ECDH-ES" | "ECDH-ES+A128KW" | "ECDH-ES+A192KW" | "ECDH-ES+A256KW";
export type JWK_OKP_SIGN = "Ed25519" | "EdDSA";

export type JWK_Symmetric_Algorithm = JWK_HMAC | JWK_AES_KW | JWK_AES_GCM | JWK_AES_GCM_KW;
export type JWK_Asymmetric_Algorithm =
  | JWK_RSA_SIGN
  | JWK_RSA_PSS
  | JWK_ECDSA
  | JWK_RSA_ENC
  | JWK_OKP_SIGN
  | JWK_ECDH_ES;

export type JWKAlgorithm =
  | JWK_Symmetric_Algorithm
  | JWK_Asymmetric_Algorithm
  | JWK_AES_CBC_HMAC
  | JWK_PBES2
  | JWK_ECDH_ES
  | "dir"; // Direct encryption (no key wrapping)

export type JWKPEMAlgorithm =
  | JWK_RSA_PSS
  | JWK_RSA_SIGN
  | JWK_RSA_ENC
  | JWK_ECDSA
  | JWK_ECDH_ES
  | JWK_OKP_SIGN;
