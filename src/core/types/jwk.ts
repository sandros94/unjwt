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
 *
 * The optional `TReturn` generic lets callers who always hand back a specific
 * key shape (e.g. a `JWK_EC_Public<"ES256">`) preserve that narrowing all the
 * way into the `verify` / `decrypt` key resolution path.
 */
export type JWKLookupFunction<
  TReturn = CryptoKey | JWK | JWKSet | string | Uint8Array<ArrayBuffer>,
> = (header: JWKLookupFunctionHeader, token: string) => TReturn | Promise<TReturn>;

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

type GenerateKeyReturnJWK<TAlg extends GenerateKeyAlgorithm> = TAlg extends JWK_Asymmetric_Algorithm
  ? JWK_Pair<TAlg>
  : TAlg extends JWK_AES_CBC_HMAC | JWK_Symmetric_Algorithm
    ? JWK_oct<TAlg>
    : never;

// AES-CBC+HMAC returns raw bytes — the composite layout isn't directly importable via Web Crypto.
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

/** PBES2 → AES-KW alg that ends up stamped on the derived JWK's `alg`. */
type DerivedJWKAlg<TAlg extends JWK_PBES2> = TAlg extends "PBES2-HS256+A128KW"
  ? "A128KW"
  : TAlg extends "PBES2-HS384+A192KW"
    ? "A192KW"
    : TAlg extends "PBES2-HS512+A256KW"
      ? "A256KW"
      : JWK_AES_KW;

export type DeriveKeyReturn<
  TOptions extends DeriveKeyOptions,
  TAlg extends JWK_PBES2 = JWK_PBES2,
> = TOptions["toJWK"] extends true
  ? JWK_oct<DerivedJWKAlg<TAlg>>
  : TOptions["toJWK"] extends object
    ? JWK_oct<DerivedJWKAlg<TAlg>>
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

/**
 * Keys admissible as the `wrappingKey` argument of {@link wrapKey}, narrowed
 * by the key management algorithm. Mirrors the runtime branches in
 * `jwk.wrapKey` and the inference in `inferJWEAllowedAlgorithms`.
 *
 * - `dir` accepts any symmetric JWK (the key _is_ the CEK).
 * - AES-GCMKW tolerates a JWK whose `alg` is the bare `A*GCM` counterpart —
 *   matches the `jweAlgsFromOctJWK` aliasing rule.
 */
export type WrappingKeyFor<A extends KeyManagementAlgorithm> = A extends JWK_RSA_ENC
  ? CryptoKey | JWK_RSA_Public<A>
  : A extends JWK_ECDH_ES
    ? CryptoKey | JWK_EC_Public<A> | JWK_OKP_Public<A>
    : A extends JWK_PBES2
      ? string | Uint8Array<ArrayBuffer> | JWK_oct<A>
      : A extends JWK_AES_KW
        ? CryptoKey | JWK_oct<A>
        : A extends JWK_AES_GCM_KW
          ? CryptoKey | JWK_oct<A | `A${"128" | "192" | "256"}GCM`>
          : A extends "dir"
            ? CryptoKey | JWK_oct | Uint8Array<ArrayBuffer>
            : never;

/**
 * Keys admissible as the `unwrappingKey` argument of {@link unwrapKey}.
 * The private-side counterpart of {@link WrappingKeyFor} — symmetric branches
 * are identical; asymmetric branches use the `_Private` variants.
 */
export type UnwrappingKeyFor<A extends KeyManagementAlgorithm> = A extends JWK_RSA_ENC
  ? CryptoKey | JWK_RSA_Private<A>
  : A extends JWK_ECDH_ES
    ? CryptoKey | JWK_EC_Private<A> | JWK_OKP_Private<A>
    : A extends JWK_PBES2
      ? string | Uint8Array<ArrayBuffer> | JWK_oct<A>
      : A extends JWK_AES_KW
        ? CryptoKey | JWK_oct<A>
        : A extends JWK_AES_GCM_KW
          ? CryptoKey | JWK_oct<A | `A${"128" | "192" | "256"}GCM`>
          : A extends "dir"
            ? CryptoKey | JWK_oct | Uint8Array<ArrayBuffer>
            : never;

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

/**
 * Result of {@link wrapKey}, discriminated by key management algorithm family.
 *
 * Narrow the shape by passing a literal `alg` to `wrapKey`:
 * - PBES2 → `{ encryptedKey, p2s, p2c }`
 * - AES-GCMKW → `{ encryptedKey, iv, tag }`
 * - ECDH-ES / ECDH-ES+A*KW → `{ encryptedKey, epk, apu?, apv? }`
 * - dir / AES-KW / RSA-OAEP → `{ encryptedKey }`
 */
export type WrapKeyResult<TAlg extends KeyManagementAlgorithm = KeyManagementAlgorithm> =
  TAlg extends JWK_PBES2
    ? {
        encryptedKey: Uint8Array<ArrayBuffer>;
        /** PBES2 Salt value (p2s). Base64URL encoded. */
        p2s: string;
        /** PBES2 Iteration count (p2c). */
        p2c: number;
      }
    : TAlg extends JWK_AES_GCM_KW
      ? {
          encryptedKey: Uint8Array<ArrayBuffer>;
          /** AES-GCMKW Initialization Vector. Base64URL encoded. */
          iv: string;
          /** AES-GCMKW Authentication Tag. Base64URL encoded. */
          tag: string;
        }
      : TAlg extends JWK_ECDH_ES
        ? {
            encryptedKey: Uint8Array<ArrayBuffer>;
            /** Ephemeral Public Key. */
            epk: JWK_EC_Public;
            /** Agreement PartyUInfo. Base64URL encoded. Present only when supplied. */
            apu?: string;
            /** Agreement PartyVInfo. Base64URL encoded. Present only when supplied. */
            apv?: string;
          }
        : { encryptedKey: Uint8Array<ArrayBuffer> };

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

/**
 * Forked from https://github.com/panva/jose/tree/v6.0.10
 * Copyright (c) 2018 Filip Skokan.
 * LICENSE: https://github.com/panva/jose/blob/v6.0.10/LICENSE.md
 */

/**
 * Generic JSON Web Key Parameters.
 *
 * The `Alg` type parameter constrains the JWK's `alg` field. Each concrete JWK
 * interface below tightens `Alg` to the algorithm family admissible for that key
 * type — e.g. a `JWK_oct<JWK_HMAC>` can only hold `"HS256" | "HS384" | "HS512"`
 * in `alg`.
 */
export interface JWKParameters<Alg extends string = string> {
  /** JWK "kty" (Key Type) Parameter */
  kty: string;
  /**
   * JWK "alg" (Algorithm) Parameter
   *
   * @see {@link https://github.com/panva/jose/issues/210 Algorithm Key Requirements}
   */
  alg?: Alg;
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
export interface JWK_EC_Public<
  Alg extends JWK_ECDSA | JWK_ECDH_ES | (string & {}) = string,
> extends JWKParameters<Alg> {
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
export interface JWK_EC_Private<
  Alg extends JWK_ECDSA | JWK_ECDH_ES | (string & {}) = string,
> extends JWK_EC_Public<Alg> {
  /** EC JWK "d" (ECC Private Key) Parameter */
  d: string;
}

/** EC JSON Web Keys */
export type JWK_EC<Alg extends JWK_ECDSA | JWK_ECDH_ES | (string & {}) = string> =
  | JWK_EC_Public<Alg>
  | JWK_EC_Private<Alg>;

/** Public RSA JSON Web Keys */
export interface JWK_RSA_Public<
  Alg extends JWK_RSA_SIGN | JWK_RSA_PSS | JWK_RSA_ENC | (string & {}) = string,
> extends JWKParameters<Alg> {
  /** RSA JWK "kty" (Key Type) Parameter */
  kty: "RSA";
  /** RSA JWK "e" (Exponent) Parameter */
  e: string;
  /** RSA JWK "n" (Modulus) Parameter */
  n: string;
  oth?: RsaOtherPrimesInfo[];
}

/** Private RSA JSON Web Keys */
export interface JWK_RSA_Private<
  Alg extends JWK_RSA_SIGN | JWK_RSA_PSS | JWK_RSA_ENC | (string & {}) = string,
> extends JWK_RSA_Public<Alg> {
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
export type JWK_RSA<Alg extends JWK_RSA_SIGN | JWK_RSA_PSS | JWK_RSA_ENC | (string & {}) = string> =
  JWK_RSA_Public<Alg> | JWK_RSA_Private<Alg>;

/** Public ED JSON Web Keys */
export interface JWK_OKP_Public<
  Alg extends JWK_OKP_SIGN | JWK_ECDH_ES | (string & {}) = string,
> extends JWKParameters<Alg> {
  /** ED JWK "kty" (Key Type) Parameter */
  kty: "OKP";
  /** ED JWK "crv" (Curve) Parameter */
  crv: string;
  /** ED JWK "x" (X Coordinate) Parameter */
  x: string;
}

/** Private ED JSON Web Keys */
export interface JWK_OKP_Private<
  Alg extends JWK_OKP_SIGN | JWK_ECDH_ES | (string & {}) = string,
> extends JWK_OKP_Public<Alg> {
  /** ED JWK "d" (Private Key) Parameter */
  d: string;
}

/** OKP JSON Web Keys */
export type JWK_OKP<Alg extends JWK_OKP_SIGN | JWK_ECDH_ES | (string & {}) = string> =
  | JWK_OKP_Public<Alg>
  | JWK_OKP_Private<Alg>;

/** oct JSON Web Keys */
export interface JWK_oct<
  Alg extends
    | JWK_HMAC
    | JWK_AES_KW
    | JWK_AES_GCM
    | JWK_AES_GCM_KW
    | JWK_AES_CBC_HMAC
    | JWK_PBES2
    | "dir"
    | (string & {}) = string,
> extends JWKParameters<Alg> {
  /** Oct JWK "k" (Key Value) Parameter */
  k: string;
}

/** Symmetric JSON Web Keys */
export type JWK_Symmetric<
  Alg extends
    | JWK_HMAC
    | JWK_AES_KW
    | JWK_AES_GCM
    | JWK_AES_GCM_KW
    | JWK_AES_CBC_HMAC
    | JWK_PBES2
    | "dir"
    | (string & {}) = string,
> = JWK_oct<Alg>;

/** Asymmetric JSON Web Keys */
export type JWK_Asymmetric<Alg extends string = string> = JWK_RSA<Alg> | JWK_EC<Alg> | JWK_OKP<Alg>;

/** Public JSON Web Keys */
export type JWK_Public<Alg extends string = string> =
  | JWK_RSA_Public<Alg>
  | JWK_EC_Public<Alg>
  | JWK_OKP_Public<Alg>;

/** Private JSON Web Keys */
export type JWK_Private<Alg extends string = string> =
  | JWK_RSA_Private<Alg>
  | JWK_EC_Private<Alg>
  | JWK_OKP_Private<Alg>;

/**
 * JSON Web Key ({@link https://www.rfc-editor.org/rfc/rfc7517 JWK}). "RSA", "EC", "OKP" and "oct" key types are supported.
 */
export type JWK<Alg extends string = string> =
  | JWK_oct<Alg>
  | JWK_RSA<Alg>
  | JWK_EC<Alg>
  | JWK_OKP<Alg>;

/**
 * A pair of public and private JSON Web Keys, narrowed by `Alg` when that
 * uniquely identifies the key family:
 *
 * - `JWK_Pair<"RS256">` → RSA pair only
 * - `JWK_Pair<"ES256">` → EC pair only
 * - `JWK_Pair<"ECDH-ES+A256KW">` → EC pair **or** OKP pair (curve decides at runtime)
 * - `JWK_Pair<"Ed25519">` / `JWK_Pair<"EdDSA">` → OKP pair only
 *
 * The final branch is a generic fallback (`Alg = string`, or any custom /
 * forward-compat algorithm that doesn't match a known family) — it yields
 * the permissive three-branch union.
 */
export type JWK_Pair<Alg extends string = string> = Alg extends
  | JWK_RSA_SIGN
  | JWK_RSA_PSS
  | JWK_RSA_ENC
  ? { publicKey: JWK_RSA_Public<Alg>; privateKey: JWK_RSA_Private<Alg> }
  : Alg extends JWK_ECDSA
    ? { publicKey: JWK_EC_Public<Alg>; privateKey: JWK_EC_Private<Alg> }
    : Alg extends JWK_ECDH_ES
      ?
          | { publicKey: JWK_EC_Public<Alg>; privateKey: JWK_EC_Private<Alg> }
          | { publicKey: JWK_OKP_Public<Alg>; privateKey: JWK_OKP_Private<Alg> }
      : Alg extends JWK_OKP_SIGN
        ? { publicKey: JWK_OKP_Public<Alg>; privateKey: JWK_OKP_Private<Alg> }
        :
            | { publicKey: JWK_RSA_Public<Alg>; privateKey: JWK_RSA_Private<Alg> }
            | { publicKey: JWK_EC_Public<Alg>; privateKey: JWK_EC_Private<Alg> }
            | { publicKey: JWK_OKP_Public<Alg>; privateKey: JWK_OKP_Private<Alg> };

/**
 * JSON Web Key Set ({@link https://www.rfc-editor.org/rfc/rfc7517 JWK Set}). "RSA", "EC" and "oct" key types are supported.
 *
 * The optional `T` generic preserves the precise key tuple when constructed
 * in TS — e.g. `JWKSet<[JWK_oct<"HS256">, JWK_EC_Public<"ES256">]>` — while the
 * default `JWK[]` keeps the permissive behavior expected for JWKS fetched from
 * external sources (runtime trials each candidate).
 */
export interface JWKSet<T extends readonly JWK[] = JWK[]> {
  /** JWK Set "keys" Parameter */
  keys: T;

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
