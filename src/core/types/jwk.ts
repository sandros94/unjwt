import type { JWSAlgorithm } from "./jws.ts";

/** The decoded header a `JWKLookupFunction` receives. Its `alg` and `enc` are already checked as supported. `enc` is set on a JWE only. */
export type JWKLookupFunctionHeader = {
  kid?: string;
  alg?: JWSAlgorithm | KeyManagementAlgorithm;
  enc?: ContentEncryptionAlgorithm;
  typ?: string;
  crit?: string[];
  [propName: string]: unknown;
};

/**
 * Returns the key that verifies or decrypts a token, from `{ header, token }`: its decoded header and the token itself.
 * A string is a PBES2 password on a JWE. Any other use of a string throws `ERR_JWK_INVALID`.
 * `undefined` means no key for this token, reported as `ERR_JWK_KEY_NOT_FOUND`. A thrown `JWTError` propagates as it is,
 * and any other throw is `ERR_JWK_KEY_NOT_FOUND` with the thrown error as `cause`.
 */
export type JWKLookupFunction<
  TReturn = CryptoKey | JWK | JWKSet | string | Uint8Array<ArrayBuffer>,
  THeader = JWKLookupFunctionHeader,
> = (lookup: {
  header: THeader;
  token: string;
}) => TReturn | undefined | Promise<TReturn | undefined>;

/** A JWK import cache for `configureJWKCache`. Both methods can return a promise. Key the entries on the RFC 7638 thumbprint, the private or public half, and `alg`, never on `kid`. */
export interface JWKCacheAdapter {
  get(jwk: JWK, alg: JWKAlgorithm): CryptoKey | undefined | Promise<CryptoKey | undefined>;
  set(jwk: JWK, alg: JWKAlgorithm, key: CryptoKey): void | Promise<void>;
}

/** A composite AES-CBC with HMAC key, split into its two halves. */
export type CompositeKey = {
  encryptionKey: CryptoKey;
  macKey: CryptoKey;
};

export type GenerateKeyAlgorithm = Exclude<JWKAlgorithm, "none" | "dir" | JWK_PBES2>;

/** Options for `generateJWK`. `Kid` is the type of the `kid` option, which types the generated `kid`. */
export interface GenerateJWKOptions<Kid extends string | false = string | false> {
  /** Narrows the usages `alg` admits and is written as `key_ops`. Without it, the key has every usage `alg` admits and no `key_ops`. */
  keyUsage?: KeyUsage[];
  /** The RSA modulus length in bits, at least 2048. Default: `2048`. */
  modulusLength?: number;
  /** The RSA public exponent as big-endian bytes. Default: `65537`. */
  publicExponent?: Uint8Array<ArrayBuffer>;
  /** The curve for `ECDH-ES*` and `EdDSA`. `ES*` and `Ed25519` fix their own curve. Default: `"P-256"` for `ECDH-ES*`, `"Ed25519"` for `EdDSA`. */
  namedCurve?: "P-256" | "P-384" | "P-521" | "X25519" | "Ed25519";
  /** The `kid` to set as given, or `false` for none. Default: the key's RFC 7638 SHA-256 thumbprint. */
  kid?: Kid;
}

/** Options for `generateKey`. `ToJWK` is the literal of the `toJWK` option, which picks key objects or JWKs. */
export interface GenerateKeyOptions<
  ToJWK extends boolean = boolean,
  Kid extends string | false = string | false,
> extends GenerateJWKOptions<Kid> {
  /** Makes the generated keys extractable. Ignored with `toJWK`. Default: `true`. */
  extractable?: boolean;
  /** Returns JWKs instead of key objects. Default: `false`. */
  toJWK?: ToJWK;
  /** With `toJWK`, the `kid` to set as given, or `false` for none. Ignored without `toJWK`. Default: the key's RFC 7638 SHA-256 thumbprint. */
  kid?: Kid;
}

/** The `generateKey` result per algorithm without `toJWK`: a `CryptoKey` (symmetric), raw bytes (`A*CBC-HS*`), or a `CryptoKeyPair` (asymmetric). */
export type GeneratedKeyMap = {
  [A in GenerateKeyAlgorithm]: A extends JWK_AES_CBC_HMAC
    ? Uint8Array<ArrayBuffer>
    : A extends JWK_Asymmetric_Algorithm
      ? CryptoKeyPair
      : CryptoKey;
};

/** The `generateJWK` result per algorithm: an `oct` JWK or a JWK pair. Each JWK has `alg`, and `kid` unless `Kid` is `false`. */
export type GeneratedJWKMap<Kid extends string | false = string> = {
  [A in GenerateKeyAlgorithm]: A extends JWK_Asymmetric_Algorithm
    ? GeneratedJWKPair<JWK_Pair<A>, A, Kid>
    : JWK_oct<Exclude<A, JWK_Asymmetric_Algorithm>> & GeneratedJWKMembers<A, Kid>;
};

/** The `generateKey` return type for `TAlg` under `TOptions`. JWKs when `toJWK` is `true`. */
export type GenerateKeyReturn<
  TAlg extends GenerateKeyAlgorithm,
  TOptions extends GenerateKeyOptions,
> = GeneratedKeyShape<TAlg, Exclude<TOptions["toJWK"], undefined>, GeneratedKid<TOptions>>;

/** The `generateJWK` return type for `TAlg` under the `kid` option `Kid`. */
export type GenerateJWKReturn<
  TAlg extends GenerateKeyAlgorithm,
  Kid extends string | false = string,
> = GeneratedJWKMap<Kid>[TAlg];

/** What `importKey` returns per input: raw bytes for bytes and `oct` JWKs, the same `CryptoKey` for a `CryptoKey`, and a `CryptoKey` for an asymmetric JWK. */
export interface ImportedKeyMap {
  bytes: Uint8Array<ArrayBuffer>;
  oct: Uint8Array<ArrayBuffer>;
  cryptoKey: CryptoKey;
  asymmetric: CryptoKey;
}

/** The `ImportedKeyMap` entry for key input `K`. A union input gives a union. */
export type ImportedKey<K> = ImportedKeyMap[K extends Uint8Array
  ? "bytes"
  : K extends CryptoKey
    ? "cryptoKey"
    : K extends JWK_oct
      ? "oct"
      : "asymmetric"];

/** Options for `deriveKeyFromPassword`. */
export interface DeriveKeyOptions {
  alg: JWK_PBES2;
  /** The salt (`p2s`) as bytes or UTF-8 text, at least 8 octets (RFC 7518 §4.8.1.1). */
  salt: string | Uint8Array<ArrayBuffer>;
  /** The iteration count (`p2c`), an integer of at least 1000 (RFC 7518 §4.8.1.2). */
  iterations: number;
  /** The derived key's usages, written as `key_ops` with `toJWK`. Default: `["wrapKey", "unwrapKey"]`. */
  keyUsage?: KeyUsage[];
  /** Makes the derived key extractable. Ignored with `toJWK`. Default: `false`. */
  extractable?: boolean;
  /** Returns the derived key as a `JWK_oct` with the inner AES-KW `alg`. Default: `false`. */
  toJWK?: boolean;
}

/** The AES-KW algorithm a `PBES2-*` or `ECDH-ES+*` algorithm wraps the CEK with. */
export type KeyWrapAlgorithmOf<A extends KeyWrappingAlgorithm> = A extends `${string}A128KW`
  ? "A128KW"
  : A extends `${string}A192KW`
    ? "A192KW"
    : A extends `${string}A256KW`
      ? "A256KW"
      : never;

/** The key management algorithms that wrap the CEK with an inner AES-KW step. */
export type KeyWrappingAlgorithm = JWK_PBES2 | Exclude<JWK_ECDH_ES, "ECDH-ES">;

/** The AES-KW `alg` of the JWK derived for a PBES2 algorithm. */
type DerivedJWKAlg<TAlg extends JWK_PBES2> = KeyWrapAlgorithmOf<TAlg>;

export type DeriveKeyReturn<
  TOptions extends DeriveKeyOptions,
  TAlg extends JWK_PBES2 = JWK_PBES2,
> = TOptions["toJWK"] extends true
  ? JWK_oct<DerivedJWKAlg<TAlg>>
  : TOptions["toJWK"] extends object
    ? JWK_oct<DerivedJWKAlg<TAlg>>
    : CryptoKey;

/** Options for `deriveJWKFromPassword`: the `deriveKeyFromPassword` options without `toJWK` and `extractable`, plus `kid` (`false` for none). */
export type DeriveJWKOptions<
  TAlg extends JWK_PBES2 = JWK_PBES2,
  Kid extends string | false = string,
> = Omit<DeriveKeyOptions, "alg" | "toJWK" | "extractable"> & { alg: TAlg; kid?: Kid };

/** The `deriveJWKFromPassword` return type: the AES-KW `oct` JWK for `TAlg`, with `kid` unless `Kid` is `false`. */
export type DeriveJWKReturn<TAlg extends JWK_PBES2, Kid extends string | false = string> = JWK_oct<
  DerivedJWKAlg<TAlg>
> &
  GeneratedJWKMembers<DerivedJWKAlg<TAlg>, Kid>;

/** The PEM types `importPEM` reads. */
export type PEMType = "pkcs8" | "spki" | "x509";

/** The `importPEM` result for `Alg`: a private JWK for PKCS#8, a public JWK for SPKI or X.509, and either when the type is inferred. */
export type ImportedPEMJWK<
  Alg extends JWKPEMAlgorithm,
  Type extends PEMType | undefined = undefined,
> = Type extends "pkcs8"
  ? JWK_Pair<Alg>["privateKey"]
  : Type extends "spki" | "x509"
    ? JWK_Pair<Alg>["publicKey"]
    : JWK_Pair<Alg>["privateKey"] | JWK_Pair<Alg>["publicKey"];

export type KeyManagementAlgorithm =
  | JWK_RSA_ENC
  | JWK_AES_KW
  | JWK_AES_GCM
  | JWK_AES_GCM_KW
  | JWK_PBES2
  | JWK_ECDH_ES
  | "dir";

export type ContentEncryptionAlgorithm = JWK_AES_GCM | JWK_AES_CBC_HMAC;

/** The keys `wrapKey` accepts as `wrappingKey` for algorithm `A`. `dir` takes any symmetric key. */
export type WrappingKeyFor<A extends KeyManagementAlgorithm> = A extends JWK_RSA_ENC
  ? CryptoKey | JWK_RSA_Public<A>
  : A extends JWK_ECDH_ES
    ? CryptoKey | JWK_EC_Public<A> | JWK_OKP_Public<A>
    : A extends JWK_PBES2
      ? string | Uint8Array<ArrayBuffer> | JWK_oct<A>
      : A extends JWK_AES_KW
        ? CryptoKey | JWK_oct<A>
        : A extends JWK_AES_GCM_KW
          ? CryptoKey | JWK_oct<A>
          : A extends "dir"
            ? CryptoKey | JWK_oct | Uint8Array<ArrayBuffer>
            : never;

/** The keys `unwrapKey` accepts as `unwrappingKey` for algorithm `A`. */
export type UnwrappingKeyFor<A extends KeyManagementAlgorithm> = A extends JWK_RSA_ENC
  ? CryptoKey | JWK_RSA_Private<A>
  : A extends JWK_ECDH_ES
    ? CryptoKey | JWK_EC_Private<A> | JWK_OKP_Private<A>
    : A extends JWK_PBES2
      ? string | Uint8Array<ArrayBuffer> | JWK_oct<A>
      : A extends JWK_AES_KW
        ? CryptoKey | JWK_oct<A>
        : A extends JWK_AES_GCM_KW
          ? CryptoKey | JWK_oct<A>
          : A extends "dir"
            ? CryptoKey | JWK_oct | Uint8Array<ArrayBuffer>
            : never;

/** Options for `wrapKey`. */
export interface WrapKeyOptions<TAlg extends KeyManagementAlgorithm = KeyManagementAlgorithm> {
  alg: TAlg;
  /** The AES-GCMKW IV. Random when omitted. Pass one only for tests and known vectors: an IV reused under one key breaks AES-GCM. */
  iv?: Uint8Array<ArrayBuffer>;
  /** The PBES2 salt (`p2s`), at least 8 octets. Required for PBES2, else `ERR_JWE_INVALID`. */
  p2s?: Uint8Array<ArrayBuffer>;
  /** The PBES2 iteration count (`p2c`), from 1000 to `600_000`. Required for PBES2, else `ERR_JWE_INVALID`. */
  p2c?: number;
  ecdh?: {
    /** The ephemeral key. Generated when omitted. */
    ephemeralKey?: ECDHEphemeralKeyInput;
    /** The agreement PartyUInfo (`apu`), at most 1024 bytes. */
    partyUInfo?: Uint8Array<ArrayBuffer>;
    /** The agreement PartyVInfo (`apv`), at most 1024 bytes. */
    partyVInfo?: Uint8Array<ArrayBuffer>;
    /** The content encryption algorithm. Required for direct `"ECDH-ES"`, else `ERR_JWK_INVALID`. */
    enc?: ContentEncryptionAlgorithm;
  };
}

/** The result of `wrapKey`, shaped by the `alg` family. String members are base64url. */
export type WrapKeyResult<TAlg extends KeyManagementAlgorithm = KeyManagementAlgorithm> =
  TAlg extends JWK_PBES2
    ? {
        encryptedKey: Uint8Array<ArrayBuffer>;
        p2s: string;
        p2c: number;
      }
    : TAlg extends JWK_AES_GCM_KW
      ? {
          encryptedKey: Uint8Array<ArrayBuffer>;
          iv: string;
          tag: string;
        }
      : TAlg extends JWK_ECDH_ES
        ? {
            encryptedKey: Uint8Array<ArrayBuffer>;
            epk: JWK_EC_Public | JWK_OKP_Public;
            apu?: string;
            apv?: string;
          }
        : { encryptedKey: Uint8Array<ArrayBuffer> };

/** Options for `unwrapKey`. */
export interface UnwrapKeyOptions<TAlg extends KeyManagementAlgorithm = KeyManagementAlgorithm> {
  alg: TAlg;
  /** `"cryptokey"` returns a `CryptoKey`, `"raw"` returns the key bytes. Default: `"cryptokey"`. */
  format?: "cryptokey" | "raw";
  /** The AES-GCMKW IV, as base64url or bytes. Required for AES-GCMKW. */
  iv?: Uint8Array<ArrayBuffer> | string;
  /** The AES-GCMKW tag, as base64url or bytes. Required for AES-GCMKW. */
  tag?: Uint8Array<ArrayBuffer> | string;
  /** The PBES2 salt, as base64url or bytes. Required for PBES2. */
  p2s?: Uint8Array<ArrayBuffer> | string;
  /** The PBES2 iteration count. Required for PBES2. */
  p2c?: number;
  /** The lowest PBES2 `p2c` accepted, else `ERR_JWE_INVALID` (RFC 7518 §4.8.1.2). Default: `1000`. */
  minIterations?: number;
  /** The highest PBES2 `p2c` accepted, else `ERR_JWE_INVALID`. Default: `600_000`. */
  maxIterations?: number;
  /** The sender's ephemeral public key. Required for ECDH-ES. */
  epk?: JWK_EC_Public | JWK_OKP_Public | CryptoKey;
  /** The agreement PartyUInfo, as base64url or bytes, at most 1024 bytes. */
  apu?: Uint8Array<ArrayBuffer> | string;
  /** The agreement PartyVInfo, as base64url or bytes, at most 1024 bytes. */
  apv?: Uint8Array<ArrayBuffer> | string;
  /** The content encryption algorithm. Required for direct ECDH-ES. With `dir` and RSA-OAEP, it checks the key length and picks the import algorithm. */
  enc?: ContentEncryptionAlgorithm;
  /** The algorithm the unwrapped key is imported as. Default: AES-GCM, or for RSA-OAEP the one `enc` and the key length name. */
  unwrappedKeyAlgorithm?:
    | string
    | Algorithm
    | RsaOaepParams
    | AesCtrParams
    | AesCbcParams
    | AesGcmParams;
  /** The unwrapped key's usages. Default: `["encrypt", "decrypt"]`. */
  keyUsage?: KeyUsage[];
  /** Makes the unwrapped key extractable. Default: `true`. */
  extractable?: boolean;
}

/** The result of `unwrapKey`: bytes for `format: "raw"`, else a `CryptoKey`. A non-literal `format` gives both. */
export type UnwrapKeyResult<TOptions extends { format?: "cryptokey" | "raw" }> =
  "format" extends keyof TOptions
    ? [TOptions["format"]] extends ["raw"]
      ? Uint8Array<ArrayBuffer>
      : [TOptions["format"]] extends ["cryptokey" | undefined]
        ? CryptoKey
        : CryptoKey | Uint8Array<ArrayBuffer>
    : CryptoKey;

/** Forked from https://github.com/panva/jose/tree/v6.0.10, Copyright (c) 2018 Filip Skokan, LICENSE: https://github.com/panva/jose/blob/v6.0.10/LICENSE.md */

/** The JWK members common to every key type (RFC 7517 §4). `Alg` constrains `alg`. */
export interface JWKParameters<Alg extends JWKAlgorithm = JWKAlgorithm> {
  /** JWK "kty" (Key Type) Parameter */
  "kty": string;
  /** JWK "alg" (Algorithm) Parameter */
  "alg"?: Alg;
  /** JWK "key_ops" (Key Operations) Parameter */
  "key_ops"?: KeyUsage[];
  /** JWK "ext" (Extractable) Parameter */
  "ext"?: boolean;
  /** JWK "use" (Public Key Use) Parameter */
  "use"?: string;
  /** JWK "x5c" (X.509 Certificate Chain) Parameter */
  "x5c"?: string[];
  /** JWK "x5t" (X.509 Certificate SHA-1 Thumbprint) Parameter */
  "x5t"?: string;
  /** JWK "x5t#S256" (X.509 Certificate SHA-256 Thumbprint) Parameter */
  "x5t#S256"?: string;
  /** JWK "x5u" (X.509 URL) Parameter */
  "x5u"?: string;
  /** JWK "kid" (Key ID) Parameter */
  "kid"?: string;
  /** A content encryption hint outside RFC 7517. `encrypt` reads it when no `enc` option is given. */
  "enc"?: ContentEncryptionAlgorithm;
}

/** The JWK members a caller can set on a generated or derived key: all but `alg`, `kty`, `key_ops` and `ext`. */
export type JWKMetadata = Omit<JWKParameters, "alg" | "kty" | "key_ops" | "ext">;

/** An ECDH-ES ephemeral key: a private key, a `CryptoKeyPair`, or an object with both halves. */
export type ECDHEphemeralKeyInput =
  | CryptoKey
  | JWK_EC_Private
  | JWK_OKP_Private
  | CryptoKeyPair
  | {
      publicKey: CryptoKey | JWK_EC_Public | JWK_OKP_Public;
      privateKey: CryptoKey | JWK_EC_Private | JWK_OKP_Private;
    };

/** A public EC JWK. */
export interface JWK_EC_Public<
  Alg extends JWK_ECDSA | JWK_ECDH_ES = JWK_ECDSA | JWK_ECDH_ES,
> extends JWKParameters<Alg> {
  kty: "EC";
  /** EC JWK "crv" (Curve) Parameter */
  crv: string;
  /** EC JWK "x" (X Coordinate) Parameter */
  x: string;
  /** EC JWK "y" (Y Coordinate) Parameter */
  y: string;
}

/** A private EC JWK. */
export interface JWK_EC_Private<
  Alg extends JWK_ECDSA | JWK_ECDH_ES = JWK_ECDSA | JWK_ECDH_ES,
> extends JWK_EC_Public<Alg> {
  /** EC JWK "d" (ECC Private Key) Parameter */
  d: string;
}

/** A public or private EC JWK. */
export type JWK_EC<Alg extends JWK_ECDSA | JWK_ECDH_ES = JWK_ECDSA | JWK_ECDH_ES> =
  | JWK_EC_Public<Alg>
  | JWK_EC_Private<Alg>;

/** A public RSA JWK. */
export interface JWK_RSA_Public<
  Alg extends JWK_RSA_SIGN | JWK_RSA_PSS | JWK_RSA_ENC = JWK_RSA_SIGN | JWK_RSA_PSS | JWK_RSA_ENC,
> extends JWKParameters<Alg> {
  kty: "RSA";
  /** RSA JWK "e" (Exponent) Parameter */
  e: string;
  /** RSA JWK "n" (Modulus) Parameter */
  n: string;
  oth?: RsaOtherPrimesInfo[];
}

/** A private RSA JWK. */
export interface JWK_RSA_Private<
  Alg extends JWK_RSA_SIGN | JWK_RSA_PSS | JWK_RSA_ENC = JWK_RSA_SIGN | JWK_RSA_PSS | JWK_RSA_ENC,
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

/** A public or private RSA JWK. */
export type JWK_RSA<
  Alg extends JWK_RSA_SIGN | JWK_RSA_PSS | JWK_RSA_ENC = JWK_RSA_SIGN | JWK_RSA_PSS | JWK_RSA_ENC,
> = JWK_RSA_Public<Alg> | JWK_RSA_Private<Alg>;

/** A public OKP JWK (RFC 8037). */
export interface JWK_OKP_Public<
  Alg extends JWK_OKP_SIGN | JWK_ECDH_ES = JWK_OKP_SIGN | JWK_ECDH_ES,
> extends JWKParameters<Alg> {
  kty: "OKP";
  /** OKP JWK "crv" (Curve) Parameter */
  crv: string;
  /** OKP JWK "x" (Public Key) Parameter */
  x: string;
}

/** A private OKP JWK (RFC 8037). */
export interface JWK_OKP_Private<
  Alg extends JWK_OKP_SIGN | JWK_ECDH_ES = JWK_OKP_SIGN | JWK_ECDH_ES,
> extends JWK_OKP_Public<Alg> {
  /** OKP JWK "d" (Private Key) Parameter */
  d: string;
}

/** A public or private OKP JWK. */
export type JWK_OKP<Alg extends JWK_OKP_SIGN | JWK_ECDH_ES = JWK_OKP_SIGN | JWK_ECDH_ES> =
  | JWK_OKP_Public<Alg>
  | JWK_OKP_Private<Alg>;

/** A symmetric (`oct`) JWK. */
export interface JWK_oct<
  Alg extends
    | JWK_HMAC
    | JWK_AES_KW
    | JWK_AES_GCM
    | JWK_AES_GCM_KW
    | JWK_AES_CBC_HMAC
    | JWK_PBES2
    | "dir" =
    | JWK_HMAC
    | JWK_AES_KW
    | JWK_AES_GCM
    | JWK_AES_GCM_KW
    | JWK_AES_CBC_HMAC
    | JWK_PBES2
    | "dir",
> extends JWKParameters<Alg> {
  kty: "oct";
  /** Oct JWK "k" (Key Value) Parameter */
  k: string;
}

/** A symmetric JWK, the same as `JWK_oct`. */
export type JWK_Symmetric<
  Alg extends
    | JWK_HMAC
    | JWK_AES_KW
    | JWK_AES_GCM
    | JWK_AES_GCM_KW
    | JWK_AES_CBC_HMAC
    | JWK_PBES2
    | "dir" =
    | JWK_HMAC
    | JWK_AES_KW
    | JWK_AES_GCM
    | JWK_AES_GCM_KW
    | JWK_AES_CBC_HMAC
    | JWK_PBES2
    | "dir",
> = JWK_oct<Alg>;

/** An asymmetric JWK, narrowed to the key types `Alg` can use. */
export type JWK_Asymmetric<Alg extends JWK_Asymmetric_Algorithm = JWK_Asymmetric_Algorithm> =
  | RSAFor<Alg, JWK_RSA<Extract<Alg, JWK_RSA_SIGN | JWK_RSA_PSS | JWK_RSA_ENC>>>
  | ECFor<Alg, JWK_EC<Extract<Alg, JWK_ECDSA | JWK_ECDH_ES>>>
  | OKPFor<Alg, JWK_OKP<Extract<Alg, JWK_OKP_SIGN | JWK_ECDH_ES>>>;

/** A public JWK, narrowed to the key types `Alg` can use. */
export type JWK_Public<Alg extends JWK_Asymmetric_Algorithm = JWK_Asymmetric_Algorithm> =
  | RSAFor<Alg, JWK_RSA_Public<Extract<Alg, JWK_RSA_SIGN | JWK_RSA_PSS | JWK_RSA_ENC>>>
  | ECFor<Alg, JWK_EC_Public<Extract<Alg, JWK_ECDSA | JWK_ECDH_ES>>>
  | OKPFor<Alg, JWK_OKP_Public<Extract<Alg, JWK_OKP_SIGN | JWK_ECDH_ES>>>;

/** A private JWK, narrowed to the key types `Alg` can use. */
export type JWK_Private<Alg extends JWK_Asymmetric_Algorithm = JWK_Asymmetric_Algorithm> =
  | RSAFor<Alg, JWK_RSA_Private<Extract<Alg, JWK_RSA_SIGN | JWK_RSA_PSS | JWK_RSA_ENC>>>
  | ECFor<Alg, JWK_EC_Private<Extract<Alg, JWK_ECDSA | JWK_ECDH_ES>>>
  | OKPFor<Alg, JWK_OKP_Private<Extract<Alg, JWK_OKP_SIGN | JWK_ECDH_ES>>>;

/** The `toPublicJWK` result: the public JWK of the input's key type and `alg`, with `kid` when the input type has one. */
export type ToPublicJWKReturn<T extends JWK_Asymmetric> = (T extends JWK_RSA<infer Alg>
  ? JWK_RSA_Public<Alg>
  : T extends JWK_EC<infer Alg>
    ? JWK_EC_Public<Alg>
    : T extends JWK_OKP<infer Alg>
      ? JWK_OKP_Public<Alg>
      : never) &
  (T extends { kid: string } ? { kid: string } : unknown);

/** A JWK (RFC 7517) of type `"RSA"`, `"EC"`, `"OKP"` or `"oct"`, narrowed to the key types `Alg` can use. */
export type JWK<Alg extends JWKAlgorithm = JWKAlgorithm> =
  | OctFor<Alg, JWK_oct<Extract<Alg, Exclude<JWKAlgorithm, JWK_Asymmetric_Algorithm>>>>
  | JWK_Asymmetric<Extract<Alg, JWK_Asymmetric_Algorithm>>;

/** A public and private JWK pair of the key type `Alg` names. ECDH-ES gives an EC or an OKP pair. */
export type JWK_Pair<Alg extends JWK_Asymmetric_Algorithm = JWK_Asymmetric_Algorithm> = Alg extends
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
        : never;

/** A JWK Set (RFC 7517 §5). `T` keeps a precise key tuple. */
export interface JWKSet<T extends readonly JWK[] = JWK[]> {
  keys: T;

  [parameter: string]: unknown;
}

/** JWA algorithm identifiers, grouped by family (RFC 7518, RFC 8037). */

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

/** Every algorithm named after an AES key size: the `A128`, `A192` and `A256` families. */
export type JWK_AES_Algorithm = JWK_AES_KW | JWK_AES_GCM | JWK_AES_GCM_KW | JWK_AES_CBC_HMAC;

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
  | "dir";

export type JWKPEMAlgorithm =
  | JWK_RSA_PSS
  | JWK_RSA_SIGN
  | JWK_RSA_ENC
  | JWK_ECDSA
  | JWK_ECDH_ES
  | JWK_OKP_SIGN;

type GeneratedJWKMembers<A, Kid> = [Kid] extends [false]
  ? { alg: A }
  : [Kid] extends [string]
    ? { alg: A; kid: string }
    : { alg: A; kid?: string };

type GeneratedJWKPair<P, A, Kid> = P extends { privateKey: infer Private; publicKey: infer Public }
  ? {
      privateKey: Private & GeneratedJWKMembers<A, Kid>;
      publicKey: Public & GeneratedJWKMembers<A, Kid>;
    }
  : never;

type GeneratedKid<TOptions> = "kid" extends keyof TOptions
  ? ThumbprintIfUnset<Extract<TOptions["kid" & keyof TOptions], string | false>>
  : string;

type ThumbprintIfUnset<Kid extends string | false> = [Kid] extends [never] ? string : Kid;

type GeneratedKeyShape<TAlg extends GenerateKeyAlgorithm, ToJWK, Kid extends string | false> = [
  ToJWK,
] extends [never]
  ? GeneratedKeyMap[TAlg]
  : ToJWK extends true
    ? GeneratedJWKMap<Kid>[TAlg]
    : GeneratedKeyMap[TAlg];

/** `Shape` when `Alg` has a member of that key type, else `never`. */
type OctFor<Alg, Shape> = [Extract<Alg, Exclude<JWKAlgorithm, JWK_Asymmetric_Algorithm>>] extends [
  never,
]
  ? never
  : Shape;
type RSAFor<Alg, Shape> = [Extract<Alg, JWK_RSA_SIGN | JWK_RSA_PSS | JWK_RSA_ENC>] extends [never]
  ? never
  : Shape;
type ECFor<Alg, Shape> = [Extract<Alg, JWK_ECDSA | JWK_ECDH_ES>] extends [never] ? never : Shape;
type OKPFor<Alg, Shape> = [Extract<Alg, JWK_OKP_SIGN | JWK_ECDH_ES>] extends [never]
  ? never
  : Shape;
