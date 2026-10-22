import type { JWSAlgorithm } from "./jws.ts";

/** Decoded protected header a `JWKLookupFunction` receives, its algorithms already checked against the ones this version implements; `enc` is present on JWE only. */
export type JWKLookupFunctionHeader = {
  kid?: string;
  alg?: JWSAlgorithm | KeyManagementAlgorithm;
  enc?: ContentEncryptionAlgorithm;
  typ?: string;
  crit?: string[];
  [propName: string]: unknown;
};

/** Resolves the verify/decrypt key from the protected header (`THeader`: the family's, else the generic one) and compact token; a string is a PBES2 password (JWE) or raw key bytes (JWS); `undefined`, `null` or a throw is `ERR_JWK_KEY_NOT_FOUND`. */
export type JWKLookupFunction<
  TReturn = CryptoKey | JWK | JWKSet | string | Uint8Array<ArrayBuffer>,
  THeader = JWKLookupFunctionHeader,
> = (
  header: THeader,
  token: string,
) => TReturn | undefined | null | Promise<TReturn | undefined | null>;

/** Custom JWK import cache; key on the JWK `thumbprint` plus private/public half and `alg`, never on `kid`. Both methods may return a promise. */
export interface JWKCacheAdapter {
  get(jwk: JWK, alg: JWKAlgorithm): CryptoKey | undefined | Promise<CryptoKey | undefined>;
  set(jwk: JWK, alg: JWKAlgorithm, key: CryptoKey): void | Promise<void>;
}

/** Structure returned for composite AES-CBC + HMAC keys. */
export type CompositeKey = {
  encryptionKey: CryptoKey;
  macKey: CryptoKey;
};

export type GenerateKeyAlgorithm = Exclude<JWKAlgorithm, "none" | "dir" | JWK_PBES2>;

/** Options for `generateJWK`; `Kid` is the `kid` option that types the generated `kid`. */
export interface GenerateJWKOptions<Kid extends string | false = string | false> {
  /** Key usages; composite (CBC) keys get their default usages separately. */
  keyUsage?: KeyUsage[];
  /** RSA modulus length. Default: `2048`. */
  modulusLength?: number;
  /** RSA public exponent. Default: `65537`. */
  publicExponent?: Uint8Array<ArrayBuffer>;
  /** EC/OKP curve. Default: `"P-256"` (EC), `"Ed25519"` (OKP). */
  namedCurve?: "P-256" | "P-384" | "P-521" | "X25519" | "Ed25519";
  /** `kid` to set verbatim, or `false` for none. Default: the RFC 7638 thumbprint, a SHA-256 digest per key. */
  kid?: Kid;
}

/** Options for `generateKey`; `ToJWK` is the `toJWK` literal that picks key objects or JWKs. */
export interface GenerateKeyOptions<
  ToJWK extends boolean = boolean,
  Kid extends string | false = string | false,
> extends GenerateJWKOptions<Kid> {
  /** Mark the key(s) extractable; ignored when `toJWK` is set. Default: `true`. */
  extractable?: boolean;
  /** Return JWKs instead of key objects. */
  toJWK?: ToJWK;
  /** Read only with `toJWK`: `kid` to set verbatim, or `false` for none. Default: the RFC 7638 thumbprint, a SHA-256 digest per key. */
  kid?: Kid;
}

/** `generateKey` result per algorithm without `toJWK`: `CryptoKey` (symmetric), raw bytes (`A*CBC-HS*`), `CryptoKeyPair` (asymmetric). */
export type GeneratedKeyMap = {
  [A in GenerateKeyAlgorithm]: A extends JWK_AES_CBC_HMAC
    ? Uint8Array<ArrayBuffer>
    : A extends JWK_Asymmetric_Algorithm
      ? CryptoKeyPair
      : CryptoKey;
};

/** `generateJWK` result per algorithm: an `oct` JWK or a JWK pair, each carrying `alg`, and `kid` unless `Kid` is `false`. */
export type GeneratedJWKMap<Kid extends string | false = string> = {
  [A in GenerateKeyAlgorithm]: A extends JWK_Asymmetric_Algorithm
    ? GeneratedJWKPair<JWK_Pair<A>, A, Kid>
    : JWK_oct<Exclude<A, JWK_Asymmetric_Algorithm>> & GeneratedJWKMembers<A, Kid>;
};

/** `generateKey` return type for `TAlg` under `TOptions`; JWKs when `toJWK` is `true`. */
export type GenerateKeyReturn<
  TAlg extends GenerateKeyAlgorithm,
  TOptions extends GenerateKeyOptions,
> = GeneratedKeyShape<TAlg, Exclude<TOptions["toJWK"], undefined>, GeneratedKid<TOptions>>;

/** `generateJWK` return type for `TAlg` under the `kid` option `Kid`. */
export type GenerateJWKReturn<
  TAlg extends GenerateKeyAlgorithm,
  Kid extends string | false = string,
> = GeneratedJWKMap<Kid>[TAlg];

/** What `importKey` resolves to per input: bytes and `oct` JWKs to raw bytes, a `CryptoKey` as is, asymmetric JWKs to a `CryptoKey`. */
export interface ImportedKeyMap {
  bytes: Uint8Array<ArrayBuffer>;
  oct: Uint8Array<ArrayBuffer>;
  cryptoKey: CryptoKey;
  asymmetric: CryptoKey;
}

/** `ImportedKeyMap` entry for key input `K`; a union input yields a union. */
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
  /** Salt (p2s), bytes or UTF-8 text; at least 8 octets (RFC 7518 §4.8.1.1). */
  salt: string | Uint8Array<ArrayBuffer>;
  /** Iteration count (p2c), a positive integer. */
  iterations: number;
  /** Key usages. Default: `["wrapKey", "unwrapKey"]`. */
  keyUsage?: KeyUsage[];
  /** Mark the derived key extractable; ignored when `toJWK` is set. Default: `false`. */
  extractable?: boolean;
  /** Return the derived key as a `JWK_oct`. */
  toJWK?: boolean;
}

/** The AES-KW algorithm a `PBES2-*` or `ECDH-ES+*` algorithm wraps the CEK with: its last six characters. */
export type KeyWrapAlgorithmOf<A extends KeyWrappingAlgorithm> = A extends `${string}A128KW`
  ? "A128KW"
  : A extends `${string}A192KW`
    ? "A192KW"
    : A extends `${string}A256KW`
      ? "A256KW"
      : never;

/** Key management algorithms that wrap the CEK with an inner AES-KW step. */
export type KeyWrappingAlgorithm = JWK_PBES2 | Exclude<JWK_ECDH_ES, "ECDH-ES">;

/** PBES2 → AES-KW `alg` stamped on the derived JWK. */
type DerivedJWKAlg<TAlg extends JWK_PBES2> = KeyWrapAlgorithmOf<TAlg>;

export type DeriveKeyReturn<
  TOptions extends DeriveKeyOptions,
  TAlg extends JWK_PBES2 = JWK_PBES2,
> = TOptions["toJWK"] extends true
  ? JWK_oct<DerivedJWKAlg<TAlg>>
  : TOptions["toJWK"] extends object
    ? JWK_oct<DerivedJWKAlg<TAlg>>
    : CryptoKey;

/** Options of `deriveJWKFromPassword`: PBES2 derivation without `toJWK`/`extractable`, plus `kid` (`false` for none). */
export type DeriveJWKOptions<
  TAlg extends JWK_PBES2 = JWK_PBES2,
  Kid extends string | false = string,
> = Omit<DeriveKeyOptions, "alg" | "toJWK" | "extractable"> & { alg: TAlg; kid?: Kid };

/** `deriveJWKFromPassword` return type: the AES-KW `oct` JWK for `TAlg`, with `kid` unless `Kid` is `false`. */
export type DeriveJWKReturn<TAlg extends JWK_PBES2, Kid extends string | false = string> = JWK_oct<
  DerivedJWKAlg<TAlg>
> &
  GeneratedJWKMembers<DerivedJWKAlg<TAlg>, Kid>;

/** PEM label families `importPEM` reads. */
export type PEMType = "pkcs8" | "spki" | "x509";

/** `importPEM` result for `Alg`: the private JWK of a PKCS#8 PEM, the public one of SPKI/X.509, both when the label is inferred. */
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

/** Keys admissible as the `wrappingKey` of `wrapKey` for algorithm `A`; `dir` takes any symmetric key. */
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

/** Private-side counterpart of `WrappingKeyFor`, for the `unwrappingKey` of `unwrapKey`. */
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
  /** AES-GCMKW IV, random when omitted; never reuse one under the same key (tests and known vectors only). */
  iv?: Uint8Array<ArrayBuffer>;
  /** PBES2 Salt value (p2s). Required for PBES2 algorithms. */
  p2s?: Uint8Array<ArrayBuffer>;
  /** PBES2 Iteration count (p2c). Required for PBES2 algorithms. */
  p2c?: number;
  ecdh?: {
    /** Ephemeral key material. Generated when omitted. */
    ephemeralKey?: ECDHEphemeralKeyInput;
    /** Agreement PartyUInfo (apu). */
    partyUInfo?: Uint8Array<ArrayBuffer>;
    /** Agreement PartyVInfo (apv). */
    partyVInfo?: Uint8Array<ArrayBuffer>;
    /** Required only for direct `"ECDH-ES"` key agreement. */
    enc?: ContentEncryptionAlgorithm;
  };
}

/** Result of `wrapKey`, shaped by the `alg` family; string members are base64url. */
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
  /** `"cryptokey"` returns a `CryptoKey`, `"raw"` the key bytes. Default: `"cryptokey"`. */
  format?: "cryptokey" | "raw";
  /** Required for AES-GCMKW; base64url or bytes. */
  iv?: Uint8Array<ArrayBuffer> | string;
  /** Required for AES-GCMKW; base64url or bytes. */
  tag?: Uint8Array<ArrayBuffer> | string;
  /** Required for PBES2; base64url or bytes. */
  p2s?: Uint8Array<ArrayBuffer> | string;
  /** Required for PBES2. */
  p2c?: number;
  /** Minimum accepted PBES2 `p2c` on unwrap. Defaults to 1000 (RFC 7518 §4.8.1.2). */
  minIterations?: number;
  /** Maximum accepted PBES2 `p2c` on unwrap. Default: `600_000`. */
  maxIterations?: number;
  /** Required for ECDH-ES. */
  epk?: JWK_EC_Public | JWK_OKP_Public | CryptoKey;
  apu?: Uint8Array<ArrayBuffer> | string;
  apv?: Uint8Array<ArrayBuffer> | string;
  /** Required for direct ECDH-ES key agreement. */
  enc?: ContentEncryptionAlgorithm;
  /** Algorithm to import the unwrapped key as. */
  unwrappedKeyAlgorithm?:
    | string
    | Algorithm
    | RsaOaepParams
    | AesCtrParams
    | AesCbcParams
    | AesGcmParams;
  keyUsage?: KeyUsage[];
  /** Mark the unwrapped key extractable. Default: `true`. */
  extractable?: boolean;
}

/** Result of `unwrapKey`: bytes for `format: "raw"`, else a `CryptoKey`; a non-literal `format` keeps both. */
export type UnwrapKeyResult<TOptions extends { format?: "cryptokey" | "raw" }> =
  "format" extends keyof TOptions
    ? [TOptions["format"]] extends ["raw"]
      ? Uint8Array<ArrayBuffer>
      : [TOptions["format"]] extends ["cryptokey" | undefined]
        ? CryptoKey
        : CryptoKey | Uint8Array<ArrayBuffer>
    : CryptoKey;

/** Forked from https://github.com/panva/jose/tree/v6.0.10, Copyright (c) 2018 Filip Skokan, LICENSE: https://github.com/panva/jose/blob/v6.0.10/LICENSE.md */

/** Generic JWK parameters; `Alg` constrains the `alg` member. */
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
  /** Non-standard `enc` hint, read when `alg` is `"dir"` and no `enc` option is given. */
  "enc"?: ContentEncryptionAlgorithm;
}

/** JWK members a caller may set on a produced key: all but `alg`, `kty`, `key_ops` and `ext`. */
export type JWKMetadata = Omit<JWKParameters, "alg" | "kty" | "key_ops" | "ext">;

/** ECDH-ES ephemeral key material: a private key, a `CryptoKeyPair`, or an object with both halves. */
export type ECDHEphemeralKeyInput =
  | CryptoKey
  | JWK_EC_Private
  | JWK_OKP_Private
  | CryptoKeyPair
  | {
      publicKey: CryptoKey | JWK_EC_Public | JWK_OKP_Public;
      privateKey: CryptoKey | JWK_EC_Private | JWK_OKP_Private;
    };

/** Public EC JSON Web Keys */
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

/** Private EC JSON Web Keys */
export interface JWK_EC_Private<
  Alg extends JWK_ECDSA | JWK_ECDH_ES = JWK_ECDSA | JWK_ECDH_ES,
> extends JWK_EC_Public<Alg> {
  /** EC JWK "d" (ECC Private Key) Parameter */
  d: string;
}

/** EC JSON Web Keys */
export type JWK_EC<Alg extends JWK_ECDSA | JWK_ECDH_ES = JWK_ECDSA | JWK_ECDH_ES> =
  | JWK_EC_Public<Alg>
  | JWK_EC_Private<Alg>;

/** Public RSA JSON Web Keys */
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

/** Private RSA JSON Web Keys */
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

/** RSA JSON Web Keys */
export type JWK_RSA<
  Alg extends JWK_RSA_SIGN | JWK_RSA_PSS | JWK_RSA_ENC = JWK_RSA_SIGN | JWK_RSA_PSS | JWK_RSA_ENC,
> = JWK_RSA_Public<Alg> | JWK_RSA_Private<Alg>;

/** Public ED JSON Web Keys */
export interface JWK_OKP_Public<
  Alg extends JWK_OKP_SIGN | JWK_ECDH_ES = JWK_OKP_SIGN | JWK_ECDH_ES,
> extends JWKParameters<Alg> {
  kty: "OKP";
  /** ED JWK "crv" (Curve) Parameter */
  crv: string;
  /** ED JWK "x" (X Coordinate) Parameter */
  x: string;
}

/** Private ED JSON Web Keys */
export interface JWK_OKP_Private<
  Alg extends JWK_OKP_SIGN | JWK_ECDH_ES = JWK_OKP_SIGN | JWK_ECDH_ES,
> extends JWK_OKP_Public<Alg> {
  /** ED JWK "d" (Private Key) Parameter */
  d: string;
}

/** OKP JSON Web Keys */
export type JWK_OKP<Alg extends JWK_OKP_SIGN | JWK_ECDH_ES = JWK_OKP_SIGN | JWK_ECDH_ES> =
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

/** Symmetric JSON Web Keys */
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

/** Asymmetric JSON Web Keys. */
export type JWK_Asymmetric<Alg extends JWK_Asymmetric_Algorithm = JWK_Asymmetric_Algorithm> =
  | RSAFor<Alg, JWK_RSA<Extract<Alg, JWK_RSA_SIGN | JWK_RSA_PSS | JWK_RSA_ENC>>>
  | ECFor<Alg, JWK_EC<Extract<Alg, JWK_ECDSA | JWK_ECDH_ES>>>
  | OKPFor<Alg, JWK_OKP<Extract<Alg, JWK_OKP_SIGN | JWK_ECDH_ES>>>;

/** Public JSON Web Keys. */
export type JWK_Public<Alg extends JWK_Asymmetric_Algorithm = JWK_Asymmetric_Algorithm> =
  | RSAFor<Alg, JWK_RSA_Public<Extract<Alg, JWK_RSA_SIGN | JWK_RSA_PSS | JWK_RSA_ENC>>>
  | ECFor<Alg, JWK_EC_Public<Extract<Alg, JWK_ECDSA | JWK_ECDH_ES>>>
  | OKPFor<Alg, JWK_OKP_Public<Extract<Alg, JWK_OKP_SIGN | JWK_ECDH_ES>>>;

/** Private JSON Web Keys. */
export type JWK_Private<Alg extends JWK_Asymmetric_Algorithm = JWK_Asymmetric_Algorithm> =
  | RSAFor<Alg, JWK_RSA_Private<Extract<Alg, JWK_RSA_SIGN | JWK_RSA_PSS | JWK_RSA_ENC>>>
  | ECFor<Alg, JWK_EC_Private<Extract<Alg, JWK_ECDSA | JWK_ECDH_ES>>>
  | OKPFor<Alg, JWK_OKP_Private<Extract<Alg, JWK_OKP_SIGN | JWK_ECDH_ES>>>;

/** `toPublicJWK` result: the public interface of the input's family and `alg`, keeping a `kid` the input is typed to carry. */
export type ToPublicJWKReturn<T extends JWK_Asymmetric> = (T extends JWK_RSA<infer Alg>
  ? JWK_RSA_Public<Alg>
  : T extends JWK_EC<infer Alg>
    ? JWK_EC_Public<Alg>
    : T extends JWK_OKP<infer Alg>
      ? JWK_OKP_Public<Alg>
      : never) &
  (T extends { kid: string } ? { kid: string } : unknown);

/** JSON Web Key (RFC 7517) of type "RSA", "EC", "OKP" or "oct". */
export type JWK<Alg extends JWKAlgorithm = JWKAlgorithm> =
  | OctFor<Alg, JWK_oct<Extract<Alg, Exclude<JWKAlgorithm, JWK_Asymmetric_Algorithm>>>>
  | JWK_Asymmetric<Extract<Alg, JWK_Asymmetric_Algorithm>>;

/** Public/private JWK pair, narrowed to the key family `Alg` identifies (ECDH-ES: EC or OKP). */
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

/** JSON Web Key Set (RFC 7517); `T` preserves a precise key tuple. */
export interface JWKSet<T extends readonly JWK[] = JWK[]> {
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

/** Every algorithm named after an AES key size: the `A128`/`A192`/`A256` families. */
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

/** `Shape` when `Alg` has a member of that family, else nothing: a family never appears for an `alg` it cannot carry. */
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
