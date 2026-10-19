import type {
  JoseHeaderParameters,
  JOSELimits,
  JOSEPayload,
  JOSEConsumerOptions,
  JOSEPayloadMode,
  JWTTimeClaimOptions,
} from "./jwt";
import type {
  JWK,
  JWK_oct,
  JWK_EC_Public,
  JWK_EC_Private,
  JWK_OKP_Public,
  JWK_OKP_Private,
  JWK_RSA_Public,
  JWK_RSA_Private,
  JWK_AES_KW,
  JWK_AES_GCM,
  JWK_AES_GCM_KW,
  JWK_AES_CBC_HMAC,
  JWK_PBES2,
  JWK_RSA_ENC,
  JWK_ECDH_ES,
  KeyManagementAlgorithm,
  ContentEncryptionAlgorithm,
  JWKSet,
  JWKLookupFunction,
  ECDHEphemeralKeyInput,
} from "./jwk";
import type { StrictOmit } from "../utils/types";

/** `oct` JWK algorithms admissible for JWE key management (HMAC excluded). */
type _JWEOctAlg = JWK_AES_KW | JWK_AES_GCM | JWK_AES_GCM_KW | JWK_AES_CBC_HMAC | JWK_PBES2 | "dir";

/** Asymmetric public JWKs admissible for JWE encryption (RSA-OAEP or ECDH-ES). */
export type JWEAsymmetricPublicJWK =
  | JWK_RSA_Public<JWK_RSA_ENC>
  | JWK_EC_Public<JWK_ECDH_ES>
  | JWK_OKP_Public<JWK_ECDH_ES>;

/** Asymmetric private JWKs admissible for JWE decryption (RSA-OAEP or ECDH-ES). */
export type JWEAsymmetricPrivateJWK =
  | JWK_RSA_Private<JWK_RSA_ENC>
  | JWK_EC_Private<JWK_ECDH_ES>
  | JWK_OKP_Private<JWK_ECDH_ES>;

/** JWKs admissible as the `key` of `encrypt`; a non-JWE `alg` is a type error. */
export type JWEEncryptJWK = JWK_oct<_JWEOctAlg> | JWEAsymmetricPublicJWK;

/** JWKs admissible as a `key` of `decrypt`; a non-JWE `alg` is a type error. */
export type JWEDecryptJWK = JWK_oct<_JWEOctAlg> | JWEAsymmetricPrivateJWK;

/** Recognized JWE Header Parameters; other members may also be present. */
export interface JWEHeaderParameters extends JoseHeaderParameters {
  /** Key Management Algorithm. */
  alg?: KeyManagementAlgorithm;
  /** Content Encryption Algorithm. */
  enc?: ContentEncryptionAlgorithm;
  /** PBES2 Count. */
  p2c?: number;
  /** PBES2 Salt, base64url. */
  p2s?: string;
  /** AES-GCMKW Initialization Vector, base64url. */
  iv?: string;
  /** AES-GCMKW Authentication Tag, base64url. */
  tag?: string;
  /** ECDH-ES Ephemeral Public Key. */
  epk?: JWK_EC_Public | JWK_OKP_Public;
  /** ECDH-ES Agreement PartyUInfo, base64url. */
  apu?: string;
  /** ECDH-ES Agreement PartyVInfo, base64url. */
  apv?: string;
  /** Compression (RFC 7516 §4.1.3) is not supported: a token carrying `zip` is rejected. */
  zip?: never;

  [propName: string]: unknown;
}

/** Recognized JWE Key Management-related Header Parameters; all but `apu`/`apv` are internal. */
export interface JWEKeyManagementHeaderParameters {
  apu?: Uint8Array<ArrayBuffer>;
  apv?: Uint8Array<ArrayBuffer>;
  p2c?: number;
  p2s?: Uint8Array<ArrayBuffer>;
  iv?: Uint8Array<ArrayBuffer>;
  epk?: CryptoKey | JWK_EC_Public | JWK_OKP_Public;
  epkPrivateKey?: CryptoKey | JWK_EC_Private | JWK_OKP_Private;
}

/** Header parameters the library writes itself and no caller header may set (RFC 7516 §4.1, RFC 7518 §4.6–§4.8). */
export type JWELibraryHeaderName =
  | "alg"
  | "enc"
  | "iv"
  | "tag"
  | "p2s"
  | "p2c"
  | "epk"
  | "apu"
  | "apv";

/** JWE encryption options. */
export interface JWEEncryptOptions extends JWTTimeClaimOptions {
  alg?: KeyManagementAlgorithm;
  enc?: ContentEncryptionAlgorithm;
  /** Extra protected header; `typ` defaults to `"JWT"` for a JSON object payload, `cty` is never added (`"JWT"` for a nested JWT, RFC 7519 §5.2). */
  protectedHeader?: StrictOmit<JWEHeaderParameters, JWELibraryHeaderName>;

  /** AES-GCMKW key-wrapping IV. Generated when omitted. */
  keyManagementIV?: Uint8Array<ArrayBuffer>;
  /** PBES2 Salt (p2s). Required for PBES2 algorithms. */
  p2s?: Uint8Array<ArrayBuffer>;
  /** PBES2 iteration count (p2c), between `1000` and `600_000`. Default: `600_000`. */
  p2c?: number;
  ecdh?: {
    ephemeralKey?: ECDHEphemeralKeyInput;
    partyUInfo?: Uint8Array<ArrayBuffer>;
    partyVInfo?: Uint8Array<ArrayBuffer>;
  };

  /** Content Encryption Key. Generated when omitted. */
  cek?: Uint8Array<ArrayBuffer>;

  /** Content encryption IV. Generated when omitted. */
  contentEncryptionIV?: Uint8Array<ArrayBuffer>;
}

/** JWE decryption options; `Mode` is the `payload` option's literal, which sets the returned payload type. */
export interface JWEDecryptOptions<
  Mode extends JOSEPayloadMode = JOSEPayloadMode,
> extends JOSEConsumerOptions<Mode> {
  /** Allowed `alg` values. Inferred from the key when omitted (a password infers PBES2); required for raw bytes and lookup functions. */
  algorithms?: KeyManagementAlgorithm[];
  /** Max JWK Set candidates per token (else `ERR_JWK_KEY_NOT_FOUND`) and PBKDF2 iterations per call (else `ERR_JWE_INVALID`). Default: `{ keyCandidates: 8, pbes2Iterations: 2_400_000 }`. */
  limits?: Pick<JOSELimits, "keyCandidates" | "pbes2Iterations">;
  /** Allowed `enc` values. */
  encryptionAlgorithms?: ContentEncryptionAlgorithm[];
  /** Algorithm to import the unwrapped CEK as. Defaults based on `enc`. */
  unwrappedKeyAlgorithm?: Parameters<typeof crypto.subtle.importKey>[2];

  /** Unwrapped CEK usages. Defaults based on `enc`. */
  keyUsage?: KeyUsage[];
  /** Mark the unwrapped CEK extractable. Default: `true`. */
  extractable?: boolean;
  /** Include the CEK and AAD in the result. */
  returnCek?: boolean;
  /** Minimum accepted PBES2 `p2c` on unwrap. Defaults to 1000 (RFC 7518 §4.8.1.2). */
  minIterations?: number;
  /** Maximum accepted PBES2 `p2c` on unwrap. Default: `600_000`. */
  maxIterations?: number;
}

/** Validated protected header returned by `decrypt`; `alg` and `enc` are always present. */
export interface JWEProtectedHeader extends JWEHeaderParameters {
  alg: KeyManagementAlgorithm;
  enc: ContentEncryptionAlgorithm;
}

/** Result of a JWE decryption. */
export interface JWEDecryptResult<T extends JOSEPayload = JOSEPayload> {
  payload: T;
  protectedHeader: JWEProtectedHeader;
  /** Present only when `returnCek` is true. */
  cek?: Uint8Array<ArrayBuffer>;
  /** Present only when `returnCek` is true. */
  aad?: Uint8Array<ArrayBuffer>;
}

/** JWE Flattened JSON Serialization (RFC 7516 §7.2.2); string members are base64url. */
export interface JWEFlattenedSerialization {
  header?: JWEHeaderParameters;
  encrypted_key?: string;
  /** JWE Protected Header (part of AAD). */
  protected?: string;
  /** Shared Unprotected Header (not part of AAD). */
  unprotected?: JWEHeaderParameters;
  /** External Additional Authenticated Data. */
  aad?: string;
  iv: string;
  ciphertext: string;
  tag: string;
}

/** JWE General JSON Serialization (RFC 7516 §7.2.1), the output of `encryptMulti`. */
export interface JWEGeneralSerialization extends Omit<
  JWEFlattenedSerialization,
  "encrypted_key" | "header"
> {
  recipients: JWEGeneralRecipient[];
}

/** One recipient entry of a JWE General JSON Serialization. */
export interface JWEGeneralRecipient {
  /** Per-recipient Unprotected Header (not part of AAD). */
  header?: JWEHeaderParameters;
  encrypted_key?: string;
}

/** One recipient of `encryptMulti`; `alg` and `kid` come from the key unless set in `header`. */
export interface JWEMultiRecipient {
  key: JWEEncryptJWK;
  /** Extra per-recipient Unprotected Header parameters (RFC 7516 §7.2.1). */
  header?: StrictOmit<JWEHeaderParameters, JWELibraryHeaderName>;
  ecdh?: JWEEncryptOptions["ecdh"];
  /** PBES2 salt. Random 16 bytes when omitted. */
  p2s?: Uint8Array<ArrayBuffer>;
  /** PBES2 iteration count, between `1000` and `600_000`. Default: `600_000`. */
  p2c?: number;
  keyManagementIV?: Uint8Array<ArrayBuffer>;
}

/** Options for `encryptMulti`; per-recipient fields are set on each `JWEMultiRecipient`. */
export interface JWEMultiEncryptOptions extends StrictOmit<
  JWEEncryptOptions,
  "alg" | "ecdh" | "p2s" | "p2c" | "keyManagementIV"
> {
  /** Shared Unprotected Header, written as `unprotected`. */
  sharedUnprotectedHeader?: Record<string, unknown>;
  /** External AAD (RFC 7516 §5.1); empty means none (RFC 7516 §7.2.1); not a string or bytes is `ERR_INVALID_OPTION`. */
  aad?: Uint8Array<ArrayBuffer> | string;
}

/** A key lookup for `decrypt`: it receives the validated JWE header. */
export type JWEKeyLookup<TReturn = CryptoKey | JWK | JWKSet | string | Uint8Array<ArrayBuffer>> =
  JWKLookupFunction<TReturn, JWEHeaderParameters>;

/** Key material `decryptMulti` accepts, or a function resolving it from the recipient's header. */
export type JWEMultiDecryptKey =
  | CryptoKey
  | JWKSet
  | JWEDecryptJWK
  | string
  | Uint8Array<ArrayBuffer>
  | JWEKeyLookup;

/** Options for `decryptMulti`. */
export interface JWEMultiDecryptOptions<
  Mode extends JOSEPayloadMode = JOSEPayloadMode,
> extends JWEDecryptOptions<Mode> {
  /** Max recipients (else `ERR_JWE_INVALID`), JWK Set candidates per recipient, and PBKDF2 iterations summed over the call. Default: `{ recipients: 16, keyCandidates: 8, pbes2Iterations: 2_400_000 }`. */
  limits?: Pick<JOSELimits, "recipients" | "keyCandidates" | "pbes2Iterations">;
  /** Try only recipients the key could open, else `ERR_JWE_NO_MATCHING_RECIPIENT`; a JWK Set with no candidate is `ERR_JWK_KEY_NOT_FOUND`. Default: `false` (trial in order). */
  strictRecipientMatch?: boolean;
}

/** Result of `decryptMulti`, with the header tiers of the recipient that decrypted. */
export interface JWEMultiDecryptResult<T extends JOSEPayload = JOSEPayload> extends Omit<
  JWEDecryptResult<T>,
  "protectedHeader"
> {
  /** Protected header as integrity protected (`{}` when absent); `alg`/`enc` may sit in the unprotected tiers (RFC 7516 §7.2.1). */
  protectedHeader: JWEHeaderParameters;
  sharedUnprotectedHeader?: JWEHeaderParameters;
  /** Unprotected header of the recipient that decrypted. */
  recipientHeader?: JWEHeaderParameters;
  /** Index into `recipients` of the recipient that decrypted. */
  recipientIndex: number;
}
