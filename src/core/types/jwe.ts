import type {
  JoseHeaderParameters,
  JOSELimits,
  JOSEPayload,
  JOSEConsumerOptions,
  JOSEPayloadMode,
  JWTTimeClaimOptions,
} from "./jwt.ts";
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
} from "./jwk.ts";
import type { StrictOmit } from "../../utils/types.ts";

/** The `oct` JWK `alg` values a JWE key accepts: all but HMAC. */
type _JWEOctAlg = JWK_AES_KW | JWK_AES_GCM | JWK_AES_GCM_KW | JWK_AES_CBC_HMAC | JWK_PBES2 | "dir";

/** The asymmetric public JWKs that can encrypt: RSA-OAEP or ECDH-ES. */
export type JWEAsymmetricPublicJWK =
  | JWK_RSA_Public<JWK_RSA_ENC>
  | JWK_EC_Public<JWK_ECDH_ES>
  | JWK_OKP_Public<JWK_ECDH_ES>;

/** The asymmetric private JWKs that can decrypt: RSA-OAEP or ECDH-ES. */
export type JWEAsymmetricPrivateJWK =
  | JWK_RSA_Private<JWK_RSA_ENC>
  | JWK_EC_Private<JWK_ECDH_ES>
  | JWK_OKP_Private<JWK_ECDH_ES>;

/** The JWKs `encrypt` accepts. A JWK whose `alg` is not a JWE algorithm is a type error. */
export type JWEEncryptJWK = JWK_oct<_JWEOctAlg> | JWEAsymmetricPublicJWK;

/** The JWKs `decrypt` accepts. A JWK whose `alg` is not a JWE algorithm is a type error. */
export type JWEDecryptJWK = JWK_oct<_JWEOctAlg> | JWEAsymmetricPrivateJWK;

/** JWE Header Parameters (RFC 7516 §4.1, RFC 7518 §4.6 to §4.8). Other members are allowed. */
export interface JWEHeaderParameters extends JoseHeaderParameters {
  /** "alg" (Key Management Algorithm) Header Parameter */
  alg?: KeyManagementAlgorithm;
  /** "enc" (Content Encryption Algorithm) Header Parameter */
  enc?: ContentEncryptionAlgorithm;
  /** "p2c" (PBES2 Count) Header Parameter */
  p2c?: number;
  /** "p2s" (PBES2 Salt Input) Header Parameter, base64url */
  p2s?: string;
  /** "iv" (AES-GCMKW Initialization Vector) Header Parameter, base64url */
  iv?: string;
  /** "tag" (AES-GCMKW Authentication Tag) Header Parameter, base64url */
  tag?: string;
  /** "epk" (ECDH-ES Ephemeral Public Key) Header Parameter */
  epk?: JWK_EC_Public | JWK_OKP_Public;
  /** "apu" (ECDH-ES Agreement PartyUInfo) Header Parameter, base64url */
  apu?: string;
  /** "apv" (ECDH-ES Agreement PartyVInfo) Header Parameter, base64url */
  apv?: string;
  /** Compression (RFC 7516 §4.1.3) is not supported. Decrypting a token with `zip` throws `ERR_JWE_INVALID`. */
  zip?: never;

  [propName: string]: unknown;
}

/** Key management inputs as bytes and keys, before they are written to the header. */
export interface JWEKeyManagementHeaderParameters {
  apu?: Uint8Array<ArrayBuffer>;
  apv?: Uint8Array<ArrayBuffer>;
  p2c?: number;
  p2s?: Uint8Array<ArrayBuffer>;
  iv?: Uint8Array<ArrayBuffer>;
  epk?: CryptoKey | JWK_EC_Public | JWK_OKP_Public;
  epkPrivateKey?: CryptoKey | JWK_EC_Private | JWK_OKP_Private;
}

/** The Header Parameters unjwt writes, which no caller header can set (RFC 7516 §4.1, RFC 7518 §4.6 to §4.8). */
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

/** Options for `encrypt`. */
export interface JWEEncryptOptions extends JWTTimeClaimOptions {
  /** The key management algorithm. Without it, a password uses `PBES2-HS256+A128KW`, an `oct` JWK whose `alg` is an `enc` uses `dir`, and any other JWK uses its `alg`. */
  alg?: KeyManagementAlgorithm;
  /** The content encryption algorithm. Without it, the JWK's `enc` applies, else `A256GCM`. For `dir`, the CEK JWK's `alg` or `enc` applies, else `ERR_JWE_ENC_MISSING`. */
  enc?: ContentEncryptionAlgorithm;
  /**
   * Protected Header Parameters to add. `kid` defaults to the JWK's `kid`. `typ` defaults to `"JWT"` for an object payload.
   * `cty` is never added. Set it to `"JWT"` for a nested JWT (RFC 7519 §5.2). A `zip` member throws `ERR_INVALID_OPTION`.
   */
  protectedHeader?: StrictOmit<JWEHeaderParameters, JWELibraryHeaderName>;

  /** The AES-GCMKW key wrapping IV. Random when omitted. */
  keyManagementIV?: Uint8Array<ArrayBuffer>;
  /** The PBES2 salt (`p2s`), at least 8 octets. Default: 16 random bytes. */
  p2s?: Uint8Array<ArrayBuffer>;
  /** The PBES2 iteration count (`p2c`), from `1000` to `600_000`. Default: `600_000`. */
  p2c?: number;
  /** ECDH-ES inputs: the ephemeral key (generated when omitted), and `partyUInfo` and `partyVInfo` of at most 1024 bytes each. */
  ecdh?: {
    ephemeralKey?: ECDHEphemeralKeyInput;
    partyUInfo?: Uint8Array<ArrayBuffer>;
    partyVInfo?: Uint8Array<ArrayBuffer>;
  };

  /** The Content Encryption Key, sized for `enc`. Random when omitted. */
  cek?: Uint8Array<ArrayBuffer>;

  /** The content encryption IV, sized for `enc`. Random when omitted. */
  contentEncryptionIV?: Uint8Array<ArrayBuffer>;
}

/** Options for `decrypt`. `Mode` is the literal of the `payload` option, which sets the returned payload type. */
export interface JWEDecryptOptions<
  Mode extends JOSEPayloadMode = JOSEPayloadMode,
> extends JOSEConsumerOptions<Mode> {
  /**
   * The accepted header `alg` values, else `ERR_JWE_ALG_NOT_ALLOWED`.
   * When omitted, the key's JWK `alg` is the policy, else the algorithms its type serves. A password accepts the three PBES2 algorithms.
   * Pass it for raw bytes and for a JWK whose type does not narrow the algorithm.
   */
  algorithms?: KeyManagementAlgorithm[];
  /** Max JWK Set keys per token (more throws `ERR_JWK_KEY_NOT_FOUND`) and PBKDF2 iterations per call (more throws `ERR_JWE_INVALID`). Default: `{ keyCandidates: 8, pbes2Iterations: 2_400_000 }`. */
  limits?: Pick<JOSELimits, "keyCandidates" | "pbes2Iterations">;
  /** The accepted header `enc` values, else `ERR_JWE_ALG_NOT_ALLOWED`. Any supported `enc` when omitted. */
  encryptionAlgorithms?: ContentEncryptionAlgorithm[];
  /** The algorithm an AES-GCM CEK is imported as. Default: AES-GCM. */
  unwrappedKeyAlgorithm?: Parameters<typeof crypto.subtle.importKey>[2];

  /** The usages of an imported CEK. Default: `["decrypt"]`. */
  keyUsage?: KeyUsage[];
  /** Makes an imported CEK extractable. `returnCek` needs it. Default: `true`. */
  extractable?: boolean;
  /** Adds the CEK and the AAD to the result. Default: `false`. */
  returnCek?: boolean;
  /** The lowest PBES2 `p2c` accepted, else `ERR_JWE_INVALID` (RFC 7518 §4.8.1.2). Default: `1000`. */
  minIterations?: number;
  /** The highest PBES2 `p2c` accepted, else `ERR_JWE_INVALID`. Default: `600_000`. */
  maxIterations?: number;
}

/** The protected header `decrypt` returns, which always holds `alg` and `enc`. */
export interface JWEProtectedHeader extends JWEHeaderParameters {
  alg: KeyManagementAlgorithm;
  enc: ContentEncryptionAlgorithm;
}

/** The result of `decrypt`. */
export interface JWEDecryptResult<T extends JOSEPayload = JOSEPayload> {
  payload: T;
  protectedHeader: JWEProtectedHeader;
  /** The CEK bytes. Set only with `returnCek`. */
  cek?: Uint8Array<ArrayBuffer>;
  /** The AAD that authenticates the content. Set only with `returnCek`. */
  aad?: Uint8Array<ArrayBuffer>;
}

/** A JWE Flattened JSON Serialization (RFC 7516 §7.2.2). String members are base64url. */
export interface JWEFlattenedSerialization {
  header?: JWEHeaderParameters;
  encrypted_key?: string;
  /** The JWE Protected Header, covered by the AAD. */
  protected?: string;
  /** The JWE Shared Unprotected Header, not covered by the AAD. */
  unprotected?: JWEHeaderParameters;
  /** The JWE AAD supplied by the producer. */
  aad?: string;
  iv: string;
  ciphertext: string;
  tag: string;
}

/** A JWE General JSON Serialization (RFC 7516 §7.2.1), as `encryptMulti` returns. */
export interface JWEGeneralSerialization extends Omit<
  JWEFlattenedSerialization,
  "encrypted_key" | "header"
> {
  recipients: JWEGeneralRecipient[];
}

/** One recipient of a JWE General JSON Serialization. */
export interface JWEGeneralRecipient {
  /** The JWE Per-Recipient Unprotected Header, not covered by the AAD. */
  header?: JWEHeaderParameters;
  encrypted_key?: string;
}

/** One recipient of `encryptMulti`. `alg` is the JWK's `alg`, else `ERR_JWE_RECIPIENT_ALG_INFERENCE`. */
export interface JWEMultiRecipient {
  /** The recipient's JWK. Its `kid` is written to the recipient header. */
  key: JWEEncryptJWK;
  /** Per-Recipient Unprotected Header Parameters to add (RFC 7516 §7.2.1). They override the JWK's `kid`. */
  header?: StrictOmit<JWEHeaderParameters, JWELibraryHeaderName>;
  /** ECDH-ES inputs for this recipient, as on `encrypt`. */
  ecdh?: JWEEncryptOptions["ecdh"];
  /** The PBES2 salt, at least 8 octets. Default: 16 random bytes. */
  p2s?: Uint8Array<ArrayBuffer>;
  /** The PBES2 iteration count, from `1000` to `600_000`. Default: `600_000`. */
  p2c?: number;
  /** The AES-GCMKW key wrapping IV. Random when omitted. */
  keyManagementIV?: Uint8Array<ArrayBuffer>;
}

/** Options for `encryptMulti`. Key management fields are set on each `JWEMultiRecipient`. */
export interface JWEMultiEncryptOptions extends StrictOmit<
  JWEEncryptOptions,
  "alg" | "ecdh" | "p2s" | "p2c" | "keyManagementIV"
> {
  /** The JWE Shared Unprotected Header, written as `unprotected`. It cannot hold `crit` or `zip`. */
  sharedUnprotectedHeader?: Record<string, unknown>;
  /** The JWE AAD (RFC 7516 §5.1), as UTF-8 text or bytes. An empty value writes no `aad` member (RFC 7516 §7.2.1). Any other type throws `ERR_INVALID_OPTION`. */
  aad?: Uint8Array<ArrayBuffer> | string;
}

/** A key lookup for `decrypt` and `decryptMulti`. It receives `{ header, token }`: the decoded JWE header and the token. */
export type JWEKeyLookup<TReturn = CryptoKey | JWK | JWKSet | string | Uint8Array<ArrayBuffer>> =
  JWKLookupFunction<TReturn, JWEHeaderParameters>;

/** The key `decryptMulti` accepts, or a lookup that returns it from a recipient's header. */
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
  /**
   * Max `recipients[]` entries (more throws `ERR_JWE_INVALID`), JWK Set keys per recipient, key trials over the call, and PBKDF2 iterations over the call.
   * Too many keys or trials throws `ERR_JWK_KEY_NOT_FOUND`.
   * Default: `{ recipients: 16, keyCandidates: 8, keyAttempts: 16, pbes2Iterations: 2_400_000 }`.
   */
  limits?: Pick<JOSELimits, "recipients" | "keyCandidates" | "keyAttempts" | "pbes2Iterations">;
  /** Skips recipients whose `kid` or `alg` the key cannot serve. No recipient left throws `ERR_JWE_NO_MATCHING_RECIPIENT`. Default: `false`, which tries every recipient in order. */
  strictRecipientMatch?: boolean;
}

/** The result of `decryptMulti`, with the headers of the recipient that decrypted. */
export interface JWEMultiDecryptResult<T extends JOSEPayload = JOSEPayload> extends Omit<
  JWEDecryptResult<T>,
  "protectedHeader"
> {
  /** The protected header as encrypted, `{}` when absent. `alg` and `enc` can be in the unprotected headers instead (RFC 7516 §7.2.1). */
  protectedHeader: JWEHeaderParameters;
  /** The JWE Shared Unprotected Header, when present. */
  sharedUnprotectedHeader?: JWEHeaderParameters;
  /** The unprotected header of the recipient that decrypted. */
  recipientHeader?: JWEHeaderParameters;
  /** The index in `recipients` of the recipient that decrypted. */
  recipientIndex: number;
}
