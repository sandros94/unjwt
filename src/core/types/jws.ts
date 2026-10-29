import type { JWTError } from "../../error.ts";
import type {
  JoseHeaderParameters,
  JOSELimits,
  JOSEPayload,
  JOSEConsumerOptions,
  JOSEPayloadMode,
  JWTTimeClaimOptions,
} from "./jwt.ts";
import type {
  JWK_oct,
  JWK_EC_Public,
  JWK_EC_Private,
  JWK_OKP_Public,
  JWK_OKP_Private,
  JWK_RSA_Public,
  JWK_RSA_Private,
  JWK_HMAC,
  JWK_RSA_SIGN,
  JWK_RSA_PSS,
  JWK_ECDSA,
  JWK_OKP_SIGN,
  JWK,
  JWKSet,
  JWKLookupFunction,
} from "./jwk.ts";
import type { StrictOmit } from "../../utils/types.ts";

/** A JWS signing algorithm (RFC 7518 §3, RFC 8037 §3.1). */
export type JWSAlgorithm = JWK_HMAC | JWK_RSA_SIGN | JWK_RSA_PSS | JWK_ECDSA | JWK_OKP_SIGN;

/** A key lookup for `verify` and the multi variants. It receives `{ header, token }`: the decoded JWS header and the token. */
export type JWSKeyLookup<TReturn = CryptoKey | JWK | JWKSet | string | Uint8Array<ArrayBuffer>> =
  JWKLookupFunction<TReturn, JWSHeaderParameters>;

/** The JWS algorithms that name their digest (`*256`, `*384`, `*512`). `EdDSA` and `Ed25519` do not. */
export type JWSHashedAlgorithm = Exclude<JWSAlgorithm, JWK_OKP_SIGN>;

/** The asymmetric private JWKs that can sign. */
export type JWSAsymmetricPrivateJWK =
  | JWK_RSA_Private<JWK_RSA_SIGN | JWK_RSA_PSS>
  | JWK_EC_Private<JWK_ECDSA>
  | JWK_OKP_Private<JWK_OKP_SIGN>;

/** The asymmetric public JWKs that can verify. */
export type JWSAsymmetricPublicJWK =
  | JWK_RSA_Public<JWK_RSA_SIGN | JWK_RSA_PSS>
  | JWK_EC_Public<JWK_ECDSA>
  | JWK_OKP_Public<JWK_OKP_SIGN>;

/** The JWKs `sign` accepts. A JWK whose `alg` is not a signing algorithm is a type error. */
export type JWSSignJWK = JWK_oct<JWK_HMAC> | JWSAsymmetricPrivateJWK;

/** The JWKs `verify` accepts. A JWK whose `alg` is not a signing algorithm is a type error. */
export type JWSVerifyJWK = JWK_oct<JWK_HMAC> | JWSAsymmetricPublicJWK;

/** JWS Header Parameters (RFC 7515 §4.1). Other members are allowed. */
export interface JWSHeaderParameters extends JoseHeaderParameters {
  /** "alg" (Algorithm) Header Parameter */
  alg?: JWSAlgorithm;

  /** `false` signs the payload unencoded (RFC 7797). Allowed in the protected header only. @default true */
  b64?: boolean;
}

/** A JWS Protected Header, which always holds `alg`. */
export interface JWSProtectedHeader extends JWSHeaderParameters {
  alg: JWSAlgorithm;
}

/** Options for `sign`. */
export interface JWSSignOptions extends JWTTimeClaimOptions {
  /** The signing algorithm. Defaults to the JWK's `alg`, else to the one an EC or Ed25519 JWK's curve names. A key that names none throws `ERR_JWS_ALG_MISSING`. */
  alg?: JWSAlgorithm;

  /**
   * Protected Header Parameters to add. `alg` cannot be set here.
   * `kid` defaults to the JWK's `kid`. `typ` defaults to `"JWT"` for an object payload.
   * A `jwk` member must be a public JWK, else `ERR_INVALID_OPTION`.
   */
  protectedHeader?: StrictOmit<JWSHeaderParameters, "alg"> & { alg?: never };
}

/** The result of `verify`. */
export interface JWSVerifyResult<T extends JOSEPayload = JOSEPayload> {
  payload: T;
  protectedHeader: JWSProtectedHeader;
}

/** Options for `verify`. `Mode` is the literal of the `payload` option. */
export interface JWSVerifyOptions<
  Mode extends JOSEPayloadMode = JOSEPayloadMode,
> extends JOSEConsumerOptions<Mode> {
  /**
   * The accepted header `alg` values, else `ERR_JWS_ALG_NOT_ALLOWED`.
   * When omitted, the key's JWK `alg` is the policy, else the algorithms its type serves.
   * Pass it for raw bytes and for an `oct` or RSA JWK without `alg`.
   */
  algorithms?: JWSAlgorithm[];
  /** Max JWK Set keys tried per token. More throws `ERR_JWK_KEY_NOT_FOUND`. @default { keyCandidates: 8 } */
  limits?: Pick<JOSELimits, "keyCandidates">;
}

/** JWS Flattened JSON Serialization (RFC 7515 §7.2.2). */
export interface JWSFlattenedSerialization {
  /** The JWS Payload, base64url-encoded unless `b64` is `false`. */
  payload: string;
  /** The base64url-encoded JWS Protected Header. */
  protected?: string;
  /** The JWS Unprotected Header, which the signature does not cover. */
  header?: JWSHeaderParameters;
  /** The base64url-encoded signature. */
  signature: string;
}

/** JWS General JSON Serialization (RFC 7515 §7.2.1). */
export interface JWSGeneralSerialization extends Omit<
  JWSFlattenedSerialization,
  "protected" | "header" | "signature"
> {
  /** One entry per signer. */
  signatures: JWSGeneralSignature[];
}

/** One entry of `JWSGeneralSerialization.signatures`. */
export type JWSGeneralSignature = Pick<
  JWSFlattenedSerialization,
  "protected" | "header" | "signature"
>;

/** One signer of `signMulti`. */
export interface JWSMultiSigner {
  /** The signing key. A JWK's `kid` is written to the protected header. For a `CryptoKey`, set `kid` in `protectedHeader`. */
  key: JWSSignJWK | CryptoKey;
  /** The signing algorithm. Defaults to the one the key names, an EC or Ed25519 JWK's curve included, else `ERR_JWS_SIGNER_ALG_INFERENCE`. */
  alg?: JWSAlgorithm;
  /** This signer's Protected Header Parameters. `b64` must match across signers (RFC 7797 §3). `typ` defaults to `"JWT"` for an object payload. */
  protectedHeader?: StrictOmit<JWSHeaderParameters, "alg"> & { alg?: never };
  /** This signer's JWS Unprotected Header. It cannot hold `crit`, `b64`, or a name the protected header holds. */
  unprotectedHeader?: JWSHeaderParameters;
}

/** Options for `signMulti`. `alg` and `protectedHeader` are set per signer. */
export interface JWSMultiSignOptions extends StrictOmit<
  JWSSignOptions,
  "alg" | "protectedHeader"
> {}

/** Options for `verifyMulti`. */
export interface JWSMultiVerifyOptions<
  Mode extends JOSEPayloadMode = JOSEPayloadMode,
> extends JWSVerifyOptions<Mode> {
  /**
   * Max `signatures[]` entries (more throws `ERR_JWS_INVALID`), JWK Set keys per signature, and key trials over the call.
   * Too many keys or trials throws `ERR_JWK_KEY_NOT_FOUND`.
   * @default { signatures: 16, keyCandidates: 8, keyAttempts: 16 }
   */
  limits?: Pick<JOSELimits, "signatures" | "keyCandidates" | "keyAttempts">;
  /** Skips signatures whose `kid` or `alg` the key cannot serve. No signature left throws `ERR_JWS_NO_MATCHING_SIGNER`. @default false */
  strictSignerMatch?: boolean;
}

/** The result of `verifyMulti`: the first signature that verified. */
export interface JWSMultiVerifyResult<T extends JOSEPayload = JOSEPayload> extends Omit<
  JWSVerifyResult<T>,
  "protectedHeader"
> {
  /** The verified signature's protected header, as signed. `alg` can be in `signerHeader` instead (RFC 7515 §7.2.1). */
  protectedHeader: JWSHeaderParameters;
  /** The verified signature's unprotected header. */
  signerHeader?: JWSHeaderParameters;
  /** The verified signature's index in `signatures`. */
  signerIndex: number;
}

/** Options for `verifyMultiAll`. */
export interface JWSMultiVerifyAllOptions<
  Mode extends JOSEPayloadMode = JOSEPayloadMode,
> extends StrictOmit<JWSMultiVerifyOptions<Mode>, "strictSignerMatch"> {}

/** One signature's outcome in `verifyMultiAll`. `verified: false` holds the `error`. */
export type JWSMultiVerifyOutcome<T extends JOSEPayload = JOSEPayload> =
  | {
      signerIndex: number;
      verified: true;
      payload: T;
      protectedHeader: JWSHeaderParameters;
      signerHeader?: JWSHeaderParameters;
    }
  | {
      signerIndex: number;
      verified: false;
      error: JWTError;
      protectedHeader?: JWSHeaderParameters;
      signerHeader?: JWSHeaderParameters;
    };
