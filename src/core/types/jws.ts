import type { JWTError } from "../error";
import type {
  JoseHeaderParameters,
  JOSELimits,
  JOSEPayload,
  JOSEConsumerOptions,
  JOSEPayloadMode,
  JWTTimeClaimOptions,
} from "./jwt";
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
} from "./jwk";
import type { StrictOmit } from "../utils/types";

/** JWS Signing Algorithm Identifier. */
export type JWSAlgorithm = JWK_HMAC | JWK_RSA_SIGN | JWK_RSA_PSS | JWK_ECDSA | JWK_OKP_SIGN;

/** A key lookup for `verify`: it receives the validated JWS header. */
export type JWSKeyLookup<TReturn = CryptoKey | JWK | JWKSet | string | Uint8Array<ArrayBuffer>> =
  JWKLookupFunction<TReturn, JWSHeaderParameters>;

/** JWS algorithms that name their digest (`*256`/`*384`/`*512`); EdDSA does not. */
export type JWSHashedAlgorithm = Exclude<JWSAlgorithm, JWK_OKP_SIGN>;

/** Asymmetric private JWKs admissible as a signing key. */
export type JWSAsymmetricPrivateJWK =
  | JWK_RSA_Private<JWK_RSA_SIGN | JWK_RSA_PSS>
  | JWK_EC_Private<JWK_ECDSA>
  | JWK_OKP_Private<JWK_OKP_SIGN>;

/** Asymmetric public JWKs admissible as a verification key. */
export type JWSAsymmetricPublicJWK =
  | JWK_RSA_Public<JWK_RSA_SIGN | JWK_RSA_PSS>
  | JWK_EC_Public<JWK_ECDSA>
  | JWK_OKP_Public<JWK_OKP_SIGN>;

/** JWKs admissible as a `sign` key; a non-signing `alg` is a type error. */
export type JWSSignJWK = JWK_oct<JWK_HMAC> | JWSAsymmetricPrivateJWK;

/** JWKs admissible as a `verify` key; a non-signing `alg` is a type error. */
export type JWSVerifyJWK = JWK_oct<JWK_HMAC> | JWSAsymmetricPublicJWK;

/** Recognized JWS Header Parameters; other members may be present. */
export interface JWSHeaderParameters extends JoseHeaderParameters {
  /** JWS "alg" (Algorithm) Header Parameter */
  alg?: JWSAlgorithm;

  /** `false` signs the payload unencoded (RFC 7797). @default true */
  b64?: boolean;
}

/** JWS Protected Header */
export interface JWSProtectedHeader extends JWSHeaderParameters {
  alg: JWSAlgorithm;
}

/** Options for `sign`. */
export interface JWSSignOptions extends JWTTimeClaimOptions {
  /** JWS algorithm; inferred from the key when omitted. */
  alg?: JWSAlgorithm;

  /** Extra protected header parameters; `alg` cannot be set, `typ` defaults to `"JWT"` for an object payload. */
  protectedHeader?: StrictOmit<JWSHeaderParameters, "alg"> & { alg?: never };
}

/** Result of JWS verification. */
export interface JWSVerifyResult<T extends JOSEPayload = JOSEPayload> {
  payload: T;
  protectedHeader: JWSProtectedHeader;
}

/** Options for `verify`; `Mode` is the `payload` option's literal. */
export interface JWSVerifyOptions<
  Mode extends JOSEPayloadMode = JOSEPayloadMode,
> extends JOSEConsumerOptions<Mode> {
  /** Allowed `alg` values; inferred from the key when omitted, required for raw secrets, alg-less JWKs and resolvers. */
  algorithms?: JWSAlgorithm[];
  /** Max JWK Set candidates per token; more is `ERR_JWK_KEY_NOT_FOUND`. @default { keyCandidates: 8 } */
  limits?: Pick<JOSELimits, "keyCandidates">;
}

/** JWS Flattened JSON Serialization (RFC 7515 §7.2.2). */
export interface JWSFlattenedSerialization {
  /** The JWS Payload; base64url-encoded unless `b64: false`. */
  payload: string;
  /** Base64url-encoded JWS Protected Header. */
  protected?: string;
  /** JWS Unprotected Header (not signed). */
  header?: JWSHeaderParameters;
  /** Base64url-encoded signature. */
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

/** A single entry of `JWSGeneralSerialization.signatures`. */
export type JWSGeneralSignature = Pick<
  JWSFlattenedSerialization,
  "protected" | "header" | "signature"
>;

/** One signer passed to `signMulti`. */
export interface JWSMultiSigner {
  /** Signing key; `kid` is taken from a JWK, a `CryptoKey` must set it in `protectedHeader`. */
  key: JWSSignJWK | CryptoKey;
  /** JWS algorithm; inferred from the key when possible, else `ERR_JWS_SIGNER_ALG_INFERENCE`. */
  alg?: JWSAlgorithm;
  /** Per-signer protected header; `b64` must match across signers (RFC 7797 §3), `typ` defaults to `"JWT"`. */
  protectedHeader?: StrictOmit<JWSHeaderParameters, "alg"> & { alg?: never };
  /** Per-signer JWS Unprotected Header (not signed). */
  unprotectedHeader?: JWSHeaderParameters;
}

/** Options for `signMulti`; `alg` and `protectedHeader` are set per signer. */
export interface JWSMultiSignOptions extends StrictOmit<
  JWSSignOptions,
  "alg" | "protectedHeader"
> {}

/** Options for `verifyMulti`. */
export interface JWSMultiVerifyOptions<
  Mode extends JOSEPayloadMode = JOSEPayloadMode,
> extends JWSVerifyOptions<Mode> {
  /** Max `signatures[]` (more is `ERR_JWS_INVALID`) and JWK Set candidates per signature. @default { signatures: 16, keyCandidates: 8 } */
  limits?: Pick<JOSELimits, "signatures" | "keyCandidates">;
  /** Try only signatures the key could have produced (by `kid`, `kty`, curve, length), else `ERR_JWS_NO_MATCHING_SIGNER`. @default false */
  strictSignerMatch?: boolean;
}

/** Result of `verifyMulti`. */
export interface JWSMultiVerifyResult<T extends JOSEPayload = JOSEPayload> extends Omit<
  JWSVerifyResult<T>,
  "protectedHeader"
> {
  /** Protected header of the verified signature as signed; `alg` may sit in `signerHeader` (RFC 7515 §7.2.1). */
  protectedHeader: JWSHeaderParameters;
  /** Unprotected header of the verified signature. */
  signerHeader?: JWSHeaderParameters;
  /** Index into `signatures` of the verified signature. */
  signerIndex: number;
}

/** Options for `verifyMultiAll`. */
export interface JWSMultiVerifyAllOptions<
  Mode extends JOSEPayloadMode = JOSEPayloadMode,
> extends StrictOmit<JWSMultiVerifyOptions<Mode>, "strictSignerMatch"> {}

/** Per-signature outcome of `verifyMultiAll`, discriminated by `verified`; failures carry `error`. */
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
