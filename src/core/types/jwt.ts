import type { JWSAlgorithm } from "./jws.ts";
import type { KeyManagementAlgorithm } from "./jwk.ts";

import type { JWK_Public } from "./jwk.ts";
import type { Duration, ExpiresIn, MaxTokenAge } from ".";

/** Header Parameters common to JWE and JWS. */
export interface JoseHeaderParameters {
  /** "kid" (Key ID) Header Parameter */
  kid?: string;

  /** "x5t" (X.509 Certificate SHA-1 Thumbprint) Header Parameter */
  x5t?: string;

  /** "x5c" (X.509 Certificate Chain) Header Parameter */
  x5c?: string[];

  /** "x5u" (X.509 URL) Header Parameter */
  x5u?: string;

  /** "jku" (JWK Set URL) Header Parameter */
  jku?: string;

  /** "jwk" (JSON Web Key) Header Parameter */
  jwk?: JWK_Public;

  /** "typ" (Type) Header Parameter */
  typ?: string;

  /** "cty" (Content Type) Header Parameter */
  cty?: string;

  /** "crit" (Critical) Header Parameter */
  crit?: string[];

  [propName: string]: unknown;
}

/** Payload accepted by `sign` and `encrypt`: a string, raw bytes, or a JSON object. */
export type JOSEPayload = string | Uint8Array<ArrayBuffer> | object;

/** How a verified or decrypted payload is decoded: `"json"` object, UTF-8 `"string"`, or raw `"bytes"`. */
export type JOSEPayloadMode = keyof JOSEPayloadTypeMap;

/** The payload type each `JOSEPayloadMode` resolves to. */
export interface JOSEPayloadTypeMap<T = JWTClaims> {
  json: T;
  string: string;
  bytes: Uint8Array<ArrayBuffer>;
}

/** The payload type returned under `Mode`; a union of modes yields the union of payloads. */
export type PayloadOf<Mode extends JOSEPayloadMode, T = JWTClaims> = JOSEPayloadTypeMap<T>[Mode];

/** "cnf" (Confirmation) Claim members (RFC 7800 §3.1), with `jkt` (RFC 9449 §6.1) and `x5t#S256` (RFC 8705 §3.1). */
export interface JWTConfirmation {
  /** The proof-of-possession key as a public JWK */
  "jwk"?: JWK_Public;
  /** The proof-of-possession key as an encrypted JWK, a JWE in compact serialization */
  "jwe"?: string;
  /** A Key ID the recipient resolves out of band */
  "kid"?: string;
  /** A JWK Set URL holding the key, selected by `kid` */
  "jku"?: string;
  /** The RFC 7638 SHA-256 thumbprint of the DPoP public key */
  "jkt"?: string;
  /** The SHA-256 thumbprint of the client certificate, base64url */
  "x5t#S256"?: string;

  [member: string]: unknown;
}

export interface JWTClaims {
  /** "iss" (Issuer) Claim */
  iss?: string;
  /** "sub" (Subject) Claim */
  sub?: string;
  /** "aud" (Audience) Claim */
  aud?: string | string[];
  /** "exp" (Expiration Time) Claim */
  exp?: number;
  /** "nbf" (Not Before) Claim */
  nbf?: number;
  /** "iat" (Issued At) Claim */
  iat?: number;
  /** "jti" (JWT ID) Claim */
  jti?: string;
  /** "cnf" (Confirmation) Claim, the proof-of-possession key; never validated, read by the application */
  cnf?: JWTConfirmation;

  [propName: string]: unknown;
}

export interface JWT<T = JWTClaims> {
  header: JoseHeaderParameters & {
    /** "alg" (Algorithm) Header Parameter */
    alg: JWSAlgorithm | KeyManagementAlgorithm;
  };
  claims: T;
}

/** Per-call work bounds; each entry must be a positive integer, else `ERR_INVALID_OPTION`. */
export interface JOSELimits {
  /** Max `signatures[]` entries in a JWS JSON serialization. @default 16 */
  signatures?: number;
  /** Max `recipients[]` entries in a JWE JSON serialization. @default 16 */
  recipients?: number;
  /** Max JWK Set candidates tried per token after `kid`/`alg`/`use` filtering. @default 8 */
  keyCandidates?: number;
  /** Total PBKDF2 iterations one call may spend across PBES2 attempts. @default 2_400_000 */
  pbes2Iterations?: number;
}

/** Claim expectations, each checked when set; an empty or malformed value is `ERR_INVALID_OPTION`. */
export interface JWTClaimValidationOptions {
  /** Expected "aud" value(s); `aud` is checked only when this is set (RFC 7519 §4.1.3). */
  audience?: string | string[];
  /** Expected "iss" value(s); implies presence. */
  issuer?: string | string[];
  /** Expected "sub" value; implies presence. */
  subject?: string;
  /** Maximum token age from "iat"; implies presence. */
  maxTokenAge?: MaxTokenAge;
  /** Clock skew tolerance for nbf/exp/iat, in seconds or a `Duration`. @default 0 */
  clockTolerance?: number | Duration;
  /** Expected "typ" header, compared as a media type (RFC 7515 §4.1.9); implies presence. */
  typ?: string;
  /** Date used for NumericDate comparisons. @default new Date() */
  currentDate?: Date;
  /** Additional required claim names. */
  requiredClaims?: string[];
  /** `crit` header parameters the caller understands (RFC 7515 §4.1.11, RFC 7516 §4.1.13). */
  recognizedHeaders?: string[];
}

/** Time claims a producer computes; a claim already in the payload is kept as given. */
export interface JWTTimeClaimOptions {
  /** The clock: `iat` when written, and the base of `expiresIn` / `notBeforeIn`. @default new Date() */
  currentDate?: Date;
  /** Writes `iat` on its own: `true` as `currentDate`, a `Date` as that instant; `false` is unset. `exp`/`nbf` options write it either way. */
  issuedAt?: boolean | Date;
  /** Duration from `currentDate` until `exp`; exclusive with `expiresAt`. */
  expiresIn?: ExpiresIn;
  /** Absolute `exp`; exclusive with `expiresIn`. */
  expiresAt?: Date;
  /** Duration from `currentDate` until `nbf` (`0` sets `nbf` to it); exclusive with `notBeforeAt`. */
  notBeforeIn?: ExpiresIn;
  /** Absolute `nbf` (RFC 7519 §4.1.5); exclusive with `notBeforeIn`. */
  notBeforeAt?: Date;
}

/** Options shared by `verify` and `decrypt` (compact and multi). */
export interface JOSEConsumerOptions<
  Mode extends JOSEPayloadMode = JOSEPayloadMode,
> extends JWTClaimValidationOptions {
  /**
   * Admit `oct` entries of a JWK Set as key material; only for application-controlled sets. @default false
   * @deprecated A JWK Set is key material the caller chose to trust, so its `oct` entries count like any other; the option goes away and symmetric entries are admitted without it.
   */
  allowSymmetricJWKSet?: boolean;
  /** Payload decoding mode; a mismatch is `ERR_JWS_INVALID` / `ERR_JWE_INVALID`. @default "json" */
  payload?: Mode;
  /**
   * If true, forces the payload to be returned as a `Uint8Array`.
   *
   * @deprecated Use `payload: "bytes"`. Deprecated in v0.8.0, removed in v0.9.0
   */
  forceUint8Array?: boolean;
  /** `false` skips claim validation; `true` with a non-`"json"` payload is `ERR_INVALID_OPTION`. */
  validateClaims?: boolean;
}
