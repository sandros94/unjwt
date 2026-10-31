import type { JWSAlgorithm } from "./jws.ts";
import type { KeyManagementAlgorithm } from "./jwk.ts";

import type { JWK_Public } from "./jwk.ts";
import type { Duration, ExpiresIn, MaxTokenAge } from ".";

/** Header Parameters common to JWS and JWE (RFC 7515 §4.1, RFC 7516 §4.1). */
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

/** A payload for `sign` and `encrypt`: a string, raw bytes, or an object serialized as JSON. */
export type JOSEPayload = string | Uint8Array<ArrayBuffer> | object;

/** How a verified or decrypted payload is returned: a `"json"` object, a UTF-8 `"string"`, or raw `"bytes"`. */
export type JOSEPayloadMode = keyof JOSEPayloadTypeMap;

/** The payload type each `JOSEPayloadMode` resolves to. */
export interface JOSEPayloadTypeMap<T = JWTClaims> {
  json: T;
  string: string;
  bytes: Uint8Array<ArrayBuffer>;
}

/** The payload type returned under `Mode`. A union of modes gives the union of their payloads. */
export type PayloadOf<Mode extends JOSEPayloadMode, T = JWTClaims> = JOSEPayloadTypeMap<T>[Mode];

/** "cnf" (Confirmation) Claim members (RFC 7800 §3.1), with `jkt` (RFC 9449 §6.1) and `x5t#S256` (RFC 8705 §3.1). */
export interface JWTConfirmation {
  /** The proof-of-possession key as a public JWK. `sign` and `encrypt` throw `ERR_JWT_CLAIM_INVALID` for a private or malformed one. */
  "jwk"?: JWK_Public;
  /** The proof-of-possession key as an encrypted JWK, in JWE Compact Serialization. */
  "jwe"?: string;
  /** The Key ID of a proof-of-possession key the recipient already holds. */
  "kid"?: string;
  /** The URL of a JWK Set that holds the key, selected by `kid`. */
  "jku"?: string;
  /** The RFC 7638 SHA-256 thumbprint of the DPoP public key. */
  "jkt"?: string;
  /** The base64url SHA-256 thumbprint of the client certificate. */
  "x5t#S256"?: string;

  [member: string]: unknown;
}

/** JWT claims (RFC 7519 §4.1). `verify` and `decrypt` check the registered ones against {@link JWTClaimValidationOptions}. */
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
  /** "cnf" (Confirmation) Claim: the proof-of-possession key (RFC 7800). `verify` and `decrypt` do not check it. */
  cnf?: JWTConfirmation;

  [propName: string]: unknown;
}

/** A decoded JWT: its JOSE header and its claims. */
export interface JWT<T = JWTClaims> {
  header: JoseHeaderParameters & {
    /** "alg" (Algorithm) Header Parameter */
    alg: JWSAlgorithm | KeyManagementAlgorithm;
  };
  claims: T;
}

/** Work limits for one call. Each entry is a positive integer, else the call throws `ERR_INVALID_OPTION`. */
export interface JOSELimits {
  /** Max `signatures[]` entries in a JWS JSON Serialization. More throws `ERR_JWS_INVALID`. @default 16 */
  signatures?: number;
  /** Max `recipients[]` entries in a JWE JSON Serialization. More throws `ERR_JWE_INVALID`. @default 16 */
  recipients?: number;
  /** Max JWK Set keys tried per token, after filtering by `kid`, `alg` and `use`. More throws `ERR_JWK_KEY_NOT_FOUND`. @default 8 */
  keyCandidates?: number;
  /** Max key trials over all entries of one `verifyMulti`, `verifyMultiAll` or `decryptMulti` call. One trial is one signature check or unwrap with one key. More throws `ERR_JWK_KEY_NOT_FOUND`. @default 16 */
  keyAttempts?: number;
  /** Max PBKDF2 iterations over all PBES2 attempts of one call. More throws `ERR_JWE_INVALID`. @default 2_400_000 */
  pbes2Iterations?: number;
}

/** Claim expectations, each checked when set. A malformed value throws `ERR_INVALID_OPTION`. */
export interface JWTClaimValidationOptions {
  /** Accepted `aud` values. The token passes when its `aud` holds one of them (RFC 7519 §4.1.3). Implies presence. */
  audience?: string | string[];
  /** Accepted `iss` values. Implies presence. */
  issuer?: string | string[];
  /** Expected `sub` value. Implies presence. */
  subject?: string;
  /** Oldest accepted `iat`, counted back from `currentDate`. Older throws `ERR_JWT_EXPIRED`. Implies `iat` presence. */
  maxTokenAge?: MaxTokenAge;
  /** Clock skew allowed on `exp`, `nbf` and `iat`: non-negative seconds or a `Duration`. @default 0 */
  clockTolerance?: number | Duration;
  /** Expected `typ` of the protected header, compared as a media type (RFC 7515 §4.1.9). A missing or different `typ` throws `ERR_JWS_INVALID` or `ERR_JWE_INVALID`. */
  typ?: string;
  /** The time the claims are checked against. @default new Date() */
  currentDate?: Date;
  /** Claim names the token must contain, else `ERR_JWT_CLAIM_MISSING`. */
  requiredClaims?: string[];
  /** `crit` Header Parameters the caller understands (RFC 7515 §4.1.11, RFC 7516 §4.1.13). Any other `crit` entry throws. */
  recognizedHeaders?: string[];
}

/** Time claims `sign` and `encrypt` write into an object payload. A claim already in the payload is kept. Any of these options with a string or bytes payload throws `ERR_INVALID_OPTION`. */
export interface JWTTimeClaimOptions {
  /** The current time: the written `iat`, and the base of `expiresIn` and `notBeforeIn`. @default new Date() */
  currentDate?: Date;
  /** Writes `iat`: `true` as `currentDate`, a `Date` as that instant. Any `exp` or `nbf` option writes `iat` too, even when this is `false`. */
  issuedAt?: boolean | Date;
  /** Sets `exp` to `currentDate` plus this positive duration. Setting `expiresAt` too throws `ERR_JWT_CLAIM_INVALID`. */
  expiresIn?: ExpiresIn;
  /** Sets `exp` to this instant. Setting `expiresIn` too throws `ERR_JWT_CLAIM_INVALID`. */
  expiresAt?: Date;
  /** Sets `nbf` to `currentDate` plus this duration, zero or more. Setting `notBeforeAt` too throws `ERR_JWT_CLAIM_INVALID`. */
  notBeforeIn?: ExpiresIn;
  /** Sets `nbf` to this instant (RFC 7519 §4.1.5). Setting `notBeforeIn` too throws `ERR_JWT_CLAIM_INVALID`. */
  notBeforeAt?: Date;
}

/** Options shared by `verify`, `decrypt` and their multi variants. */
export interface JOSEConsumerOptions<
  Mode extends JOSEPayloadMode = JOSEPayloadMode,
> extends JWTClaimValidationOptions {
  /** How the payload is returned. Under `"json"`, a payload that is not a JSON object throws `ERR_JWS_INVALID` or `ERR_JWE_INVALID`. @default "json" */
  payload?: Mode;
  /**
   * `false` skips claim validation. Claims are checked only under `payload: "json"`.
   * `true` with another payload, or a claim option (`audience`, `issuer`, `subject`, `maxTokenAge`, `requiredClaims`) while claims go unchecked, throws `ERR_INVALID_OPTION`.
   * @default true
   */
  validateClaims?: boolean;
}
