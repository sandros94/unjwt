import type { JWK_Public } from "./jwk";
import type { MaxTokenAge } from ".";

/** Header Parameters common to JWE and JWS */
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

  /** Any other JWS/JWE Header member. */
  [propName: string]: unknown;
}

/**
 * Payload accepted by {@link sign} and {@link encrypt}.
 *
 * Covers raw strings and bytes for non-JWT use, plus any JSON-serializable
 * object for JWT and generic structured payloads. JWT-specific claim names
 * are not enforced at this level — use {@link JWTClaims} when you want typed
 * claim names and spec-compliant field types.
 */
export type JOSEPayload = string | Uint8Array<ArrayBuffer> | Record<string, unknown>;

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

  /** Any other JWT member. */
  [propName: string]: unknown;
}

export interface JWT<T = JWTClaims> {
  header: JoseHeaderParameters & {
    /** "alg" (Algorithm) Header Parameter */
    alg: string;
  };
  claims: T;
}

export interface JWTClaimValidationOptions {
  /** Expected JWT "aud" (Audience) Claim value(s). Implies presence requirement. */
  audience?: string | string[];
  /** Expected JWT "iss" (Issuer) Claim value(s). Implies presence requirement. */
  issuer?: string | string[];
  /** Expected JWT "sub" (Subject) Claim value. Implies presence requirement. */
  subject?: string;
  /** Maximum token age, from the JWT "iat" (Issued At) Claim value. Implies presence requirement. */
  maxTokenAge?: MaxTokenAge;
  /** Clock skew tolerance (in seconds) for validating time-based claims (nbf/exp/iat). */
  clockTolerance?: number;
  /** Expected JWT "typ" (Type) Header Parameter value. Implies presence requirement. */
  typ?: string;
  /** Date to use when comparing NumericDate claims, defaults to `new Date()`. */
  currentDate?: Date;
  /** Additional required claim names. */
  requiredClaims?: string[];
  /**
   * Critical header parameters that this caller understands and has processed.
   * If the token's `crit` header lists a parameter not present in this list
   * (and not natively understood by the library), verification will fail per
   * RFC 7515 §4.1.11 / RFC 7516 §4.1.13.
   */
  recognizedHeaders?: string[];
}
