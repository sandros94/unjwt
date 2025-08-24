import type { JWK_RSA_Public } from "./jwk";

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
  jwk?: JWK_RSA_Public;

  /** "typ" (Type) Header Parameter */
  typ?: string;

  /** "cty" (Content Type) Header Parameter */
  cty?: string;

  /** "crit" (Critical) Header Parameter */
  crit?: string[];

  /** Any other JWS/JWE Header member. */
  [propName: string]: unknown;
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
  /** Maximum token age in seconds, from the JWT "iat" (Issued At) Claim value. Implies presence requirement. */
  maxTokenAge?: number;
  /** Clock skew tolerance (in seconds) for validating time-based claims (nbf/exp/iat). */
  clockTolerance?: number;
  /** Expected JWT "typ" (Type) Header Parameter value. Implies presence requirement. */
  typ?: string;
  /** Date to use when comparing NumericDate claims, defaults to `new Date()`. */
  currentDate?: Date;
  /** Additional required claim names. */
  requiredClaims?: string[];
  /** List of critical header parameters that must be understood and processed. */
  requiredHeaders?: string[];

  /**
   * Critical Header Parameters to be understood and processed.
   * If the JWT contains critical headers not in this list (and not inherently understood by the library), decryption will fail.
   * @deprecated use {@link requiredHeaders `recognizedHeaders` option} instead.
   */
  critical?: string[];
}
