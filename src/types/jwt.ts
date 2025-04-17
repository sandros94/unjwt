import type { JWK } from "./jwk";

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
  jwk?: Pick<JWK, "kty" | "crv" | "x" | "y" | "e" | "n">;

  /** "typ" (Type) Header Parameter */
  typ?: string;

  /** "cty" (Content Type) Header Parameter */
  cty?: string;

  /** "crit" (Critical) Header Parameter */
  crit?: string[];

  /** Any other JWS/JWE Header member. */
  [propName: string]: unknown;
}
