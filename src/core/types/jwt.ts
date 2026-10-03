import type { JWK_Public } from "./jwk";
import type { Duration, MaxTokenAge } from ".";

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

/**
 * How the payload of a verified JWS or a decrypted JWE is decoded.
 *
 * - `"json"` — the payload bytes are UTF-8 JSON naming a non-null, non-array
 *   object; anything else is rejected. JWT claim validation applies.
 * - `"string"` — the payload bytes are returned as a UTF-8 string.
 * - `"bytes"` — the payload bytes are returned verbatim.
 *
 * The mode is the caller's declaration of what the payload is: the decoded
 * content never decides its own shape.
 */
export type JOSEPayloadMode = "json" | "string" | "bytes";

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

/**
 * The work one JOSE call may do before it is refused.
 *
 * A token names how much work its verifier is asked for — how many signatures
 * or recipients to try, and at what PBKDF2 cost — and a JWK Set names how many
 * keys to try it against. Each of these is bounded per call, so an attacker who
 * holds no key cannot turn one request into unbounded CPU. `limits` is an
 * object and every entry a positive integer; anything else is
 * `ERR_INVALID_OPTION`.
 *
 * The defaults are {@link DEFAULT_JOSE_LIMITS}. Each operation exposes the
 * subset that applies to it.
 */
export interface JOSELimits {
  /** Entries of `signatures[]` a JWS JSON serialization may carry. @default 16 */
  signatures?: number;
  /** Entries of `recipients[]` a JWE JSON serialization may carry. @default 16 */
  recipients?: number;
  /** JWK Set candidates tried for one token after `kid`/`alg`/`use` filtering. @default 8 */
  keyCandidates?: number;
  /**
   * Total PBKDF2 iterations one call may spend across every PBES2 attempt —
   * four attempts at the `p2c` a producer mints by default.
   *
   * @default 2_400_000
   */
  pbes2Iterations?: number;
}

/**
 * Claim expectations for verification and decryption. Each one is checked
 * whenever it is set: an empty `audience`, `issuer`, `subject` or `typ`,
 * `maxTokenAge: 0`, or a list option that is not an array of strings is
 * `ERR_INVALID_OPTION` rather than a check that is skipped.
 */
export interface JWTClaimValidationOptions {
  /**
   * Expected JWT "aud" (Audience) Claim value(s).
   *
   * The `aud` claim is checked only when this option is configured: a token
   * carrying `aud` is accepted by a verifier that sets no `audience`, and one
   * lacking it is rejected by a verifier that does. Configure `audience`
   * wherever a token is meant for this recipient alone — that is what enforces
   * RFC 7519 §4.1.3.
   */
  audience?: string | string[];
  /** Expected JWT "iss" (Issuer) Claim value(s). Implies presence requirement. */
  issuer?: string | string[];
  /** Expected JWT "sub" (Subject) Claim value. Implies presence requirement. */
  subject?: string;
  /** Maximum token age, from the JWT "iat" (Issued At) Claim value. Implies presence requirement. */
  maxTokenAge?: MaxTokenAge;
  /**
   * Clock skew tolerance for validating time-based claims (nbf/exp/iat): a
   * non-negative number of seconds or a {@link Duration} shorthand (`"5m"`,
   * `"1h"`, …). Anything else — negative, non-finite, or unparseable — throws
   * `ERR_INVALID_OPTION`.
   *
   * @default 0
   */
  clockTolerance?: number | Duration;
  /**
   * Expected JWT "typ" (Type) Header Parameter value. Implies presence requirement.
   *
   * Compared under RFC 7515 §4.1.9 media-type semantics: case-insensitive, and
   * the `application/` prefix may be omitted on either side, so `"at+jwt"`
   * matches a header carrying `"application/AT+JWT"`.
   */
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
