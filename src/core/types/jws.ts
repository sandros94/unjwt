import type { JoseHeaderParameters, JOSEPayload, JWTClaimValidationOptions } from "./jwt";
import type { JWK_HMAC, JWK_RSA_SIGN, JWK_RSA_PSS, JWK_ECDSA, JWK_OKP_SIGN } from "./jwk";
import type { StrictOmit } from "../utils/types";
import type { ExpiresIn } from ".";

/** JWS Signing Algorithm Identifier. */
export type JWSAlgorithm = JWK_HMAC | JWK_RSA_SIGN | JWK_RSA_PSS | JWK_ECDSA | JWK_OKP_SIGN;

/** Recognized JWS Header Parameters, any other Header Members may also be present. */
export interface JWSHeaderParameters extends JoseHeaderParameters {
  /** JWS "alg" (Algorithm) Header Parameter */
  alg?: JWSAlgorithm;

  /**
   * This JWS Extension Header Parameter modifies the JWS Payload representation and the JWS Signing
   * Input computation as per {@link https://www.rfc-editor.org/rfc/rfc7797 RFC7797}.
   * If `false`, the payload is used directly without Base64URL encoding.
   * Defaults to `true`.
   */
  b64?: boolean;
}

/** JWS Protected Header */
export interface JWSProtectedHeader extends JWSHeaderParameters {
  alg: JWSAlgorithm;
}

/**
 * JWS (JSON Web Signature) options for signing
 */
export interface JWSSignOptions {
  /** The JWS Algorithm to use. Must be provided. */
  alg?: JWSAlgorithm;

  /**
   * Additional protected header parameters. `alg` is always derived from the top-level `alg`
   * option (or inferred from the key) and cannot be overridden. `typ` defaults to `"JWT"`
   * when the payload is a JSON object.
   */
  protectedHeader?: StrictOmit<JWSHeaderParameters, "alg"> & { alg?: never };

  /** Date to use when comparing NumericDate claims, defaults to `new Date()`. */
  currentDate?: Date;

  /**
   * Time at which the JWS should expire, if no `exp` was already provided.
   */
  expiresIn?: ExpiresIn;
}

/** Result of JWS verification */
export interface JWSVerifyResult<T extends JOSEPayload = JOSEPayload> {
  /** The decoded and verified payload. */
  payload: T;
  /** The JWS Protected Header. */
  protectedHeader: JWSProtectedHeader;
}

// TODO: add unprotected header for JWS JSON Serialization

/** Options for JWS verification */
export interface JWSVerifyOptions extends JWTClaimValidationOptions {
  /** List of allowed algorithms. If provided, the JWS `alg` must be in this list. */
  algorithms?: JWSAlgorithm[];
  /** If true, forces the payload to be returned as a Uint8Array, otherwise type is inferred. */
  forceUint8Array?: boolean;
  /**
   * Controls JWT claim validation after a successful verification.
   *
   * - `true` — always validate claims regardless of the `typ` header
   * - `false` — skip claim validation entirely
   * - `undefined` (default) — validate when `typ` is `"JWT"` or contains `"jwt"`
   */
  validateClaims?: boolean;
}
