import type { JoseHeaderParameters, JWTClaims } from "./jwt";
import type { JWK_HMAC, JWK_RSA_SIGN, JWK_RSA_PSS, JWK_ECDSA } from "./jwk";

type JWS_SIGN_EXTRA = "Ed25519" | "EdDSA";
/** JWS Signing Algorithm Identifier. */
export type JWSAlgorithm =
  | JWK_HMAC
  | JWK_RSA_SIGN
  | JWK_RSA_PSS
  | JWK_ECDSA
  | JWS_SIGN_EXTRA;

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
   * Additional protected header parameters. `alg` is automatically included.
   * `typ` defaults to "JWT" if not provided.
   */
  protectedHeader?: JWSHeaderParameters;
}

/** Result of JWS verification */
export interface JWSVerifyResult<T = JWTClaims | Uint8Array | string> {
  /** The decoded and verified payload. */
  payload: T;
  /** The JWS Protected Header. */
  protectedHeader: JWSProtectedHeader;
}

// TODO: add unprotected header for JWS JSON Serialization

/** Options for JWS verification */
export interface JWSVerifyOptions {
  /** List of allowed algorithms. If provided, the JWS `alg` must be in this list. */
  algorithms?: JWSAlgorithm[];
  /** List of critical header parameters that must be understood and processed. */
  critical?: string[];
  /** If true, forces the payload to be returned as a Uint8Array, otherwise type is inferred. */
  forceUint8Array?: boolean;
  // TODO: Add other verification options like clock tolerance, audience, issuer etc. later if needed
}
