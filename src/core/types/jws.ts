import type { JoseHeaderParameters, JWTClaims, JWTClaimValidationOptions } from "./jwt";
import type { JWK_HMAC, JWK_RSA_SIGN, JWK_RSA_PSS, JWK_ECDSA, JWK_OKP_SIGN } from "./jwk";
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
   * Additional protected header parameters. `alg` is automatically included.
   * `typ` defaults to "JWT" if not provided and payload is an object.
   */
  protectedHeader?: JWSHeaderParameters;

  /** Date to use when comparing NumericDate claims, defaults to `new Date()`. */
  currentDate?: Date;

  /**
   * Time at which the JWS should expire, if no `exp` was already provided.
   */
  expiresIn?: ExpiresIn;
}

/** Result of JWS verification */
export interface JWSVerifyResult<
  T extends JWTClaims | Uint8Array<ArrayBuffer> | string =
    | JWTClaims
    | Uint8Array<ArrayBuffer>
    | string,
> {
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
  /** Unless false, will parse payload as JWT and validate claims if applicable (typ "JWT"). */
  validateJWT?: boolean;
}
