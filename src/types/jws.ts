import type { JoseHeaderParameters } from "./jwt";

/** Recognized JWS Header Parameters, any other Header Members may also be present. */
export interface JWSHeaderParameters extends JoseHeaderParameters {
  /** JWS "alg" (Algorithm) Header Parameter */
  alg?: string;

  /**
   * This JWS Extension Header Parameter modifies the JWS Payload representation and the JWS Signing
   * Input computation as per {@link https://www.rfc-editor.org/rfc/rfc7797 RFC7797}.
   */
  b64?: boolean;
}

/**
 * JWS (JSON Web Signature) options for signing
 */
export interface JWSSignOptions {
  /**
   * Additional protected header parameters
   */
  protectedHeader?: JWSHeaderParameters;
}
