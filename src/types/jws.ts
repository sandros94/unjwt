import type { JoseHeaderParameters } from "./jwt";
import type { JWS_SYMMETRIC_ALGORITHMS } from "../utils/defaults";

/** Supported JWS Symmetric Algorithm types */
export type JWSSymmetricAlgorithm = keyof typeof JWS_SYMMETRIC_ALGORITHMS;

// TODO: Add asymmetric algorithm types later
/** Supported JWS Algorithm types */
export type JWSAlgorithm = JWSSymmetricAlgorithm; // | JWSAsymmetricAlgorithm;

/** Recognized JWS Header Parameters, any other Header Members may also be present. */
export interface JWSHeaderParameters extends JoseHeaderParameters {
  /** JWS "alg" (Algorithm) Header Parameter */
  alg?: JWSAlgorithm;

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
