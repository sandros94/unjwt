import type { JoseHeaderParameters } from "./jwt";

/** Recognized JWE Header Parameters, any other Header Members may also be present. */
export interface JWEHeaderParameters extends JoseHeaderParameters {
  /**
   * `alg` (Algorithm): Header Parameter
   */
  alg?: string;
  /**
   * `enc` (Encryption Algorithm): Header Parameter
   */
  enc?: string;
  /**
   * `p2c` (PBES2 Count): Header Parameter
   */
  p2c?: number;
  /**
   * `p2s` (PBES2 Salt): Header Parameter
   */
  p2s?: string;
}

/**
 * JWE (JSON Web Encryption) options
 */
export interface JWEOptions {
  /**
   * Additional protected header parameters
   */
  protectedHeader?: JWEHeaderParameters;
}
