import type { JoseHeaderParameters } from "./jwt"; // Import JoseHeaderParameters

import type {
  KEY_WRAPPING_ALGORITHMS,
  CONTENT_ENCRYPTION_ALGORITHMS,
} from "../utils/defaults";

export type KeyWrappingAlgorithmType = keyof typeof KEY_WRAPPING_ALGORITHMS;
export type ContentEncryptionAlgorithmType =
  keyof typeof CONTENT_ENCRYPTION_ALGORITHMS;

export interface JWEHeaderParameters extends JoseHeaderParameters {
  /**
   * `alg` (Algorithm): Header Parameter
   *
   * @default "PBES2-HS256+A128KW"
   */
  alg?: KeyWrappingAlgorithmType;
  /**
   * `enc` (Encryption Algorithm): Header Parameter
   *
   * @default "A256GCM"
   */
  enc?: ContentEncryptionAlgorithmType;
  /**
   * `p2c` (PBES2 Count): Header Parameter
   *
   * @default 2048
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
   * Number of iterations for PBES2 key derivation
   * Also accessible as `protectedHeader.p2c`
   *
   * @default 2048
   */
  iterations?: number;
  /**
   * Size of the salt for PBES2 key derivation
   *
   * @default 16
   */
  saltSize?: number;
  /**
   * Additional protected header parameters
   */
  protectedHeader?: JWEHeaderParameters;
}
