/**
Based on https://github.com/panva/jose/tree/v6.0.10
Copyright (c) 2018 Filip Skokan.
https://github.com/panva/jose/blob/v6.0.10/LICENSE.md
 */

/** Generic JSON Web Key Parameters. */
export interface JWKParameters {
  /** JWK "kty" (Key Type) Parameter */
  kty?: string;
  /**
   * JWK "alg" (Algorithm) Parameter
   *
   * @see {@link https://github.com/panva/jose/issues/210 Algorithm Key Requirements}
   */
  alg?: string;
  /** JWK "key_ops" (Key Operations) Parameter */
  key_ops?: string[];
  /** JWK "ext" (Extractable) Parameter */
  ext?: boolean;
  /** JWK "use" (Public Key Use) Parameter */
  use?: string;
  /** JWK "x5c" (X.509 Certificate Chain) Parameter */
  x5c?: string[];
  /** JWK "x5t" (X.509 Certificate SHA-1 Thumbprint) Parameter */
  x5t?: string;
  /** JWK "x5t#S256" (X.509 Certificate SHA-256 Thumbprint) Parameter */
  "x5t#S256"?: string;
  /** JWK "x5u" (X.509 URL) Parameter */
  x5u?: string;
  /** JWK "kid" (Key ID) Parameter */
  kid?: string;
}

/**
 * JSON Web Key ({@link https://www.rfc-editor.org/rfc/rfc7517 JWK}). "RSA", "EC", "OKP", and "oct"
 * key types are supported.
 *
 * @see {@link JWK_OKP_Public}
 * @see {@link JWK_OKP_Private}
 * @see {@link JWK_EC_Public}
 * @see {@link JWK_EC_Private}
 * @see {@link JWK_RSA_Public}
 * @see {@link JWK_RSA_Private}
 * @see {@link JWK_oct}
 */
export interface JWK extends JWKParameters {
  /**
   * - EC JWK "crv" (Curve) Parameter
   * - OKP JWK "crv" (The Subtype of Key Pair) Parameter
   */
  crv?: string;
  /**
   * - Private RSA JWK "d" (Private Exponent) Parameter
   * - Private EC JWK "d" (ECC Private Key) Parameter
   * - Private OKP JWK "d" (The Private Key) Parameter
   */
  d?: string;
  /** Private RSA JWK "dp" (First Factor CRT Exponent) Parameter */
  dp?: string;
  /** Private RSA JWK "dq" (Second Factor CRT Exponent) Parameter */
  dq?: string;
  /** RSA JWK "e" (Exponent) Parameter */
  e?: string;
  /** Oct JWK "k" (Key Value) Parameter */
  k?: string;
  /** RSA JWK "n" (Modulus) Parameter */
  n?: string;
  /** Private RSA JWK "p" (First Prime Factor) Parameter */
  p?: string;
  /** Private RSA JWK "q" (Second Prime Factor) Parameter */
  q?: string;
  /** Private RSA JWK "qi" (First CRT Coefficient) Parameter */
  qi?: string;
  /**
   * - EC JWK "x" (X Coordinate) Parameter
   * - OKP JWK "x" (The public key) Parameter
   */
  x?: string;
  /** EC JWK "y" (Y Coordinate) Parameter */
  y?: string;
}
