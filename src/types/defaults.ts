import type {
  JWS_ALGORITHMS_SYMMETRIC,
  JWS_ALGORITHMS_ASYMMETRIC_RSA,
  JWE_KEY_WRAPPING_PBES2,
  JWE_KEY_WRAPPING_RSA,
  JWE_CONTENT_ENCRYPTION_ALGORITHMS,
} from "../utils/defaults";

// --- Algorithm Sets Derived from Defaults ---

/** Set of supported HMAC algorithm identifiers. */
export type HmacAlgorithm = keyof typeof JWS_ALGORITHMS_SYMMETRIC;

/** Set of supported AES Key Wrap algorithm identifiers (used in PBES2). */
export type AesKwWrapAlgorithm = keyof typeof JWE_KEY_WRAPPING_PBES2;

/** Set of supported AES-GCM algorithm identifiers. */
export type AesGcmAlgorithm = {
  [K in keyof typeof JWE_CONTENT_ENCRYPTION_ALGORITHMS]: (typeof JWE_CONTENT_ENCRYPTION_ALGORITHMS)[K]["type"] extends "gcm"
    ? K
    : never;
}[keyof typeof JWE_CONTENT_ENCRYPTION_ALGORITHMS];

/** Set of supported AES-CBC algorithm identifiers (composite). */
export type AesCbcAlgorithm = {
  [K in keyof typeof JWE_CONTENT_ENCRYPTION_ALGORITHMS]: (typeof JWE_CONTENT_ENCRYPTION_ALGORITHMS)[K]["type"] extends "cbc"
    ? K
    : never;
}[keyof typeof JWE_CONTENT_ENCRYPTION_ALGORITHMS];

/** Set of supported RSA Signing algorithm identifiers. */
export type RsaSignAlgorithm = keyof typeof JWS_ALGORITHMS_ASYMMETRIC_RSA;

/** Set of supported RSA Key Wrapping algorithm identifiers. */
export type RsaWrapAlgorithm = keyof typeof JWE_KEY_WRAPPING_RSA;

// --- Composite Algorithm Sets ---

/** Set of JOSE algorithms that typically use a single symmetric CryptoKey. */
export type JoseSingleKeyAlgorithm =
  | HmacAlgorithm
  | AesKwWrapAlgorithm
  | AesGcmAlgorithm;

/** Set of JOSE algorithms that typically use an asymmetric CryptoKeyPair. */
export type JoseKeyPairAlgorithm = RsaSignAlgorithm | RsaWrapAlgorithm;

/** Set of all supported JOSE algorithm identifiers relevant for JWK operations. */
export type JoseAlgorithm =
  | JoseSingleKeyAlgorithm
  | JoseKeyPairAlgorithm
  | AesCbcAlgorithm;
