import type { JoseHeaderParameters, JOSEPayload, JWTClaimValidationOptions } from "./jwt";
import type {
  JWK,
  JWK_EC_Public,
  JWK_EC_Private,
  KeyManagementAlgorithm,
  ContentEncryptionAlgorithm,
} from "./jwk";
import type { ExpiresIn } from ".";
import type { StrictOmit } from "../utils/types";

/** Recognized JWE Header Parameters, any other Header Members may also be present. */
export interface JWEHeaderParameters extends JoseHeaderParameters {
  /**
   * `alg` (Algorithm): Header Parameter - Key Management Algorithm
   */
  alg?: KeyManagementAlgorithm | (string & {});
  /**
   * `enc` (Encryption Algorithm): Header Parameter - Content Encryption Algorithm
   */
  enc?: ContentEncryptionAlgorithm | (string & {});
  /**
   * `p2c` (PBES2 Count): Header Parameter
   */
  p2c?: number;
  /**
   * `p2s` (PBES2 Salt): Header Parameter. Base64URL encoded.
   */
  p2s?: string;
  /**
   * "iv" (Initialization Vector) Header Parameter for AES GCM Key Wrapping. Base64URL encoded.
   */
  iv?: string;
  /**
   * "tag" (Authentication Tag) Header Parameter for AES GCM Key Wrapping. Base64URL encoded.
   */
  tag?: string;
  /**
   * "epk" (Ephemeral Public Key) Header Parameter for ECDH-ES.
   */
  epk?: JWK_EC_Public;
  /**
   * "apu" (Agreement PartyUInfo) Header Parameter for ECDH-ES. Base64URL encoded.
   */
  apu?: string;
  /**
   * "apv" (Agreement PartyVInfo) Header Parameter for ECDH-ES. Base64URL encoded.
   */
  apv?: string;

  /** Any other JWE Header member. */
  [propName: string]: unknown;
}

/** Recognized JWE Key Management-related Header Parameters. */
export interface JWEKeyManagementHeaderParameters {
  apu?: Uint8Array<ArrayBuffer>;
  apv?: Uint8Array<ArrayBuffer>;
  /**
   * For Internal use only
   */
  p2c?: number;
  /**
   * For Internal use only
   */
  p2s?: Uint8Array<ArrayBuffer>;
  /**
   * For Internal use only
   */
  iv?: Uint8Array<ArrayBuffer>;
  /**
   * For Internal use only
   */
  epk?: CryptoKey | JWK_EC_Public;
  /**
   * For Internal use only
   */
  epkPrivateKey?: CryptoKey | JWK_EC_Private;
}

/**
 * JWE (JSON Web Encryption) encryption options
 */
export interface JWEEncryptOptions {
  /** JWE "alg" (Algorithm) Header Parameter. Key Management Algorithm. */
  alg?: KeyManagementAlgorithm;
  /** JWE "enc" (Encryption Algorithm) Header Parameter. Content Encryption Algorithm. */
  enc?: ContentEncryptionAlgorithm;
  /** Date to use when computing NumericDate claims, defaults to `new Date()`. */
  currentDate?: Date;
  /**
   * Duration until the JWT should expire, relative to `currentDate` (or `new Date()`).
   * Skipped when the payload already carries an `exp` claim.
   *
   * Mutually exclusive with {@link expiresAt}.
   */
  expiresIn?: ExpiresIn;

  /**
   * Absolute moment at which the JWT should expire (sets the `exp` claim directly).
   * Skipped when the payload already carries an `exp` claim.
   *
   * Mutually exclusive with {@link expiresIn}.
   */
  expiresAt?: Date;

  /**
   * Duration from `iat` before which the JWT must not be accepted.
   * `0` is allowed and sets `nbf = iat` (explicit temporal floor at sign time).
   * Skipped when the payload already carries an `nbf` claim.
   *
   * Mutually exclusive with {@link notBeforeAt}.
   */
  notBeforeIn?: ExpiresIn;

  /**
   * Absolute moment before which the JWT must not be accepted (sets the `nbf`
   * claim directly per RFC 7519 §4.1.5). Skipped when the payload already
   * carries an `nbf` claim.
   *
   * Mutually exclusive with {@link notBeforeIn}.
   */
  notBeforeAt?: Date;

  /** Additional JWE Protected Header parameters. */
  protectedHeader?: StrictOmit<
    JWEHeaderParameters,
    "alg" | "enc" | "iv" | "tag" | "p2s" | "p2c" | "epk" | "apu" | "apv"
  >;

  /** Initialization Vector for AES-GCMKW key wrapping. Generated if not provided. */
  keyManagementIV?: Uint8Array<ArrayBuffer>;
  /** PBES2 Salt value (p2s). Required for PBES2 algorithms. */
  p2s?: Uint8Array<ArrayBuffer>;
  /** PBES2 Iteration count (p2c). Required for PBES2 algorithms. */
  p2c?: number;
  /** ECDH-ES specific options. */
  ecdh?: {
    /**
     * ECDH-ES Ephemeral key material. Provide a private key (CryptoKey or JWK),
     * a CryptoKeyPair, or an object exposing both public and private parts.
     */
    ephemeralKey?:
      | CryptoKey
      | JWK_EC_Private
      | CryptoKeyPair
      | {
          publicKey: CryptoKey | JWK_EC_Public;
          privateKey: CryptoKey | JWK_EC_Private;
        };
    /** ECDH-ES Agreement PartyUInfo. */
    partyUInfo?: Uint8Array<ArrayBuffer>;
    /** ECDH-ES Agreement PartyVInfo. */
    partyVInfo?: Uint8Array<ArrayBuffer>;
  };

  /**
   * Content Encryption Key (CEK) to use.
   * If provided, it will be used directly. Otherwise, a CEK will be generated.
   */
  cek?: Uint8Array<ArrayBuffer>;

  /**
   * Initialization Vector for content encryption.
   * If provided, it will be used. Otherwise, one will be generated.
   */
  contentEncryptionIV?: Uint8Array<ArrayBuffer>;
}

/**
 * JWE (JSON Web Encryption) decryption options
 */
export interface JWEDecryptOptions extends JWTClaimValidationOptions {
  /** A list of allowed JWE "alg" (Algorithm) Header Parameter values for key management. */
  algorithms?: KeyManagementAlgorithm[];
  /** A list of allowed JWE "enc" (Encryption Algorithm) Header Parameter values for content encryption. */
  encryptionAlgorithms?: ContentEncryptionAlgorithm[];
  /** Algorithm to import the unwrapped CEK as (e.g., { name: 'AES-GCM' }). Defaults based on 'enc'. */
  unwrappedKeyAlgorithm?: Parameters<typeof crypto.subtle.importKey>[2];

  /** Key usages for the unwrapped CEK. Defaults based on 'enc' (typically ['encrypt', 'decrypt']). */
  keyUsage?: KeyUsage[];
  /** Mark the unwrapped CEK as extractable. Defaults to true. */
  extractable?: boolean;
  /** If true, forces the payload to be returned as a Uint8Array, otherwise type is inferred based on JWE headers. */
  forceUint8Array?: boolean;
  /**
   * Controls JWT claim validation after a successful decryption.
   *
   * - `true` — always validate claims regardless of the `typ` header
   * - `false` — skip claim validation entirely
   * - `undefined` (default) — validate when `typ` is `"JWT"` or contains `"jwt"`
   */
  validateClaims?: boolean;
  /** If true, include the Content Encryption Key (CEK) and Additional Authenticated Data (AAD) in the result. */
  returnCek?: boolean;
  /** Minimum accepted PBES2 `p2c` on unwrap. Defaults to 1000 (RFC 7518 §4.8.1.2). */
  minIterations?: number;
  /** Maximum accepted PBES2 `p2c` on unwrap. Defaults to 1_000_000 to cap PBKDF2 DoS potential. */
  maxIterations?: number;
}

/**
 * JWE Protected Header — the parsed and validated protected header returned
 * after a successful {@link decrypt} call. Both `alg` and `enc` are present
 * and strongly typed because decryption could not have succeeded without them.
 */
export interface JWEProtectedHeader extends JWEHeaderParameters {
  /** Key management algorithm. */
  alg: KeyManagementAlgorithm;
  /** Content encryption algorithm. */
  enc: ContentEncryptionAlgorithm;
}

/**
 * Result of a JWE decryption operation.
 */
export interface JWEDecryptResult<T extends JOSEPayload = JOSEPayload> {
  /** The decrypted payload. */
  payload: T;
  /** The JWE Protected Header. */
  protectedHeader: JWEProtectedHeader;
  /** The Content Encryption Key (CEK) used for decryption, as Uint8Array. Only present when `returnCek` is true. */
  cek?: Uint8Array<ArrayBuffer>;
  /** The Additional Authenticated Data (AAD) used, as Uint8Array. Only present when `returnCek` is true. */
  aad?: Uint8Array<ArrayBuffer>;
}

/**
 * JWE Flattened JSON Serialization, RFC 7516 §7.2.2.
 */
export interface JWEFlattenedSerialization {
  header?: JWEHeaderParameters;
  encrypted_key?: string;
  /** Base64URL-encoded JWE Protected Header (part of AAD). */
  protected?: string;
  /** Shared JWE Unprotected Header (JSON, not part of AAD). */
  unprotected?: JWEHeaderParameters;
  /** Base64URL-encoded external Additional Authenticated Data. */
  aad?: string;
  /** Base64URL-encoded IV (Initialization Vector). */
  iv?: string;
  /** Base64URL-encoded ciphertext. */
  ciphertext: string;
  /** Base64URL-encoded authentication tag. */
  tag?: string;
}

/**
 * JWE General JSON Serialization, RFC 7516 §7.2.1. The canonical
 * multi-recipient output shape of {@link encryptMulti}.
 */
export interface JWEGeneralSerialization extends Omit<
  JWEFlattenedSerialization,
  "encrypted_key" | "header"
> {
  /** One entry per recipient. */
  recipients: JWEGeneralRecipient[];
}

/** A single recipient entry within {@link JWEGeneralSerialization.recipients}. */
export interface JWEGeneralRecipient {
  /** Per-recipient JWE Unprotected Header (JSON, not part of AAD). */
  header?: JWEHeaderParameters;
  /** Base64URL-encoded encrypted CEK for this recipient. */
  encrypted_key?: string;
}

/**
 * Input shape for a single recipient passed to {@link encryptMulti}.
 *
 * `alg` is inferred from `key.alg` or from the JWK's kty/curve/length using
 * the same rules as {@link encrypt}. `kid` is pulled from `key.kid` when
 * present. To override either, spread or set via {@link JWEMultiRecipient.header}.
 */
export interface JWEMultiRecipient {
  /** Recipient key (JWK-first; `alg` inferred if absent from JWK). */
  key: JWK;
  /**
   * Extra per-recipient JWE Unprotected Header parameters (RFC 7516 §7.2.1).
   * Excludes fields the library writes automatically: `alg`, `enc`, `iv`,
   * `tag`, `p2s`, `p2c`, `epk`, `apu`, `apv`.
   *
   * Typical use: `x5c`, `x5t`, custom routing metadata.
   */
  header?: StrictOmit<
    JWEHeaderParameters,
    "alg" | "enc" | "iv" | "tag" | "p2s" | "p2c" | "epk" | "apu" | "apv"
  >;
  /** ECDH-ES ephemeral key / party info for this recipient. */
  ecdh?: JWEEncryptOptions["ecdh"];
  /** PBES2 salt for this recipient. Randomized (16 bytes) when omitted. */
  p2s?: Uint8Array<ArrayBuffer>;
  /** PBES2 iteration count for this recipient. Defaults to 600_000. */
  p2c?: number;
  /** Initialization vector for AES-GCMKW key wrapping for this recipient. */
  keyManagementIV?: Uint8Array<ArrayBuffer>;
}

/**
 * Options for {@link encryptMulti}. Extends {@link JWEEncryptOptions} and drops
 * the fields that are per-recipient in multi-recipient mode (`alg`, `ecdh`,
 * `p2s`, `p2c`, `keyManagementIV` — set those on each {@link JWEMultiRecipient}
 * instead).
 */
export interface JWEMultiEncryptOptions extends StrictOmit<
  JWEEncryptOptions,
  "alg" | "ecdh" | "p2s" | "p2c" | "keyManagementIV"
> {
  /** Shared JWE Unprotected Header (surfaces as `unprotected` in the output). */
  sharedUnprotectedHeader?: Record<string, unknown>;
  /**
   * External Additional Authenticated Data (RFC 7516 §5.1). Encoded as
   * base64url and written to the `aad` field; the content cipher AAD becomes
   * `BASE64URL(protected) || '.' || BASE64URL(aad)`.
   */
  aad?: Uint8Array<ArrayBuffer> | string;
}

/**
 * Options for {@link decryptMulti}. Extends {@link JWEDecryptOptions}.
 */
export interface JWEMultiDecryptOptions extends JWEDecryptOptions {
  /**
   * When `false` (default) decryption trials recipients in order — mirrors the
   * multi-key retry behaviour of {@link decrypt} against a JWK Set. When
   * `true`, only recipients whose header unambiguously matches the provided
   * key (by `kid`, then by `kty`/`crv`/length) are attempted, and any mismatch
   * throws `ERR_JWE_NO_MATCHING_RECIPIENT` before any crypto work.
   */
  strictRecipientMatch?: boolean;
}

/**
 * Result of a {@link decryptMulti} operation. Extends {@link JWEDecryptResult}
 * with the per-recipient header tier surfaced on the matching recipient.
 */
export interface JWEMultiDecryptResult<
  T extends JOSEPayload = JOSEPayload,
> extends JWEDecryptResult<T> {
  /** Parsed shared unprotected header, when present on the serialization. */
  sharedUnprotectedHeader?: JWEHeaderParameters;
  /** Parsed per-recipient unprotected header of the recipient that decrypted. */
  recipientHeader?: JWEHeaderParameters;
  /** Index into `jwe.recipients` of the recipient that successfully decrypted. */
  recipientIndex: number;
}
