import type {
  JoseHeaderParameters,
  JOSELimits,
  JOSEPayload,
  JOSEPayloadMode,
  JWTClaimValidationOptions,
} from "./jwt";
import type {
  JWK_oct,
  JWK_EC_Public,
  JWK_EC_Private,
  JWK_OKP_Public,
  JWK_OKP_Private,
  JWK_RSA_Public,
  JWK_RSA_Private,
  JWK_HMAC,
  JWK_RSA_SIGN,
  JWK_RSA_PSS,
  JWK_ECDSA,
  JWK_OKP_SIGN,
} from "./jwk";
import type { StrictOmit } from "../utils/types";
import type { ExpiresIn } from ".";

/** JWS Signing Algorithm Identifier. */
export type JWSAlgorithm = JWK_HMAC | JWK_RSA_SIGN | JWK_RSA_PSS | JWK_ECDSA | JWK_OKP_SIGN;

/**
 * Asymmetric private JWKs admissible as a signing key. RSA keys carry a
 * signing `alg` (RS* or PS*); EC keys carry an ECDSA alg; OKP keys carry an Ed
 * signing alg.
 */
export type JWSAsymmetricPrivateJWK =
  | JWK_RSA_Private<JWK_RSA_SIGN | JWK_RSA_PSS>
  | JWK_EC_Private<JWK_ECDSA>
  | JWK_OKP_Private<JWK_OKP_SIGN>;

/**
 * Asymmetric public JWKs admissible as a verification key. RSA keys carry a
 * signing `alg` (RS* or PS*); EC keys carry an ECDSA alg; OKP keys carry an Ed
 * signing alg.
 */
export type JWSAsymmetricPublicJWK =
  | JWK_RSA_Public<JWK_RSA_SIGN | JWK_RSA_PSS>
  | JWK_EC_Public<JWK_ECDSA>
  | JWK_OKP_Public<JWK_OKP_SIGN>;

/**
 * JWKs admissible as the `key` argument of {@link sign}. HMAC oct keys carry a
 * {@link JWK_HMAC} alg; asymmetric private keys carry their family's signing alg.
 * A JWK whose `alg` points at a non-signing family (e.g. `"RSA-OAEP"`) is
 * rejected at the type level.
 */
export type JWSSignJWK = JWK_oct<JWK_HMAC> | JWSAsymmetricPrivateJWK;

/**
 * JWKs admissible as a `key` for {@link verify}. HMAC oct keys carry a
 * {@link JWK_HMAC} alg; asymmetric public keys carry their family's signing alg.
 * A JWK whose `alg` points at a non-signing family (e.g. `"RSA-OAEP"`) is
 * rejected at the type level.
 */
export type JWSVerifyJWK = JWK_oct<JWK_HMAC> | JWSAsymmetricPublicJWK;

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
   * Duration until the JWS should expire, relative to `currentDate` (or `new Date()`).
   * Skipped when the payload already carries an `exp` claim.
   *
   * Mutually exclusive with {@link expiresAt}.
   */
  expiresIn?: ExpiresIn;

  /**
   * Absolute moment at which the JWS should expire (sets the `exp` claim directly).
   * Skipped when the payload already carries an `exp` claim.
   *
   * Mutually exclusive with {@link expiresIn}.
   */
  expiresAt?: Date;

  /**
   * Duration from `iat` before which the JWS must not be accepted.
   * `0` is allowed and sets `nbf = iat` (explicit temporal floor at sign time).
   * Skipped when the payload already carries an `nbf` claim.
   *
   * Mutually exclusive with {@link notBeforeAt}.
   */
  notBeforeIn?: ExpiresIn;

  /**
   * Absolute moment before which the JWS must not be accepted (sets the `nbf`
   * claim directly per RFC 7519 §4.1.5). Skipped when the payload already
   * carries an `nbf` claim.
   *
   * Mutually exclusive with {@link notBeforeIn}.
   */
  notBeforeAt?: Date;
}

/** Result of JWS verification */
export interface JWSVerifyResult<T extends JOSEPayload = JOSEPayload> {
  /** The decoded and verified payload. */
  payload: T;
  /** The JWS Protected Header. */
  protectedHeader: JWSProtectedHeader;
}

/** Options for JWS verification */
export interface JWSVerifyOptions extends JWTClaimValidationOptions {
  /**
   * List of allowed algorithms. If provided, the JWS `alg` must be in this list.
   * When omitted, the allowlist is inferred from the key's shape — keys without
   * usable metadata (raw `Uint8Array`/string, alg-less JWKs, lookup functions)
   * cannot be inferred and require this option explicitly.
   */
  algorithms?: JWSAlgorithm[];
  /**
   * Admit the `oct` entries of a JWK Set as key material.
   *
   * A JWK Set is public-key material: its `oct` entries are ignored, so a
   * symmetric key appended to a published set cannot turn into a secret this
   * token is checked against. Set this to `true` only for a set the application
   * itself controls — an HMAC key-rotation set — never for one fetched from a
   * `jwks_uri`.
   *
   * @default false
   */
  allowSymmetricJWKSet?: boolean;
  /**
   * How many JWK Set candidates one token may be tried against, after `kid`,
   * `alg` and `use` have narrowed the set. A wider set is
   * `ERR_JWK_KEY_NOT_FOUND` before the first key is imported.
   *
   * @default { keyCandidates: 8 }
   */
  limits?: Pick<JOSELimits, "keyCandidates">;
  /**
   * What the verified payload is, declared by the caller — the signed content
   * never decides its own shape.
   *
   * - `"json"` (default) — the payload must be UTF-8 JSON naming a non-null,
   *   non-array object, returned as the result's `T`. Anything else is
   *   `ERR_JWS_INVALID`. JWT claim validation applies.
   * - `"string"` — the payload is returned as a UTF-8 string; invalid UTF-8 is
   *   `ERR_JWS_INVALID`.
   * - `"bytes"` — the payload is returned as `Uint8Array<ArrayBuffer>`.
   *
   * Under RFC 7797 `b64: false` the unencoded payload segment is the content
   * and the same three modes apply to it.
   *
   * @default "json"
   */
  payload?: JOSEPayloadMode;
  /**
   * If true, forces the payload to be returned as a `Uint8Array`.
   *
   * @deprecated Use `payload: "bytes"`. Deprecated in v0.8.0, removed in v0.9.0
   */
  forceUint8Array?: boolean;
  /**
   * Set to `false` to skip JWT claim validation after a successful signature
   * verification.
   *
   * Claim validation runs under `payload: "json"` (the default) unless this
   * option is `false`; `true` and the default `undefined` behave alike. It is
   * the payload mode — never the `typ` header or the payload's shape — that
   * decides whether there are claims to validate, so `validateClaims: true`
   * alongside `payload: "string"` / `"bytes"` is `ERR_INVALID_OPTION` rather
   * than a validation that silently does not run.
   */
  validateClaims?: boolean;
}

/**
 * JWS Flattened JSON Serialization, RFC 7515 §7.2.2. Accepted as input by
 * {@link verifyMulti} and normalized to {@link JWSGeneralSerialization}
 * internally. Emitted by {@link generalToFlattenedJWS} on a single-signature
 * General serialization.
 */
export interface JWSFlattenedSerialization {
  /** The JWS Payload. base64url-encoded when `b64 !== false`. */
  payload: string;
  /** Base64URL-encoded JWS Protected Header (part of the signing input). */
  protected?: string;
  /** JWS Unprotected Header (not part of the signing input). */
  header?: JWSHeaderParameters;
  /** Base64URL-encoded signature bytes. */
  signature: string;
}

/**
 * JWS General JSON Serialization, RFC 7515 §7.2.1. Canonical multi-signature
 * output shape of {@link signMulti}.
 *
 * `payload` is shared across all signatures and carries base64url-encoded
 * bytes by default. When the consistent `b64: false` signing mode is used
 * (RFC 7797), `payload` holds the raw UTF-8 payload string instead.
 */
export interface JWSGeneralSerialization extends Omit<
  JWSFlattenedSerialization,
  "protected" | "header" | "signature"
> {
  /** One entry per signer. */
  signatures: JWSGeneralSignature[];
}

/** A single signature entry within {@link JWSGeneralSerialization.signatures}. */
export type JWSGeneralSignature = Pick<
  JWSFlattenedSerialization,
  "protected" | "header" | "signature"
>;

/**
 * Input shape for a single signer passed to {@link signMulti}.
 *
 * `alg` comes from this signer's `alg`, else from `key.alg` (JWK) or the key's
 * own WebCrypto algorithm (CryptoKey); when none of those resolve it throws
 * `ERR_JWS_SIGNER_ALG_INFERENCE`. `kid` is pulled from `key.kid` when the key
 * is a JWK — a CryptoKey signer must set `kid` on its `protectedHeader`.
 */
export interface JWSMultiSigner {
  /** Signing key (JWK-first; a `CryptoKey` is also accepted). */
  key: JWSSignJWK | CryptoKey;
  /**
   * JWS Algorithm for this signer. Optional for keys whose algorithm can be
   * inferred (a JWK with `alg`, or a CryptoKey); required otherwise.
   */
  alg?: JWSAlgorithm;
  /**
   * Extra per-signer JWS Protected Header parameters (RFC 7515 §7.2.1).
   * `alg` is always derived from the JWK and cannot be set here. `b64`
   * MUST be consistent across every signer (RFC 7797 §3) — if set on one
   * signer it must match on all.
   */
  protectedHeader?: StrictOmit<JWSHeaderParameters, "alg"> & { alg?: never };
  /** Per-signer JWS Unprotected Header (not part of signing input). */
  unprotectedHeader?: JWSHeaderParameters;
}

/**
 * Options for {@link signMulti}. Mirrors {@link JWSSignOptions} minus the
 * per-signer fields (`alg`, `protectedHeader` — set those on each
 * {@link JWSMultiSigner} instead).
 */
export interface JWSMultiSignOptions extends StrictOmit<
  JWSSignOptions,
  "alg" | "protectedHeader"
> {}

/** Options for {@link verifyMulti}. Extends {@link JWSVerifyOptions}. */
export interface JWSMultiVerifyOptions extends JWSVerifyOptions {
  /**
   * How many `signatures[]` entries the serialization may carry, and how many
   * JWK Set candidates each of them may be tried against. A token carrying
   * more signatures than this is `ERR_JWS_INVALID` before any of them is read.
   *
   * @default { signatures: 16, keyCandidates: 8 }
   */
  limits?: Pick<JOSELimits, "signatures" | "keyCandidates">;
  /**
   * When `false` (default), verification trials signatures in order — mirrors
   * the multi-key retry behaviour of {@link verify} against a JWK Set. When
   * `true`, only signatures whose header unambiguously matches the provided
   * key (by `kid`, then by `kty`/`crv`/length) are attempted, and any
   * mismatch throws `ERR_JWS_NO_MATCHING_SIGNER` before any crypto work.
   */
  strictSignerMatch?: boolean;
}

/**
 * Result of a {@link verifyMulti} operation. Extends {@link JWSVerifyResult}
 * with the per-signer header and matched signature index.
 */
export interface JWSMultiVerifyResult<T extends JOSEPayload = JOSEPayload> extends Omit<
  JWSVerifyResult<T>,
  "protectedHeader"
> {
  /**
   * The integrity-protected header of the signature that verified, exactly as
   * signed. `alg` may instead sit in {@link signerHeader} (RFC 7515 §7.2.1), so
   * it is present here only when the signer protected it; a Flattened JWS with
   * no `protected` member yields `{}`.
   */
  protectedHeader: JWSHeaderParameters;
  /** Parsed per-signer unprotected header of the signature that verified. */
  signerHeader?: JWSHeaderParameters;
  /** Index into `jws.signatures` of the signature that successfully verified. */
  signerIndex: number;
}

/**
 * Options for {@link verifyMultiAll}. Inherits the same validation knobs as
 * {@link JWSMultiVerifyOptions} minus `strictSignerMatch` (not meaningful when
 * every signature is independently reported).
 */
export interface JWSMultiVerifyAllOptions extends StrictOmit<
  JWSMultiVerifyOptions,
  "strictSignerMatch"
> {}

/**
 * Per-signature outcome collected by {@link verifyMultiAll}. Discriminated by
 * `verified`:
 *
 *   - `verified: true` — the signature cryptographically verified and any
 *     claim/`crit` validation the caller asked for also passed. `payload` is
 *     provided.
 *   - `verified: false` — verification could not be completed for this
 *     signature. `error` carries the {@link JWTError} reason (signature
 *     invalid, disallowed alg, `typ` mismatch, key-resolver failure, malformed
 *     protected header, expired claim, etc.). `protectedHeader` / `signerHeader`
 *     are populated when they were successfully parsed before failure.
 *
 * `protectedHeader` holds only what was integrity protected; an `alg` carried
 * in the unprotected header (RFC 7515 §7.2.1) appears in `signerHeader`.
 *
 * Callers apply their own policy over the returned array — e.g. "all must
 * verify", "quorum of N", "signed by these specific kids".
 */
export type JWSMultiVerifyOutcome<T extends JOSEPayload = JOSEPayload> =
  | {
      signerIndex: number;
      verified: true;
      payload: T;
      protectedHeader: JWSHeaderParameters;
      signerHeader?: JWSHeaderParameters;
    }
  | {
      signerIndex: number;
      verified: false;
      error: import("./../error").JWTError;
      protectedHeader?: JWSHeaderParameters;
      signerHeader?: JWSHeaderParameters;
    };
