import type {
  JWSAlgorithm,
  JWSAsymmetricPrivateJWK,
  JWSAsymmetricPublicJWK,
} from "../core/types/jws.ts";

/** The JWS algorithms a DPoP proof can use: every supported `alg` except `HS*`. */
export type DPoPAlgorithm = Exclude<JWSAlgorithm, `HS${string}`>;

/** The request a proof is bound to. A Web `Request` matches this shape. */
export interface DPoPTarget {
  /** HTTP method, compared case-sensitively with the proof's `htm`. */
  method: string;
  /** Absolute `http:` or `https:` URL without credentials. Its query and fragment are ignored. */
  url: string;
}

/**
 * The signing key pair: two `CryptoKey`s or two asymmetric JWKs.
 * The private `CryptoKey` can be non-extractable. The public `CryptoKey` must be extractable.
 */
export type DPoPKeyPair =
  | CryptoKeyPair
  | { privateKey: JWSAsymmetricPrivateJWK; publicKey: JWSAsymmetricPublicJWK };

/** The claims of a DPoP proof (RFC 9449 §4.2). */
export interface DPoPPayload {
  /** Unique proof identifier. */
  jti: string;
  /** Creation time in NumericDate seconds. */
  iat: number;
  /** Expiration time in NumericDate seconds. */
  exp?: number;
  /** Earliest acceptance time in NumericDate seconds. */
  nbf?: number;
  /** HTTP method of the request. */
  htm: string;
  /** Target URI of the request, without query and fragment. */
  htu: string;
  /** Nonce the server supplied. */
  nonce?: string;
  /** Base64url SHA-256 hash of the access token. */
  ath?: string;
  [claim: string]: unknown;
}

export interface DPoPCreateOptions {
  /** The key pair that signs the proof. Its public key is written to the `jwk` header. */
  keyPair: DPoPKeyPair;
  /**
   * Signing algorithm. Inferred from the JWK pair's `alg`, or from a key that serves one algorithm.
   * Required for a `CryptoKey` pair.
   */
  algorithm?: DPoPAlgorithm;
  /**
   * Unique proof identifier. Must be a non-empty string.
   * @default crypto.randomUUID()
   */
  jti?: string;
  /**
   * Creation time in NumericDate seconds.
   * @default the current Unix second
   */
  iat?: number;
  /** Expiration time in NumericDate seconds. The proof has no `exp` when omitted. */
  exp?: number;
  /** Earliest acceptance time in NumericDate seconds. The proof has no `nbf` when omitted. */
  nbf?: number;
  /** Nonce the server supplied: printable ASCII without space, `"` or `\`. */
  nonce?: string;
  /** The non-empty ASCII access token the proof is bound to. Its SHA-256 hash is written to `ath`. */
  accessToken?: { token: string };
}

export interface DPoPVerifyResult {
  /** The verified proof claims. */
  payload: DPoPPayload;
  /** RFC 7638 SHA-256 thumbprint of the proof's public key, the value a `cnf.jkt` binds. */
  thumbprint: string;
}

export interface DPoPVerifyOptions {
  /** Accepted signing algorithms. Must be non-empty. */
  algorithms: DPoPAlgorithm[];
  /** Maximum proof age in seconds, measured from `iat`. Must be positive and finite. */
  maxTokenAge: number;
  /**
   * Time the proof is verified against.
   * @default new Date()
   */
  currentDate?: Date;
  /**
   * Clock skew in seconds accepted on `iat`, `exp` and `nbf`. Must be finite and non-negative.
   * @default 0
   */
  clockTolerance?: number;
  /** Expected nonce. A proof without it, or with another one, fails with `ERR_DPOP_NONCE_INVALID`. */
  nonce?: string;
  /**
   * The access token and the `cnf.jkt` thumbprint it is bound to. The proof's `ath` must match
   * `token` and its key must match `thumbprint`.
   */
  accessToken?: { token: string; thumbprint: string };
  /**
   * Replay check, called with a copy of the result once every other check passes.
   * Return `true` to accept the proof. Any other value, or a throw, fails with `ERR_DPOP_REPLAY`.
   * No replay storage is included: record the `jti` atomically.
   */
  consumeProof?: (result: DPoPVerifyResult) => boolean | Promise<boolean>;
}
