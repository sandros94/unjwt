import type {
  JWSAlgorithm,
  JWSAsymmetricPrivateJWK,
  JWSAsymmetricPublicJWK,
} from "../core/types/jws.ts";

/** Closed set of supported asymmetric JWS algorithms. */
export type DPoPAlgorithm = Exclude<JWSAlgorithm, `HS${string}`>;

/** The request method and absolute HTTP(S) URL; a Web Request satisfies this shape. */
export interface DPoPTarget {
  method: string;
  url: string;
}

/** Explicit signing pair; the private CryptoKey need not be extractable. */
export type DPoPKeyPair =
  | CryptoKeyPair
  | { privateKey: JWSAsymmetricPrivateJWK; publicKey: JWSAsymmetricPublicJWK };

export interface DPoPPayload {
  jti: string;
  iat: number;
  exp?: number;
  nbf?: number;
  htm: string;
  htu: string;
  nonce?: string;
  ath?: string;
  [claim: string]: unknown;
}

export interface DPoPCreateOptions {
  keyPair: DPoPKeyPair;
  /** Inferred from JWK alg metadata or an unambiguous key shape. Required for CryptoKey pairs. */
  algorithm?: DPoPAlgorithm;
  /** Unique proof identifier. Defaults to a fresh UUID v4 for each proof. */
  jti?: string;
  /** Creation time in NumericDate seconds. Defaults to the current Unix second. */
  iat?: number;
  /** Expiration time in NumericDate seconds. Omitted by default. */
  exp?: number;
  /** Earliest acceptance time in NumericDate seconds. Omitted by default. */
  nbf?: number;
  nonce?: string;
  /** Raw ASCII access token whose SHA-256 digest becomes `ath`. */
  accessToken?: { token: string };
}

export interface DPoPVerifyResult {
  payload: DPoPPayload;
  /** SHA-256 RFC 7638 thumbprint of the authenticated public key. */
  thumbprint: string;
}

export interface DPoPVerifyOptions {
  algorithms: DPoPAlgorithm[];
  /** Positive finite maximum proof age, in seconds. */
  maxTokenAge: number;
  currentDate?: Date;
  /** Finite, non-negative clock tolerance, in seconds. Default: 0. */
  clockTolerance?: number;
  nonce?: string;
  /** The raw access token and its authenticated `cnf.jkt` binding, supplied together. */
  accessToken?: { token: string; thumbprint: string };
  /** Atomically consume a validated proof; false rejects replay. No replay storage is provided. */
  consumeProof?: (result: DPoPVerifyResult) => boolean | Promise<boolean>;
}
