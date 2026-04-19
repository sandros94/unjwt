/**
 * Internal helpers shared across `jws.ts`, `jws-multi.ts`, `jwe.ts`, `jwe-multi.ts`.
 * Not part of the public API — do not re-export from `src/core/{jws,jwe}.ts`
 * or add to the `utils/` barrel.
 */

import type {
  JWK,
  JWEEncryptOptions,
  JWK_EC_Public,
  JWK_EC_Private,
  JWTClaimValidationOptions,
  JWTClaims,
} from "./types";
import type { JWTErrorCode } from "./error";
import { JWTError } from "./error";
import {
  base64UrlDecode,
  decodePayloadFromB64UrlSegment,
  inferJWEAllowedAlgorithms,
  inferJWSAllowedAlgorithms,
  isCryptoKey,
  isCryptoKeyPair,
  isJWK,
  safeJsonParse,
  textEncoder,
  validateJwtClaims,
} from "./utils";

// -----------------------------------------------------------------------------
// JWKSet candidate filter — used by JWS verify + JWE decrypt (compact & multi).
// -----------------------------------------------------------------------------

/**
 * Build a JWKSet candidate filter based on a header's `kid` + `alg`.
 *
 * A JWK is kept when its `kid` matches the header (or the header carries none)
 * AND either the key declares no `alg` or it matches the header's alg. Used
 * by `getJWKsFromSet` to narrow the retry set before cryptographic attempts.
 */
export function buildJWKSetFilter(
  header: { kid?: string; alg?: string } | undefined,
): (k: JWK) => boolean {
  const kid = header?.kid;
  const alg = header?.alg;
  return (k) => (!kid || k.kid === kid) && (!k.alg || k.alg === alg);
}

// -----------------------------------------------------------------------------
// ECDH-ES ephemeral key parser (JWE compact + multi).
// -----------------------------------------------------------------------------

/**
 * Normalize a user-provided ECDH-ES ephemeral key (CryptoKey, CryptoKeyPair,
 * `{ publicKey, privateKey }` object, or private JWK) into
 * `{ epk, epkPrivateKey }` pairs consumable by the encrypt-key primitive.
 */
export function parseEphemeralKey(
  ephemeralKey: NonNullable<JWEEncryptOptions["ecdh"]>["ephemeralKey"],
): { epk: CryptoKey | JWK_EC_Public; epkPrivateKey: CryptoKey | JWK_EC_Private } {
  if (isCryptoKeyPair(ephemeralKey)) {
    return { epk: ephemeralKey.publicKey, epkPrivateKey: ephemeralKey.privateKey };
  }
  if (
    typeof ephemeralKey === "object" &&
    ephemeralKey !== null &&
    "publicKey" in ephemeralKey &&
    "privateKey" in ephemeralKey
  ) {
    if (!ephemeralKey.publicKey || !ephemeralKey.privateKey) {
      throw new JWTError(
        "ECDH-ES custom ephemeral key must include both publicKey and privateKey.",
        "ERR_JWK_INVALID",
      );
    }
    return { epk: ephemeralKey.publicKey, epkPrivateKey: ephemeralKey.privateKey };
  }
  if (isCryptoKey(ephemeralKey)) {
    if (ephemeralKey.type !== "private") {
      throw new JWTError(
        "ECDH-ES custom ephemeral CryptoKey must include private key material.",
        "ERR_JWK_INVALID",
      );
    }
    return { epk: ephemeralKey, epkPrivateKey: ephemeralKey };
  }
  if (isJWK(ephemeralKey)) {
    if (!("d" in ephemeralKey) || typeof ephemeralKey.d !== "string") {
      throw new JWTError(
        'ECDH-ES custom ephemeral JWK must include private parameter "d".',
        "ERR_JWK_INVALID",
      );
    }
    return {
      epk: ephemeralKey as JWK_EC_Public,
      epkPrivateKey: ephemeralKey as JWK_EC_Private,
    };
  }
  throw new JWTError("Unsupported ECDH-ES ephemeral key material provided.", "ERR_JWK_INVALID");
}

// -----------------------------------------------------------------------------
// JWS signing / verification key resolver (compact + multi).
// -----------------------------------------------------------------------------

/**
 * Resolve a key for JWS sign/verify:
 *   - Raw `Uint8Array` → imported as HMAC with the expected hash; a minimum
 *     key length is enforced based on the alg digest size.
 *   - RSA keys → `modulusLength ≥ 2048` enforced (RFC 7518 §3.3 / §3.5).
 *   - Other `CryptoKey`s → returned unchanged.
 */
export async function resolveSigningKey(
  alg: string,
  key: CryptoKey | Uint8Array<ArrayBuffer>,
  usage: "sign" | "verify",
): Promise<CryptoKey> {
  if (key instanceof Uint8Array) {
    const minBytes = Number.parseInt(alg.slice(2), 10) / 8;
    if (key.length < minBytes) {
      throw new JWTError(`${alg} requires a key of at least ${minBytes} bytes`, "ERR_JWK_INVALID");
    }
    return crypto.subtle.importKey(
      "raw",
      key,
      { name: "HMAC", hash: `SHA-${alg.slice(-3)}` },
      false,
      [usage],
    );
  }
  if (alg.startsWith("RS") || alg.startsWith("PS")) {
    const { modulusLength } = key.algorithm as RsaKeyAlgorithm;
    if (typeof modulusLength !== "number" || modulusLength < 2048) {
      throw new JWTError(
        `${alg} requires a key modulusLength of at least 2048 bits`,
        "ERR_JWK_INVALID",
      );
    }
  }
  return key;
}

// -----------------------------------------------------------------------------
// JWT claim validation guard (JWS verify + JWE decrypt, compact & multi).
// -----------------------------------------------------------------------------

/**
 * Run RFC 7519 JWT claim validation when the decoded payload looks like a
 * JSON object (not a `Uint8Array`, not forced-binary) and the caller hasn't
 * opted out with `validateClaims: false`.
 */
export function validateJwtClaimsIfJsonPayload(
  payload: unknown,
  options: JWTClaimValidationOptions & {
    forceUint8Array?: boolean;
    validateClaims?: boolean;
  },
): void {
  if (
    payload &&
    typeof payload === "object" &&
    !(payload instanceof Uint8Array) &&
    !options.forceUint8Array &&
    options.validateClaims !== false
  ) {
    validateJwtClaims(payload as JWTClaims, options);
  }
}

// -----------------------------------------------------------------------------
// Algorithm allowlist check (JWS verify + JWE decrypt, compact & multi).
// -----------------------------------------------------------------------------

/** Policy + error metadata for {@link checkAlgAllowed}. */
export interface AlgCheckContext {
  /** Infer the set of allowed algs from a key's shape. */
  infer: (key: unknown) => string[] | undefined;
  /**
   * When true, the JWK fast-path is skipped for `oct` keys — their declared
   * `alg` aliases to multiple wrap variants (e.g. a JWE oct JWK with
   * `alg: "A256GCM"` maps to both `A256GCMKW` and `dir`). True for JWE,
   * false for JWS where `alg` maps 1:1.
   */
  octAliasing: boolean;
  /** Error code emitted on rejection. */
  errorCode: "ERR_JWS_ALG_NOT_ALLOWED" | "ERR_JWE_ALG_NOT_ALLOWED";
  /** Error message prefix — `"Algorithm"` (JWS) or `"Key management algorithm"` (JWE). */
  label: string;
}

/** Static context for JWS signature verification. */
export const JWS_ALG_CTX: AlgCheckContext = /* @__PURE__ */ Object.freeze({
  infer: inferJWSAllowedAlgorithms,
  octAliasing: false,
  errorCode: "ERR_JWS_ALG_NOT_ALLOWED",
  label: "Algorithm",
});

/** Static context for JWE key-management algorithms. */
export const JWE_ALG_CTX: AlgCheckContext = /* @__PURE__ */ Object.freeze({
  infer: inferJWEAllowedAlgorithms,
  octAliasing: true,
  errorCode: "ERR_JWE_ALG_NOT_ALLOWED",
  label: "Key management algorithm",
});

/**
 * Verify the header-declared `alg` is allowed for the resolved key.
 *
 * Policy order:
 *   1. Explicit `options.algorithms` allowlist (when provided) — membership
 *      checked verbatim.
 *   2. Fast path — a JWK whose own `alg` is set names its only allowed
 *      algorithm. JWE skips this for `oct` JWKs (their alg aliases to
 *      multiple wrap variants; see `inferJWEAllowedAlgorithms`).
 *   3. Inference — derive the allowed set from the key shape and reject
 *      unless the declared `alg` is in it.
 *
 * Returns `undefined` when allowed, or a {@link JWTError} the caller decides
 * whether to throw (compact) or collect as `lastError` for the multi retry
 * loop.
 */
export function checkAlgAllowed(
  alg: string,
  key: unknown,
  explicit: readonly string[] | undefined,
  ctx: AlgCheckContext,
): JWTError | undefined {
  if (explicit) {
    return explicit.includes(alg) ? undefined : notAllowed(alg, ctx);
  }
  if (isJWK(key) && typeof key.alg === "string" && (!ctx.octAliasing || key.kty !== "oct")) {
    return key.alg === alg ? undefined : notAllowed(alg, ctx);
  }
  const inferred = ctx.infer(key);
  if (!inferred) {
    return new JWTError(
      `Cannot infer allowed ${ctx.label.toLowerCase()}s from this key; pass "options.algorithms" explicitly.`,
      ctx.errorCode,
    );
  }
  return inferred.includes(alg) ? undefined : notAllowed(alg, ctx);
}

function notAllowed(alg: string, ctx: AlgCheckContext): JWTError {
  return new JWTError(`${ctx.label} not allowed: ${alg}`, ctx.errorCode);
}

// -----------------------------------------------------------------------------
// Protected header decode (JWS verify + JWE decrypt, compact & multi).
// -----------------------------------------------------------------------------

/**
 * Parse the base64url-encoded JWS/JWE Protected Header. Returns an empty
 * header when `encoded` is absent (valid per RFC 7515 §7.2 / RFC 7516 §7.2.1);
 * throws `ERR_{family}_INVALID` on a malformed header.
 */
export function decodeProtectedHeader<T extends object>(
  encoded: string | undefined,
  family: "JWS" | "JWE",
): T {
  if (!encoded) return {} as T;
  try {
    return safeJsonParse<T>(base64UrlDecode(encoded));
  } catch {
    throw new JWTError(
      `Invalid ${family}: Protected header could not be decoded.`,
      `ERR_${family}_INVALID` as JWTErrorCode,
    );
  }
}

// -----------------------------------------------------------------------------
// JWS payload decoding (RFC 7797 aware) — compact verify + multi verify.
// -----------------------------------------------------------------------------

/**
 * Decode a JWS payload segment, honouring `b64: false` (RFC 7797) and
 * `forceUint8Array`.
 *
 * `useB64 = true` (default):
 *   - `forceUint8Array` → raw bytes from the base64url segment.
 *   - otherwise → parsed JSON when the decoded string looks like a JSON
 *     object / array, else the string verbatim.
 *
 * `useB64 = false`:
 *   - `forceUint8Array` → UTF-8 encode the raw payload string.
 *   - otherwise → the payload string as-is.
 */
export function decodeJWSPayload<T>(
  payloadSegment: string,
  useB64: boolean,
  forceUint8Array: boolean | undefined,
): T {
  if (useB64) {
    return decodePayloadFromB64UrlSegment<T>(payloadSegment, forceUint8Array) as T;
  }
  return (forceUint8Array ? textEncoder.encode(payloadSegment) : payloadSegment) as T;
}
