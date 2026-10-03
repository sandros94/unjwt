import { safeJsonParse } from "unsecure/sanitize";
import { textEncoder } from "unsecure/utils";
import { base64UrlParse } from "./utils/base64";

import type {
  JWK,
  ContentEncryptionAlgorithm,
  JWEEncryptOptions,
  JWK_EC_Public,
  JWK_EC_Private,
  JOSELimits,
  JWTClaimValidationOptions,
  JWTClaims,
  JWSAlgorithm,
  JOSEPayloadMode,
  JWEHeaderParameters,
  KeyManagementAlgorithm,
  UnwrapKeyOptions,
} from "./types";
import type { JWTErrorCode } from "./error";
import { JWTError } from "./error";
import {
  decodePayloadFromB64UrlSegment,
  decodePayloadFromBytes,
  inferJWEAllowedAlgorithms,
  inferJWSAllowedAlgorithms,
  isCryptoKey,
  isCryptoKeyPair,
  isJWK,
  assertCritShape,
  validateJwtClaims,
} from "./utils";
import {
  DEFAULT_PBES2_ITERATIONS,
  assertOctKeyLength,
  bitLengthCEK,
  bitLengthIV,
  bitLengthTag,
} from "./_crypto";

/**
 * RFC 7518 §4.6.1.2 / §4.6.1.3 — `apu` / `apv` feed the Concat KDF input
 * verbatim and arrive from the wire, so their size is bounded on both sides.
 */
export const MAX_PARTY_INFO_BYTES = 1024;

// -----------------------------------------------------------------------------
// Bounded work per call (JWS verify + JWE decrypt, compact & multi).
// -----------------------------------------------------------------------------

export { DEFAULT_PBES2_ITERATIONS };

/**
 * The work one JOSE call does when the caller names no {@link JOSELimits}:
 * 16 signatures, 16 recipients, 8 JWK Set candidates, and the PBKDF2 iterations
 * of four default-strength attempts for the whole call. Exported so the numbers
 * have one source.
 *
 * `pbes2Iterations` is four times {@link DEFAULT_PBES2_ITERATIONS}, so a token
 * whose recipients were all minted at the default cost is openable by the
 * fourth of them: a budget under that would refuse the holder of a key the
 * producer wrote. The worst case stays bounded by two other numbers — the
 * `recipients` limit caps how many attempts are made at all, and `maxIterations`
 * caps what any single attempt may claim.
 */
export const DEFAULT_JOSE_LIMITS: Readonly<Required<JOSELimits>> = /* @__PURE__ */ Object.freeze({
  signatures: 16,
  recipients: 16,
  keyCandidates: 8,
  pbes2Iterations: 4 * DEFAULT_PBES2_ITERATIONS,
});

/**
 * Read one limit, falling back to its default. Resolved once at the start of an
 * operation, so a malformed value is an option error regardless of what the
 * token turns out to contain.
 */
export function resolveLimit(limits: JOSELimits | undefined, name: keyof JOSELimits): number {
  const value = limits?.[name];
  if (value === undefined) return DEFAULT_JOSE_LIMITS[name];
  if (typeof value !== "number" || !Number.isInteger(value) || value < 1) {
    throw new JWTError(`"limits.${name}" must be a positive integer.`, "ERR_INVALID_OPTION");
  }
  return value;
}

/**
 * RFC 7515 §7.2.1 / RFC 7516 §7.2.1 — a JSON serialization may carry as many
 * signatures or recipients as its producer likes, and nothing about them is
 * integrity protected. The count is checked before any of them is looked at.
 */
export function assertEntryLimit(
  count: number,
  limit: number,
  options: { family: "JWS" | "JWE"; what: "signatures" | "recipients" },
): void {
  if (count <= limit) return;
  throw new JWTError(
    `Invalid ${options.family}: ${count} ${options.what} exceed the limit of ${limit}.`,
    `ERR_${options.family}_INVALID` as JWTErrorCode,
  );
}

/**
 * A JWK Set narrowed by `kid`/`alg`/`use` still decides how many keys one token
 * is tried against, so the surviving candidates are counted before the first
 * import. A set this wide is a lookup that has not been narrowed rather than a
 * token failure.
 */
export function assertCandidateLimit(count: number, limit: number): void {
  if (count <= limit) return;
  throw new JWTError(
    `${count} candidate keys exceed the limit of ${limit}; narrow the JWK Set with a "kid".`,
    "ERR_JWK_KEY_NOT_FOUND",
  );
}

/**
 * The gate every JWK Set read passes: a set that offers no key for this token
 * is a key-not-found failure, and one that offers more than the caller allows
 * is refused before a single candidate is tried.
 */
export function assertJWKSetCandidates(
  candidates: readonly unknown[],
  options: { limit: number; notFound: string },
): void {
  if (candidates.length === 0) {
    throw new JWTError(options.notFound, "ERR_JWK_KEY_NOT_FOUND");
  }
  assertCandidateLimit(candidates.length, options.limit);
}

/**
 * The PBKDF2 iterations one call may still spend. Every PBES2 attempt — the
 * single one of a compact token, or one per recipient and per JWK Set candidate
 * — charges its `p2c` here first, so the `p2c` values of a whole token are
 * summed rather than each being weighed on its own.
 */
export interface PBES2Budget {
  /**
   * Charge one PBES2 attempt. A `p2c` that no longer fits in what is left
   * throws, and the attempt is not made: the iterations are never spent, so a
   * recipient the caller does hold a key for is still tried on what remains.
   * A no-op under every other key management algorithm.
   */
  spend(alg: string, p2c: unknown): void;
}

/** Open a {@link PBES2Budget} of `limit` iterations for one call. */
export function createPBES2Budget(limit: number): PBES2Budget {
  let remaining = limit;
  return {
    spend(alg, p2c) {
      if (!alg.startsWith("PBES2")) return;
      // A `p2c` that is not a positive number is rejected by the PBES2
      // primitive itself; charging it here would move the budget on a value
      // that never derives anything.
      if (typeof p2c !== "number" || !(p2c > 0)) return;
      if (p2c > remaining) {
        throw new JWTError(`PBES2 iteration budget of ${limit} exhausted.`, "ERR_JWE_INVALID");
      }
      remaining -= p2c;
    },
  };
}

// -----------------------------------------------------------------------------
// Producer option gates (JWS sign + JWE encrypt, compact & multi).
// -----------------------------------------------------------------------------

/**
 * Serialize a protected header that is about to be signed or encrypted. A
 * header carrying a BigInt or a circular reference has no JSON form, which is
 * the caller's own option rather than a failure of the token being built.
 */
export function serializeProtectedHeader(header: object): string {
  try {
    return JSON.stringify(header);
  } catch (error) {
    throw new JWTError(
      "The protected header is not JSON-serializable.",
      "ERR_INVALID_OPTION",
      error,
    );
  }
}

/**
 * RFC 7515 §4.1.11 / RFC 7516 §4.1.13 — `crit` names the extension parameters a
 * recipient must understand. The producer holds itself to what every consumer
 * checks: the same shape, and an entry only for a parameter the header being
 * built actually carries — `"b64"` included.
 */
export function assertProducerCrit(header: Record<string, unknown>, family: "JWS" | "JWE"): void {
  const crit = header.crit;
  if (crit === undefined) return;
  assertCritShape(crit, { family, code: "ERR_INVALID_OPTION" });
  for (const param of crit) {
    if (Object.hasOwn(header, param)) continue;
    throw new JWTError(
      `"crit" lists "${param}", which the protected header does not carry.`,
      "ERR_INVALID_OPTION",
    );
  }
}

/**
 * RFC 7515 §4.1.11 / RFC 7516 §4.1.13 — `crit` must be integrity protected, so a
 * consumer refuses it in any unprotected header. The producer refuses to write
 * it there.
 */
export function assertNoUnprotectedCritOption(
  header: object | undefined,
  tier: string,
  family: "JWS" | "JWE",
): void {
  if (!header || !Object.hasOwn(header, "crit")) return;
  throw new JWTError(
    `${family} "crit" must be integrity protected; move it from the ${tier} header to the protected header.`,
    "ERR_INVALID_OPTION",
  );
}

/**
 * RFC 7518 §4.6.1.2 / §4.6.1.3 — `apu` / `apv` are bytes, and the consumer
 * bounds their size (see {@link MAX_PARTY_INFO_BYTES}), so a producer that
 * exceeds it would mint a token nothing can open.
 */
export function assertProducerPartyInfo(name: "apu" | "apv", value: unknown): void {
  if (!(value instanceof Uint8Array)) {
    throw new JWTError(
      `"${name === "apu" ? "partyUInfo" : "partyVInfo"}" (${name}) must be a Uint8Array.`,
      "ERR_INVALID_OPTION",
    );
  }
  if (value.length > MAX_PARTY_INFO_BYTES) {
    throw new JWTError(
      `"${name === "apu" ? "partyUInfo" : "partyVInfo"}" (${name}) must not exceed ${MAX_PARTY_INFO_BYTES} bytes (got ${value.length}).`,
      "ERR_INVALID_OPTION",
    );
  }
}

/**
 * RFC 7518 §5 — the CEK size is fixed by `enc`. A caller-supplied key of any
 * other size is a malformed option, not a token or key-material failure.
 */
export function assertProducerCEK(
  cek: Uint8Array<ArrayBuffer> | undefined,
  enc: ContentEncryptionAlgorithm,
): void {
  if (cek === undefined) return;
  const expected = bitLengthCEK(enc) >> 3;
  if (!(cek instanceof Uint8Array) || cek.length !== expected) {
    throw new JWTError(
      `"cek" must be ${expected} bytes for ${enc} (got ${cek instanceof Uint8Array ? cek.length : typeof cek}).`,
      "ERR_INVALID_OPTION",
    );
  }
}

/** RFC 7518 §5.2 / §5.3 — the content IV length is fixed by `enc`. */
export function assertProducerIV(
  iv: Uint8Array<ArrayBuffer> | undefined,
  enc: ContentEncryptionAlgorithm,
): void {
  if (iv === undefined) return;
  const expected = bitLengthIV(enc) >> 3;
  if (!(iv instanceof Uint8Array) || iv.length !== expected) {
    throw new JWTError(
      `"contentEncryptionIV" must be ${expected} bytes for ${enc} (got ${iv instanceof Uint8Array ? iv.length : typeof iv}).`,
      "ERR_INVALID_OPTION",
    );
  }
}

// -----------------------------------------------------------------------------
// JWKSet candidate filter — used by JWS verify + JWE decrypt (compact & multi).
// -----------------------------------------------------------------------------

/** What a JWK Set is being searched for: a signature check or a key unwrap. */
export type JWKSetOperation = "sig" | "enc";

/** `key_ops` values (RFC 7517 §4.3) that can serve each operation. */
const JWK_SET_KEY_OPS: Readonly<Record<JWKSetOperation, readonly string[]>> =
  /* @__PURE__ */ Object.freeze({
    sig: ["verify"],
    enc: ["unwrapKey", "decrypt", "deriveBits", "deriveKey"],
  });

/**
 * Build a JWK Set candidate filter for one operation.
 *
 * A set is public-key material: `oct` entries are dropped unless the caller
 * admits them with `allowSymmetric`, and so is anything that is not a JWK. Of
 * what remains an entry is kept when its `kid` matches the header (or the
 * header carries none), its `alg` matches (or it declares none), its `use` is
 * absent or names this operation, and its `key_ops` is absent or permits an
 * operation compatible with it. Used by `getJWKsFromSet` to narrow the retry
 * set before any cryptographic attempt.
 */
export function buildJWKSetFilter(
  header: { kid?: string; alg?: string } | undefined,
  options: { op: JWKSetOperation; allowSymmetric?: boolean },
): (k: JWK) => boolean {
  const kid = header?.kid;
  const alg = header?.alg;
  const { op, allowSymmetric } = options;
  const use = op;
  const keyOps = JWK_SET_KEY_OPS[op];
  return (k) => {
    if (!isJWK(k)) return false;
    if (k.kty === "oct" && !allowSymmetric) return false;
    if (kid && k.kid !== kid) return false;
    if (k.alg && k.alg !== alg) return false;
    if (k.use !== undefined && k.use !== use) return false;
    const ops = k.key_ops;
    if (ops !== undefined && !(Array.isArray(ops) && ops.some((o) => keyOps.includes(o)))) {
      return false;
    }
    return true;
  };
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
 *   - Raw `Uint8Array` → imported as HMAC with the expected hash under an `HS*`
 *     algorithm, and rejected under any other: bytes are a shared secret, never
 *     an RSA, EC or OKP key. A minimum key length is enforced based on the alg
 *     digest size.
 *   - RSA keys → `modulusLength ≥ 2048` enforced (RFC 7518 §3.3 / §3.5).
 *   - Other `CryptoKey`s → returned unchanged.
 */
export async function resolveSigningKey(
  alg: string,
  key: CryptoKey | Uint8Array<ArrayBuffer>,
  usage: "sign" | "verify",
): Promise<CryptoKey> {
  if (key instanceof Uint8Array) {
    if (!alg.startsWith("HS")) {
      throw new JWTError(
        `Raw key bytes are HMAC secrets; ${alg} needs an asymmetric key. Pass a JWK or a CryptoKey.`,
        "ERR_JWK_INVALID",
      );
    }
    assertOctKeyLength(key, alg);
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
 * Run RFC 7519 JWT claim validation on a payload the caller asked to be
 * decoded as JSON, unless they opted out with `validateClaims: false`.
 *
 * `"string"` and `"bytes"` payloads carry no claims to validate; asking for
 * them together with `validateClaims: true` is rejected as an option error by
 * {@link resolvePayloadMode}, so silently skipping validation here is never
 * mistaken for having run it.
 */
export function validateClaimsIfJson(
  payload: unknown,
  mode: JOSEPayloadMode,
  options: JWTClaimValidationOptions & { validateClaims?: boolean },
): void {
  if (mode !== "json" || options.validateClaims === false) return;
  validateJwtClaims(payload as JWTClaims, options);
}

// -----------------------------------------------------------------------------
// Payload mode + key shape option gates (JWS verify + JWE decrypt, compact & multi).
// -----------------------------------------------------------------------------

const PAYLOAD_MODES: ReadonlySet<string> = /* @__PURE__ */ new Set([
  "json",
  "string",
  "bytes",
] satisfies JOSEPayloadMode[]);

/**
 * Resolve the {@link JOSEPayloadMode} a verification or decryption runs under.
 *
 * `payload` is the option; `forceUint8Array` is its deprecated boolean alias
 * and may only agree with it. `validateClaims: true` is meaningful under
 * `"json"` alone — claim validation cannot be asked for over content that is
 * never parsed. Every contradiction is an `ERR_INVALID_OPTION`.
 */
export function resolvePayloadMode(options: {
  payload?: JOSEPayloadMode;
  forceUint8Array?: boolean;
  validateClaims?: boolean;
}): JOSEPayloadMode {
  const { payload, forceUint8Array, validateClaims } = options;

  if (payload !== undefined && !PAYLOAD_MODES.has(payload)) {
    throw new JWTError('"payload" must be "json", "string" or "bytes".', "ERR_INVALID_OPTION");
  }

  let mode: JOSEPayloadMode = payload ?? "json";
  if (forceUint8Array !== undefined) {
    if (payload === undefined) {
      mode = forceUint8Array ? "bytes" : "json";
    } else if (forceUint8Array !== (payload === "bytes")) {
      throw new JWTError(
        '"forceUint8Array" contradicts "payload"; pass "payload" alone.',
        "ERR_INVALID_OPTION",
      );
    }
  }

  if (validateClaims === true && mode !== "json") {
    throw new JWTError('"validateClaims" requires payload: "json".', "ERR_INVALID_OPTION");
  }

  return mode;
}

/**
 * The rejection every entry point shares for a `string` key: a password is the
 * only string JOSE has a use for, and only where PBES2 derives a key from it.
 */
export function stringKeyError(): JWTError {
  return new JWTError(
    "String keys are not accepted: pass an oct JWK or a Uint8Array secret, or import PEM text with importPEM().",
    "ERR_JWK_INVALID",
  );
}

/** Guard for JWS entry points, whose keys are never passwords. */
export function assertNotStringKey<K>(key: K): asserts key is Exclude<K, string> {
  if (typeof key === "string") throw stringKeyError();
}

/**
 * Resolve raw JWE key material before import: a `string` is a PBES2 password
 * and is UTF-8 encoded here (RFC 7518 §4.8.1), rejected under every other
 * `alg`. Anything else passes through to `importKey`.
 */
export function resolvePasswordKey<K>(
  alg: string,
  key: K,
): Exclude<K, string> | Uint8Array<ArrayBuffer> {
  if (typeof key !== "string") return key as Exclude<K, string>;
  if (!alg.startsWith("PBES2")) throw stringKeyError();
  return textEncoder.encode(key);
}

// -----------------------------------------------------------------------------
// Algorithm allowlist check (JWS verify + JWE decrypt, compact & multi).
// -----------------------------------------------------------------------------

/** Policy + error metadata for {@link checkAlgAllowed}. */
export interface AlgCheckContext {
  /** Infer the set of allowed algs from a key's shape. */
  infer: (key: unknown, options?: { allowSymmetric?: boolean }) => string[] | undefined;
  /**
   * When true, the JWK fast-path is skipped for `oct` keys — their declared
   * `alg` names a role rather than the header's `alg` (a JWE oct JWK with
   * `alg: "A256GCM"` is a CEK, so the algorithm it serves is `dir`). True for
   * JWE, false for JWS where `alg` maps 1:1.
   */
  octRoles: boolean;
  /** Error code emitted on rejection. */
  errorCode: "ERR_JWS_ALG_NOT_ALLOWED" | "ERR_JWE_ALG_NOT_ALLOWED";
  /** Error message prefix — `"Algorithm"` (JWS) or `"Key management algorithm"` (JWE). */
  label: string;
}

/** Static context for JWS signature verification. */
export const JWS_ALG_CTX: AlgCheckContext = /* @__PURE__ */ Object.freeze({
  infer: inferJWSAllowedAlgorithms,
  octRoles: false,
  errorCode: "ERR_JWS_ALG_NOT_ALLOWED",
  label: "Algorithm",
});

/** Static context for JWE key-management algorithms. */
export const JWE_ALG_CTX: AlgCheckContext = /* @__PURE__ */ Object.freeze({
  infer: inferJWEAllowedAlgorithms,
  octRoles: true,
  errorCode: "ERR_JWE_ALG_NOT_ALLOWED",
  label: "Key management algorithm",
});

/**
 * Verify the header-declared `alg` is allowed for the resolved key.
 *
 * Policy order:
 *   1. Explicit `algorithms` allowlist (when provided) — membership checked
 *      verbatim.
 *   2. Fast path — a JWK whose own `alg` is set names its only allowed
 *      algorithm. JWE skips this for `oct` JWKs, whose `alg` names a role
 *      instead (see `inferJWEAllowedAlgorithms`).
 *   3. Inference — derive the allowed set from the key shape and reject
 *      unless the declared `alg` is in it. For a JWK Set, `allowSymmetric`
 *      decides whether its `oct` entries contribute at all.
 *
 * Returns `undefined` when allowed, or a {@link JWTError} the caller decides
 * whether to throw (compact) or collect as `lastError` for the multi retry
 * loop.
 */
export function checkAlgAllowed(
  alg: string,
  key: unknown,
  options: {
    ctx: AlgCheckContext;
    algorithms?: readonly string[];
    allowSymmetric?: boolean;
  },
): JWTError | undefined {
  const { ctx, algorithms, allowSymmetric } = options;
  if (algorithms) {
    return algorithms.includes(alg) ? undefined : notAllowed(alg, ctx);
  }
  if (isJWK(key) && typeof key.alg === "string" && (!ctx.octRoles || key.kty !== "oct")) {
    return key.alg === alg ? undefined : notAllowed(alg, ctx);
  }
  const inferred = ctx.infer(key, { allowSymmetric });
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
// JWS algorithm support gate (compact verify + multi verify).
// -----------------------------------------------------------------------------

// The library's JWS algorithm set. `satisfies Record<JWSAlgorithm, true>` is the
// compile-time guard that keeps it in lockstep with the `JWSAlgorithm` union:
// a missing key and a stray key both fail the type check.
const JWS_ALGORITHM_SET: ReadonlySet<string> = /* @__PURE__ */ new Set(
  Object.keys({
    HS256: true,
    HS384: true,
    HS512: true,
    RS256: true,
    RS384: true,
    RS512: true,
    PS256: true,
    PS384: true,
    PS512: true,
    ES256: true,
    ES384: true,
    ES512: true,
    Ed25519: true,
    EdDSA: true,
  } satisfies Record<JWSAlgorithm, true>),
);

/**
 * Reject a header-declared `alg` the library cannot verify — `"none"`
 * (RFC 7518 §3.6 Unsecured JWS) and anything outside {@link JWSAlgorithm} —
 * before any key import or WebCrypto call. Returns `undefined` when the alg is
 * supported, or the {@link JWTError} the caller throws (compact) or collects
 * per signature (multi).
 */
export function checkJWSAlgSupported(alg: string): JWTError | undefined {
  if (alg === "none") {
    return new JWTError('"none" is not a valid signing algorithm', "ERR_JWS_ALG_NOT_ALLOWED");
  }
  if (!JWS_ALGORITHM_SET.has(alg)) {
    return new JWTError(`Algorithm not supported: ${alg}`, "ERR_JWS_ALG_NOT_ALLOWED");
  }
  return undefined;
}

/**
 * RFC 7797 §6 — an unencoded payload (`b64: false`) is only honoured when
 * `"b64"` is integrity protected by being listed in `crit`. Returns the
 * {@link JWTError} to throw (compact) or collect (multi) otherwise.
 */
export function checkJWSB64Crit(header: { b64?: boolean; crit?: unknown }): JWTError | undefined {
  if (header.b64 !== false) return undefined;
  if (Array.isArray(header.crit) && header.crit.includes("b64")) return undefined;
  return new JWTError(
    'Invalid JWS: "b64" must be listed in "crit" (RFC 7797 §6).',
    "ERR_JWS_INVALID",
  );
}

/**
 * Settle `b64` on a protected header being built. `b64: true` is the default
 * (RFC 7797 §3) and is dropped — unless `crit` lists it, since a listed
 * parameter must be present (RFC 7515 §4.1.11). `b64: false` must be listed in
 * `crit` (RFC 7797 §6), so `"b64"` is added there, creating `crit` when absent
 * and never duplicating the entry.
 */
export function applyB64Header(header: { b64?: boolean; crit?: string[] }): void {
  if (header.b64 === true) {
    if (!(Array.isArray(header.crit) && header.crit.includes("b64"))) delete header.b64;
    return;
  }
  if (header.b64 !== false) return;
  const crit = header.crit;
  if (crit === undefined) header.crit = ["b64"];
  else if (Array.isArray(crit) && !crit.includes("b64")) header.crit = [...crit, "b64"];
}

/**
 * The rejection a compact entry point raises for a token that is not a string:
 * `split` would otherwise decide the shape of the failure, or throw a raw
 * `TypeError` before a single segment is looked at.
 */
export function assertCompactToken(token: unknown, family: "JWS" | "JWE"): asserts token is string {
  if (typeof token !== "string") {
    throw new JWTError(
      `Invalid ${family}: token must be a string.`,
      `ERR_${family}_INVALID` as JWTErrorCode,
    );
  }
}

/**
 * The rejection a JSON-serialization helper raises for an argument that is not
 * an object — there is no serialization to read members off.
 */
export function assertSerializationObject(
  value: unknown,
  family: "JWS" | "JWE",
): asserts value is object {
  if (!isJSONObject(value)) {
    throw new JWTError(
      `Invalid ${family} JSON Serialization: expected an object.`,
      `ERR_${family}_INVALID_SERIALIZATION` as JWTErrorCode,
    );
  }
}

/**
 * RFC 7515 §7.2.1 / RFC 7516 §7.2.1 — a `signatures[]` / `recipients[]` entry
 * (or the JWE envelope itself) is a JSON object, each header member listed in
 * `objects` is a JSON object when present, and each base64url member listed in
 * `strings` is a string when present. For an entry, a failure condemns that
 * entry alone: the caller records the returned error and moves on to the next.
 */
export function checkSerializationEntry(
  entry: unknown,
  options: {
    family: "JWS" | "JWE";
    label: string;
    objects: readonly string[];
    strings: readonly string[];
  },
): JWTError | undefined {
  const { family, label, objects, strings } = options;
  const code = `ERR_${family}_INVALID` as JWTErrorCode;
  if (!isJSONObject(entry)) {
    return new JWTError(`Invalid ${family}: ${label} must be a JSON object.`, code);
  }
  for (const member of objects) {
    if (entry[member] !== undefined && !isJSONObject(entry[member])) {
      return new JWTError(`Invalid ${family}: ${label} "${member}" must be a JSON object.`, code);
    }
  }
  for (const member of strings) {
    if (entry[member] !== undefined && typeof entry[member] !== "string") {
      return new JWTError(`Invalid ${family}: ${label} "${member}" must be a string.`, code);
    }
  }
  return undefined;
}

/**
 * A key-lookup function is caller code: whatever it throws means the key for
 * this token could not be resolved, so it surfaces as `ERR_JWK_KEY_NOT_FOUND`
 * with the thrown value as `cause`. A {@link JWTError} it raises itself is its
 * own verdict and passes through.
 */
export function asKeyLookupError(error: unknown, what: string): JWTError {
  if (error instanceof JWTError) return error;
  return new JWTError(`Key lookup failed for ${what}.`, "ERR_JWK_KEY_NOT_FOUND", error);
}

/**
 * Normalize any non-{@link JWTError} raised while importing, resolving or
 * using a verification key (WebCrypto `TypeError`/`DOMException`, codec
 * `SyntaxError`, …) into `ERR_JWK_INVALID`, keeping the original as `cause`.
 * `JWTError`s pass through untouched.
 */
export function asKeyUsageError(error: unknown, alg: string): JWTError {
  if (error instanceof JWTError) return error;
  return new JWTError(`Key is not usable for ${alg}.`, "ERR_JWK_INVALID", error);
}

// -----------------------------------------------------------------------------
// JWE algorithm, header and segment gates (compact decrypt + multi decrypt).
// -----------------------------------------------------------------------------

// The key management algorithms `unwrapKey` implements. `KeyManagementAlgorithm`
// is wider — it also carries the bare `A*GCM` spellings an `oct` JWK may declare
// for its `A*GCMKW` / `dir` use — so the guard is `Partial<Record<…>>`: a stray
// or misspelled entry fails the type check, a deliberate omission does not.
const JWE_ALGORITHM_SET: ReadonlySet<string> = /* @__PURE__ */ new Set(
  Object.keys({
    "dir": true,
    "A128KW": true,
    "A192KW": true,
    "A256KW": true,
    "A128GCMKW": true,
    "A192GCMKW": true,
    "A256GCMKW": true,
    "PBES2-HS256+A128KW": true,
    "PBES2-HS384+A192KW": true,
    "PBES2-HS512+A256KW": true,
    "RSA-OAEP": true,
    "RSA-OAEP-256": true,
    "RSA-OAEP-384": true,
    "RSA-OAEP-512": true,
    "ECDH-ES": true,
    "ECDH-ES+A128KW": true,
    "ECDH-ES+A192KW": true,
    "ECDH-ES+A256KW": true,
  } satisfies Partial<Record<KeyManagementAlgorithm, true>>),
);

// The content encryption algorithms the library implements, each mapped to the
// form its CEK takes: AES-GCM decrypts from a `CryptoKey`, AES-CBC-HMAC needs
// the raw bytes to split into MAC and encryption halves.
const JWE_ENC_CEK_FORMAT = /* @__PURE__ */ Object.freeze({
  "A128GCM": "cryptokey",
  "A192GCM": "cryptokey",
  "A256GCM": "cryptokey",
  "A128CBC-HS256": "raw",
  "A192CBC-HS384": "raw",
  "A256CBC-HS512": "raw",
} satisfies Record<ContentEncryptionAlgorithm, "cryptokey" | "raw">);

/**
 * RFC 7518 §4.5 — under `dir` the key *is* the content encryption key, so a JWK
 * that declares an `alg` must declare either `dir` or exactly the `enc` it is a
 * CEK for: a key minted for `A256GCM` is not a CEK for `A128CBC-HS256`.
 * Wrapping keys (`A*KW`, `A*GCMKW`, PBES2) never reach this check — importing
 * them under `dir` already fails on their declared algorithm.
 */
export function assertDirectKeyRole(key: unknown, enc: string | undefined): void {
  if (!isJWK(key) || typeof key.alg !== "string" || key.alg === "dir") return;
  if (enc !== undefined && key.alg === enc) return;
  throw new JWTError(
    `JWK "alg" is "${key.alg}" but "dir" requires a key declared as "dir" or as the token's "enc" (${enc ?? "unknown"}).`,
    "ERR_JWK_INVALID",
  );
}

/** `dir` and bare `ECDH-ES` agree on the CEK directly — RFC 7518 §4.5 / §4.6, RFC 7516 §5.2 step 6. */
export const JWE_DIRECT_ALGS: ReadonlySet<string> = /* @__PURE__ */ new Set(["dir", "ECDH-ES"]);

/**
 * Reject a header-declared key management `alg` the library cannot unwrap —
 * `"none"` and anything outside the implemented set — before the caller's
 * allowlist, any key import or WebCrypto call.
 */
export function checkJWEAlgSupported(alg: string): JWTError | undefined {
  if (alg === "none") {
    return new JWTError(
      '"none" is not a valid key management algorithm',
      "ERR_JWE_ALG_NOT_ALLOWED",
    );
  }
  if (!JWE_ALGORITHM_SET.has(alg)) {
    return new JWTError(
      `Key management algorithm not supported: ${alg}`,
      "ERR_JWE_ALG_NOT_ALLOWED",
    );
  }
  return undefined;
}

/** Reject an `enc` outside {@link ContentEncryptionAlgorithm}. */
export function checkJWEEncSupported(enc: string): JWTError | undefined {
  if (Object.hasOwn(JWE_ENC_CEK_FORMAT, enc)) return undefined;
  return new JWTError(`Invalid JWE: unsupported "enc" ${enc}`, "ERR_JWE_INVALID");
}

/** The CEK form `enc` consumes. Call only after {@link checkJWEEncSupported}. */
export function cekFormatForEnc(enc: ContentEncryptionAlgorithm): "cryptokey" | "raw" {
  return JWE_ENC_CEK_FORMAT[enc];
}

/**
 * The unwrap options one JWE recipient is opened with: the algorithms it was
 * encrypted under, the key management parameters its header carries, and the
 * caller's own unwrap overrides. Parameters absent from the header are left
 * off rather than set to `undefined`, so the primitive sees only what the
 * token actually declared.
 */
export function buildUnwrapKeyOptions(
  header: JWEHeaderParameters,
  algorithms: { alg: KeyManagementAlgorithm; enc: ContentEncryptionAlgorithm },
  options:
    | Pick<
        UnwrapKeyOptions,
        "keyUsage" | "unwrappedKeyAlgorithm" | "extractable" | "minIterations" | "maxIterations"
      >
    | undefined,
): UnwrapKeyOptions {
  const { alg, enc } = algorithms;
  const opts: UnwrapKeyOptions = {
    alg,
    enc,
    format: cekFormatForEnc(enc),
    keyUsage: options?.keyUsage || ["decrypt"],
  };
  if (header.iv) opts.iv = header.iv;
  if (header.tag) opts.tag = header.tag;
  if (header.p2s) opts.p2s = header.p2s;
  if (header.p2c) opts.p2c = header.p2c;
  if (header.epk) opts.epk = header.epk;
  if (header.apu) opts.apu = header.apu;
  if (header.apv) opts.apv = header.apv;
  if (options?.unwrappedKeyAlgorithm) opts.unwrappedKeyAlgorithm = options.unwrappedKeyAlgorithm;
  if (options?.extractable) opts.extractable = options.extractable;
  if (options?.minIterations !== undefined) opts.minIterations = options.minIterations;
  if (options?.maxIterations !== undefined) opts.maxIterations = options.maxIterations;
  return opts;
}

/**
 * RFC 7516 §5.2 step 6 / §7.2.1 — direct key agreement carries no wrapped CEK,
 * so a non-empty encrypted key is a forgery attempt rather than ignorable bytes.
 */
export function checkJWEDirectEncryptedKey(
  alg: string,
  encryptedKey: string | undefined,
): JWTError | undefined {
  if (!JWE_DIRECT_ALGS.has(alg) || !encryptedKey) return undefined;
  return new JWTError(`Invalid JWE: Encrypted key must be empty for ${alg}.`, "ERR_JWE_INVALID");
}

/**
 * RFC 7518 §5.2 / §5.3 — the IV and authentication tag sizes are fixed by `enc`.
 * Without this the AES-GCM primitive would accept any split of
 * `ciphertext ‖ tag`, leaving the segment boundary attacker-controlled, and the
 * AES-CBC-HMAC comparison would run against a truncated tag.
 */
export function checkJWEContentSegments(
  enc: ContentEncryptionAlgorithm,
  iv: Uint8Array<ArrayBuffer>,
  tag: Uint8Array<ArrayBuffer>,
): JWTError | undefined {
  const ivBytes = bitLengthIV(enc) >> 3;
  if (iv.length !== ivBytes) {
    return new JWTError(
      `Invalid JWE: Initialization vector must be ${ivBytes} bytes for ${enc} (got ${iv.length}).`,
      "ERR_JWE_INVALID",
    );
  }
  const tagBytes = bitLengthTag(enc) >> 3;
  if (tag.length !== tagBytes) {
    return new JWTError(
      `Invalid JWE: Authentication tag must be ${tagBytes} bytes for ${enc} (got ${tag.length}).`,
      "ERR_JWE_INVALID",
    );
  }
  return undefined;
}

/** RFC 7516 §4.1.3 — the library does not implement compression. */
export function checkJWEZip(header: object | undefined): JWTError | undefined {
  if (!header || !Object.hasOwn(header, "zip")) return undefined;
  return new JWTError("Invalid JWE: compression is not supported.", "ERR_JWE_INVALID");
}

/** Producer-side counterpart of {@link checkJWEZip}. */
export function assertNoZipOption(header: object | undefined, tier: string): void {
  if (!header || !Object.hasOwn(header, "zip")) return;
  throw new JWTError(
    `JWE compression ("zip") is not supported; remove it from the ${tier} header.`,
    "ERR_INVALID_OPTION",
  );
}

/** RFC 7516 §4.1.13 — `crit` is only meaningful when it is integrity protected. */
export function checkJWEUnprotectedCrit(header: object | undefined): JWTError | undefined {
  if (!header || !Object.hasOwn(header, "crit")) return undefined;
  return new JWTError(
    'Invalid JWE: "crit" must be integrity protected (RFC 7516 §4.1.13).',
    "ERR_JWE_INVALID",
  );
}

// -----------------------------------------------------------------------------
// `typ` header comparison (RFC 7515 §4.1.9 / RFC 7516 §4.1.11).
// -----------------------------------------------------------------------------

/**
 * Compare an expected `typ` against a header's `typ` under RFC 7515 §4.1.9
 * media-type semantics: the comparison is case-insensitive and the
 * `application/` prefix may be omitted when the remainder contains no `"/"`,
 * so `"at+jwt"`, `"AT+JWT"` and `"application/at+jwt"` all match.
 */
export function typMatches(expected: string, actual: unknown): boolean {
  if (typeof actual !== "string") return false;
  return normalizeTyp(expected) === normalizeTyp(actual);
}

/** Refuse a JWE whose `typ` is not the one the caller expects. */
export function assertJWETyp(expected: string | undefined, actual: string | undefined): void {
  if (expected && !typMatches(expected, actual)) {
    throw new JWTError(
      `Invalid JWE: "typ" (Type) Header Parameter mismatch. Expected "${expected}", got "${actual}".`,
      "ERR_JWE_INVALID",
    );
  }
}

function normalizeTyp(typ: string): string {
  const lowered = typ.toLowerCase();
  return lowered.includes("/") ? lowered : `application/${lowered}`;
}

// -----------------------------------------------------------------------------
// Protected header decode (JWS verify + JWE decrypt, compact & multi).
// -----------------------------------------------------------------------------

/**
 * Parse the base64url-encoded JWS/JWE Protected Header. Returns an empty
 * header when `encoded` is absent (valid per RFC 7515 §7.2 / RFC 7516 §7.2.1);
 * throws `ERR_{family}_INVALID` on a malformed header, with the originating
 * `UnsecureError` (base64url or JSON) as `cause`.
 */
export function decodeProtectedHeader<T extends object>(
  encoded: string | undefined,
  family: "JWS" | "JWE",
): T {
  if (!encoded) return {} as T;
  let parsed: unknown;
  try {
    parsed = safeJsonParse<T>(base64UrlParse(encoded));
  } catch (error) {
    throw new JWTError(
      `Invalid ${family}: Protected header could not be decoded.`,
      `ERR_${family}_INVALID` as JWTErrorCode,
      error,
    );
  }
  // RFC 7515 §4 / RFC 7516 §4: the header is a JSON object. `null`, arrays and
  // JSON scalars parse fine but must not reach the header consumers.
  if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) {
    throw new JWTError(
      `Invalid ${family}: Protected header must be a JSON object.`,
      `ERR_${family}_INVALID` as JWTErrorCode,
    );
  }
  return parsed as T;
}

// -----------------------------------------------------------------------------
// Wire segment decode (JWS/JWE/JWK) — the single codec-failure boundary.
// -----------------------------------------------------------------------------

/**
 * Decode a base64url-encoded wire segment or key field into bytes, translating
 * a codec failure into `ERR_{family}_INVALID` with the originating
 * `UnsecureError` as `cause`. Decoding is always strict — the canonical,
 * unpadded RFC 7515 §2 encoding is the contract for token material.
 */
export function decodeSegment(
  encoded: string,
  options: { family: "JWS" | "JWE" | "JWK"; what: string },
): Uint8Array<ArrayBuffer> {
  try {
    return base64UrlParse(encoded, { returnAs: "uint8array" });
  } catch (error) {
    throw new JWTError(
      `Invalid ${options.family}: ${options.what} could not be decoded.`,
      `ERR_${options.family}_INVALID` as JWTErrorCode,
      error,
    );
  }
}

// -----------------------------------------------------------------------------
// JWS payload decoding (RFC 7797 aware) — compact verify + multi verify.
// -----------------------------------------------------------------------------

/**
 * Decode a JWS payload segment under the caller-declared
 * {@link JOSEPayloadMode}, honouring `b64: false` (RFC 7797) — where the
 * segment carries the payload text itself rather than its Base64URL encoding.
 *
 * A segment that cannot be Base64URL-decoded fails as
 * `"Invalid JWS: Payload could not be decoded."`; one that does not meet the
 * declared mode fails with that mode's rejection.
 */
export function decodeJWSPayload<T>(
  payloadSegment: string,
  useB64: boolean,
  mode: JOSEPayloadMode,
): T {
  if (!useB64) {
    if (mode === "string") return payloadSegment as T;
    return decodePayloadFromBytes<T>(textEncoder.encode(payloadSegment), {
      payload: mode,
      family: "JWS",
    }) as T;
  }
  try {
    return decodePayloadFromB64UrlSegment<T>(payloadSegment, {
      payload: mode,
      family: "JWS",
    }) as T;
  } catch (error) {
    if (error instanceof JWTError) throw error;
    throw new JWTError("Invalid JWS: Payload could not be decoded.", "ERR_JWS_INVALID", error);
  }
}

function isJSONObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}
