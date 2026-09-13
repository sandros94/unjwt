import { sanitizeObjectCopy } from "unsecure/sanitize";
import { textEncoder, textDecoder } from "unsecure/utils";
import { base64UrlStringify } from "./utils/base64";

import type {
  JWKSet,
  JWSVerifyJWK,
  JWKLookupFunction,
  JWSAlgorithm,
  JWSHeaderParameters,
  JWSProtectedHeader,
  JOSEPayload,
  JOSEPayloadMode,
  JWTClaims,
  JWSGeneralSerialization,
  JWSGeneralSignature,
  JWSFlattenedSerialization,
  JWSMultiSigner,
  JWSMultiSignOptions,
  JWSMultiVerifyOptions,
  JWSMultiVerifyResult,
  JWSMultiVerifyAllOptions,
  JWSMultiVerifyOutcome,
} from "./types";

import { importKey, getJWKsFromSet } from "./jwk";
import { sign as joseSign, verify as joseVerify } from "./_crypto";
import type { JWTErrorCode } from "./error";
import { JWTError } from "./error";
import {
  isJWK,
  isJWKSet,
  applyTypCtyDefaults,
  computeJwtTimeClaims,
  getPlaintextBytes,
  inferJWSAllowedAlgorithms,
  validateCriticalHeadersJWS,
} from "./utils";
import {
  JWS_ALG_CTX,
  applyB64Crit,
  assertProducerCrit,
  asKeyLookupError,
  asKeyUsageError,
  assertJWKSetCandidates,
  assertSerializationObject,
  assertEntryLimit,
  buildJWKSetFilter,
  checkAlgAllowed,
  checkJWSAlgSupported,
  checkJWSB64Crit,
  assertNotStringKey,
  decodeJWSPayload,
  decodeProtectedHeader,
  resolveLimit,
  resolvePayloadMode,
  resolveSigningKey,
  serializeProtectedHeader,
  stringKeyError,
  typMatches,
  validateClaimsIfJson,
  decodeSegment,
} from "./_internal";

/**
 * Sign a payload with multiple signers using JWS General JSON Serialization
 * (RFC 7515 §7.2.1).
 *
 * The payload is shared across all signatures; each signer independently
 * produces a signature over `BASE64URL(its own protected header) . BASE64URL(payload)`
 * using its own algorithm: the signer's `alg` when given, else `key.alg` (JWK)
 * or the CryptoKey's own WebCrypto algorithm. When none of those resolve it
 * throws `ERR_JWS_SIGNER_ALG_INFERENCE`.
 *
 * Per RFC 7797 §3, `b64` MUST be consistent across every signer. If one
 * signer sets `b64: false` in its protected header, every other signer
 * must match or this function throws `ERR_JWS_B64_INCONSISTENT`; `"b64"` is
 * then added to each signer's `crit` (RFC 7797 §6).
 *
 * @example
 * const jws = await signMulti({ sub: "u1" }, [
 *   { key: alicePrivateJwk },
 *   { key: bobPrivateJwk, protectedHeader: { typ: "vc+jwt" } },
 * ], { expiresIn: "1h" });
 */
export async function signMulti(
  payload: JOSEPayload,
  signers: JWSMultiSigner[],
  options: JWSMultiSignOptions = {},
): Promise<JWSGeneralSerialization> {
  if (!Array.isArray(signers) || signers.length === 0) {
    throw new JWTError("signMulti requires at least one signer.", "ERR_JWS_INVALID");
  }

  for (const signer of signers) assertNotStringKey(signer?.key);

  const resolvedAlgs: JWSAlgorithm[] = signers.map((s, i) => _resolveSignerAlg(s, i));

  const b64 = _resolveB64(signers);

  const computedPayload: JWTClaims | undefined = computeJwtTimeClaims(payload, options);
  const payloadBytes = getPlaintextBytes(computedPayload || payload);

  const payloadEncoded = b64 ? base64UrlStringify(payloadBytes) : textDecoder.decode(payloadBytes);

  const wireSignatures: JWSGeneralSignature[] = [];
  for (let i = 0; i < signers.length; i++) {
    const signer = signers[i]!;
    const alg = resolvedAlgs[i]!;

    const protectedHeader = _buildSignerProtectedHeader(signer, alg, payload, b64);
    const unprotectedHeader = sanitizeObjectCopy(signer.unprotectedHeader) as
      | Record<string, unknown>
      | undefined;

    _assertDisjointHeaders(protectedHeader, unprotectedHeader);

    const protectedHeaderEncoded = base64UrlStringify(serializeProtectedHeader(protectedHeader));
    const signingInputBytes = textEncoder.encode(`${protectedHeaderEncoded}.${payloadEncoded}`);

    const signingKey = await resolveSigningKey(
      alg,
      await importKey(signer.key, { alg, expect: "private" }),
      "sign",
    );
    const signatureBytes = await joseSign(alg, signingKey, signingInputBytes);

    const wireSig: JWSGeneralSignature = {
      protected: protectedHeaderEncoded,
      signature: base64UrlStringify(signatureBytes),
    };
    if (unprotectedHeader && Object.keys(unprotectedHeader).length > 0) {
      wireSig.header = unprotectedHeader;
    }
    wireSignatures.push(wireSig);
  }

  return {
    payload: payloadEncoded,
    signatures: wireSignatures,
  };
}

/**
 * Verify a JWS in JSON Serialization form (General RFC 7515 §7.2.1 or
 * Flattened §7.2.2 — both accepted). Returns the first signature that
 * verifies against the supplied key.
 *
 * Matches signers by, in order: `kid` equality, `kty`/`crv`/length
 * compatibility, then trial verification. Set `strictSignerMatch: true`
 * to disable the trial fallback.
 *
 * Every signature-scoped failure (malformed header, rejected `alg`, header
 * overlap, undecodable signature, unusable key, bad signature) is collected
 * and the next signature is still attempted; the collected error surfaces only
 * when none verifies.
 *
 * For compact (string) tokens, use {@link verify}.
 */
export async function verifyMulti(
  jws: JWSGeneralSerialization | JWSFlattenedSerialization,
  keyOrLookup: CryptoKey | JWKSet | JWSVerifyJWK | Uint8Array<ArrayBuffer> | JWKLookupFunction,
  options: JWSMultiVerifyOptions & { payload: "bytes" },
): Promise<JWSMultiVerifyResult<Uint8Array<ArrayBuffer>>>;
export async function verifyMulti(
  jws: JWSGeneralSerialization | JWSFlattenedSerialization,
  keyOrLookup: CryptoKey | JWKSet | JWSVerifyJWK | Uint8Array<ArrayBuffer> | JWKLookupFunction,
  options: JWSMultiVerifyOptions & { payload: "string" },
): Promise<JWSMultiVerifyResult<string>>;
export async function verifyMulti(
  jws: JWSGeneralSerialization | JWSFlattenedSerialization,
  keyOrLookup: CryptoKey | JWKSet | JWSVerifyJWK | Uint8Array<ArrayBuffer> | JWKLookupFunction,
  options: JWSMultiVerifyOptions & { forceUint8Array: true },
): Promise<JWSMultiVerifyResult<Uint8Array<ArrayBuffer>>>;
export async function verifyMulti<T extends Record<string, unknown> = JWTClaims>(
  jws: JWSGeneralSerialization | JWSFlattenedSerialization,
  keyOrLookup: CryptoKey | JWKSet | JWSVerifyJWK | Uint8Array<ArrayBuffer> | JWKLookupFunction,
  options?: JWSMultiVerifyOptions,
): Promise<JWSMultiVerifyResult<T>>;
export async function verifyMulti<T extends JOSEPayload = JOSEPayload>(
  jws: JWSGeneralSerialization | JWSFlattenedSerialization,
  keyOrLookup: CryptoKey | JWKSet | JWSVerifyJWK | Uint8Array<ArrayBuffer> | JWKLookupFunction,
  options: JWSMultiVerifyOptions = {},
): Promise<JWSMultiVerifyResult<T>> {
  const payloadMode = resolvePayloadMode(options);
  const signatureLimit = resolveLimit(options.limits, "signatures");
  const keyCandidates = resolveLimit(options.limits, "keyCandidates");

  const general = _normalizeSerialization(jws);

  if (
    typeof general.payload !== "string" ||
    !Array.isArray(general.signatures) ||
    general.signatures.length === 0
  ) {
    throw new JWTError(
      "Invalid JWS JSON Serialization: missing payload or signatures.",
      "ERR_JWS_INVALID_SERIALIZATION",
    );
  }

  assertEntryLimit(general.signatures.length, signatureLimit, {
    family: "JWS",
    what: "signatures",
  });

  let lastError: JWTError | undefined;
  let cryptoAttempted = false;
  for (let i = 0; i < general.signatures.length; i++) {
    const wireSig = general.signatures[i]!;
    if (typeof wireSig.signature !== "string") {
      lastError = new JWTError(
        `Signature[${i}] is missing the "signature" field.`,
        "ERR_JWS_INVALID",
      );
      continue;
    }

    let protectedHeader: JWSProtectedHeader;
    try {
      protectedHeader = decodeProtectedHeader<JWSProtectedHeader>(wireSig.protected, "JWS");
    } catch (err) {
      lastError = err instanceof JWTError ? err : undefined;
      continue;
    }

    if (!protectedHeader.alg) {
      lastError = new JWTError(
        `Invalid JWS: Signature[${i}] protected header must have an "alg" property.`,
        "ERR_JWS_INVALID",
      );
      continue;
    }

    const alg = protectedHeader.alg;

    const headerError =
      checkJWSAlgSupported(alg) ??
      checkJWSB64Crit(protectedHeader) ??
      _checkUnprotectedCrit(wireSig.header);
    if (headerError) {
      lastError = headerError;
      continue;
    }

    const unprotectedHeader = sanitizeObjectCopy(wireSig.header) as JWSHeaderParameters | undefined;
    try {
      _assertDisjointHeaders(protectedHeader, unprotectedHeader);
    } catch (err) {
      lastError = _asJWTError(err, "ERR_JWS_INVALID");
      continue;
    }

    const effective = _mergeHeaders(protectedHeader, unprotectedHeader);

    if (options.typ && !typMatches(options.typ, protectedHeader.typ)) {
      lastError = new JWTError(
        `Invalid JWS: "typ" Header Parameter mismatch on signature[${i}]. Expected "${options.typ}", got "${protectedHeader.typ}".`,
        "ERR_JWS_INVALID",
      );
      continue;
    }

    let rawKeyMaterial: unknown;
    try {
      rawKeyMaterial =
        typeof keyOrLookup === "function"
          ? await (keyOrLookup as JWKLookupFunction)(
              effective as Parameters<JWKLookupFunction>[0],
              wireSig.protected ?? "",
            )
          : keyOrLookup;
    } catch (err) {
      lastError = asKeyLookupError(err, `signature[${i}]`);
      continue;
    }

    if (typeof rawKeyMaterial === "string") {
      lastError = stringKeyError();
      continue;
    }

    const algError = checkAlgAllowed(alg, rawKeyMaterial, {
      ctx: JWS_ALG_CTX,
      algorithms: options.algorithms,
      allowSymmetric: options.allowSymmetricJWKSet,
    });
    if (algError) {
      lastError = algError;
      continue;
    }

    if (options.strictSignerMatch && !_signerKeyMatches(effective, rawKeyMaterial)) {
      continue;
    }

    let signatureBytes: Uint8Array<ArrayBuffer>;
    try {
      signatureBytes = decodeSegment(wireSig.signature, { family: "JWS", what: "Signature" });
    } catch (err) {
      lastError = _asJWTError(err, "ERR_JWS_INVALID");
      continue;
    }
    const signingInputBytes = textEncoder.encode(`${wireSig.protected ?? ""}.${general.payload}`);

    cryptoAttempted = true;
    try {
      const verified = await _verifyWithKey(alg, rawKeyMaterial, {
        signature: signatureBytes,
        signingInput: signingInputBytes,
        kid: effective.kid,
        allowSymmetric: options.allowSymmetricJWKSet,
        keyCandidates,
      });
      if (!verified) {
        lastError = new JWTError("JWS signature verification failed.", "ERR_JWS_SIGNATURE_INVALID");
        continue;
      }

      validateCriticalHeadersJWS(protectedHeader, options.recognizedHeaders);

      const useB64 = protectedHeader.b64 !== false;
      const payload = decodeJWSPayload<T>(general.payload, useB64, payloadMode);

      validateClaimsIfJson(payload, payloadMode, options);

      const result: JWSMultiVerifyResult<T> = {
        payload,
        protectedHeader,
        signerIndex: i,
      };
      if (unprotectedHeader) result.signerHeader = unprotectedHeader;
      return result;
    } catch (err) {
      // Per-signature failures (bad signature, no/unusable key for THIS signer) are
      // collected so a later signature still gets its chance; anything else —
      // `crit` violations, claim failures — is a verdict on the token itself.
      const error = _asJWTError(err, "ERR_JWS_SIGNATURE_INVALID");
      if (!PER_SIGNATURE_ERROR_CODES.has(error.code)) throw error;
      lastError = error;
    }
  }

  // Strict mode: if no crypto was ever attempted (every signature filtered out
  // by alg / kid / kty mismatch), signal the match failure rather than the
  // filter reason. Crypto-level failures still surface as-is.
  if (options.strictSignerMatch && !cryptoAttempted) {
    throw new JWTError(
      "No signature matched the provided key under strictSignerMatch.",
      "ERR_JWS_NO_MATCHING_SIGNER",
    );
  }
  throw (
    lastError ?? new JWTError("JWS signature verification failed.", "ERR_JWS_SIGNATURE_INVALID")
  );
}

/**
 * Verify every signature in a JWS independently and return a per-signature
 * outcome array — the caller applies their own policy (all-must-verify,
 * M-of-N quorum, specific-signer checks, audit logs, etc.).
 *
 * Unlike {@link verifyMulti}, this function never throws on an individual
 * signature's failure — malformed protected headers, `"none"`/unsupported or
 * disallowed `alg`s, `b64: false` without `"b64"` in `crit`, `crit` in an
 * unprotected header, header-parameter overlap, malformed signature segments,
 * `typ` mismatches, key-resolver errors, keys unusable for the declared `alg`,
 * bad signatures, critical header violations, and JWT claim failures are all
 * collected into {@link JWSMultiVerifyOutcome} entries with `verified: false`.
 *
 * Structural errors in the envelope itself (non-object input, missing
 * `payload` / `signatures[]`) still throw `ERR_JWS_INVALID_SERIALIZATION`
 * — there's no per-signature outcome to return in that case.
 *
 * Requires a {@link JWKLookupFunction} because different signatures almost
 * always need different keys. Wrap a static `JWKSet` as `(header) => mySet`
 * if that's all you have.
 *
 * @example
 * // All signatures must verify
 * const outcomes = await verifyMultiAll(jws, myKeyResolver);
 * if (!outcomes.every((o) => o.verified)) {
 *   throw new Error("not all signatures verified");
 * }
 *
 * @example
 * // Quorum — at least 2 valid signatures from a recognised signer set
 * const outcomes = await verifyMultiAll(jws, myKeyResolver);
 * const validKids = outcomes
 *   .filter((o) => o.verified)
 *   .map((o) => o.protectedHeader.kid);
 * if (new Set(validKids).size < 2) {
 *   throw new Error("quorum not met");
 * }
 */
export async function verifyMultiAll(
  jws: JWSGeneralSerialization | JWSFlattenedSerialization,
  keyResolver: JWKLookupFunction,
  options: JWSMultiVerifyAllOptions & { payload: "bytes" },
): Promise<JWSMultiVerifyOutcome<Uint8Array<ArrayBuffer>>[]>;
export async function verifyMultiAll(
  jws: JWSGeneralSerialization | JWSFlattenedSerialization,
  keyResolver: JWKLookupFunction,
  options: JWSMultiVerifyAllOptions & { payload: "string" },
): Promise<JWSMultiVerifyOutcome<string>[]>;
export async function verifyMultiAll(
  jws: JWSGeneralSerialization | JWSFlattenedSerialization,
  keyResolver: JWKLookupFunction,
  options: JWSMultiVerifyAllOptions & { forceUint8Array: true },
): Promise<JWSMultiVerifyOutcome<Uint8Array<ArrayBuffer>>[]>;
export async function verifyMultiAll<T extends Record<string, unknown> = JWTClaims>(
  jws: JWSGeneralSerialization | JWSFlattenedSerialization,
  keyResolver: JWKLookupFunction,
  options?: JWSMultiVerifyAllOptions,
): Promise<JWSMultiVerifyOutcome<T>[]>;
export async function verifyMultiAll<T extends JOSEPayload = JOSEPayload>(
  jws: JWSGeneralSerialization | JWSFlattenedSerialization,
  keyResolver: JWKLookupFunction,
  options: JWSMultiVerifyAllOptions = {},
): Promise<JWSMultiVerifyOutcome<T>[]> {
  const payloadMode = resolvePayloadMode(options);
  const signatureLimit = resolveLimit(options.limits, "signatures");
  const keyCandidates = resolveLimit(options.limits, "keyCandidates");

  const general = _normalizeSerialization(jws);

  if (
    typeof general.payload !== "string" ||
    !Array.isArray(general.signatures) ||
    general.signatures.length === 0
  ) {
    throw new JWTError(
      "Invalid JWS JSON Serialization: missing payload or signatures.",
      "ERR_JWS_INVALID_SERIALIZATION",
    );
  }

  // A token carrying more signatures than this caller verifies is a verdict on
  // the token, not one signature's outcome: there is no per-signature report to
  // return for signatures that are never looked at.
  assertEntryLimit(general.signatures.length, signatureLimit, {
    family: "JWS",
    what: "signatures",
  });

  const outcomes: JWSMultiVerifyOutcome<T>[] = [];
  for (let i = 0; i < general.signatures.length; i++) {
    outcomes.push(
      await _verifyOneSignature<T>(general.payload, general.signatures[i]!, i, keyResolver, {
        options,
        payloadMode,
        keyCandidates,
      }),
    );
  }
  return outcomes;
}

/**
 * Convert a {@link JWSGeneralSerialization} with exactly one signature into
 * the {@link JWSFlattenedSerialization} form (RFC 7515 §7.2.2). Throws
 * `ERR_JWS_INVALID_SERIALIZATION` when the input has zero or multiple
 * signatures — Flattened is strictly single-signature.
 *
 * `signMulti` never emits Flattened itself (stable return shape across
 * signer counts); this is the canonical post-processing step when
 * interoperating with a strict Flattened-only consumer.
 *
 * @example
 * const general = await signMulti(payload, [signer], opts);
 * const flattened = generalToFlattenedJWS(general);
 */
export function generalToFlattenedJWS(jws: JWSGeneralSerialization): JWSFlattenedSerialization {
  assertSerializationObject(jws, "JWS");
  if (!Array.isArray(jws.signatures)) {
    throw new JWTError(
      'Invalid JWS JSON Serialization: missing "signatures".',
      "ERR_JWS_INVALID_SERIALIZATION",
    );
  }
  if (jws.signatures.length !== 1) {
    throw new JWTError(
      `Flattened JWS Serialization requires exactly one signature, got ${jws.signatures.length}.`,
      "ERR_JWS_INVALID_SERIALIZATION",
    );
  }
  const [signature] = jws.signatures as [JWSGeneralSignature];
  const flattened: JWSFlattenedSerialization = {
    payload: jws.payload,
    signature: signature.signature,
  };
  if (signature.protected !== undefined) flattened.protected = signature.protected;
  if (signature.header !== undefined) flattened.header = signature.header;
  return flattened;
}

// --- Internal helpers ---

/** Error codes that condemn a single signature rather than the whole token. */
const PER_SIGNATURE_ERROR_CODES: ReadonlySet<string> = /* @__PURE__ */ new Set([
  "ERR_JWS_SIGNATURE_INVALID",
  "ERR_JWK_KEY_NOT_FOUND",
  "ERR_JWK_INVALID",
]);

/** RFC 7515 §4.1.11 — `crit` is only meaningful when it is integrity protected. */
function _checkUnprotectedCrit(header: JWSHeaderParameters | undefined): JWTError | undefined {
  if (!header || !Object.hasOwn(header, "crit")) return undefined;
  return new JWTError(
    'Invalid JWS: "crit" must be integrity protected (RFC 7515 §4.1.11).',
    "ERR_JWS_INVALID",
  );
}

function _resolveSignerAlg(signer: JWSMultiSigner, index: number): JWSAlgorithm {
  const alg = signer.alg ?? _inferSignerAlg(signer.key, index);
  // Settled before any key work, so a signer names an algorithm the library can
  // actually produce — and is refused with the code verification would use.
  const unsupported = checkJWSAlgSupported(alg);
  if (unsupported) throw unsupported;
  return alg;
}

function _inferSignerAlg(key: JWSMultiSigner["key"], index: number): JWSAlgorithm {
  if (isJWK(key)) {
    const alg = key.alg as JWSAlgorithm | undefined;
    if (!alg) {
      throw new JWTError(
        `Cannot infer "alg" for signer[${index}]: the JWK has no "alg" property.`,
        "ERR_JWS_SIGNER_ALG_INFERENCE",
      );
    }
    return alg;
  }
  // CryptoKeys carry their algorithm and hash, so the JWS alg follows from the key itself.
  const inferred = inferJWSAllowedAlgorithms(key);
  if (!inferred?.length) {
    throw new JWTError(
      `Cannot infer "alg" for signer[${index}]: pass it explicitly on the signer.`,
      "ERR_JWS_SIGNER_ALG_INFERENCE",
    );
  }
  return inferred[0]!;
}

function _resolveB64(signers: JWSMultiSigner[]): boolean {
  let decided: boolean | undefined;
  for (let i = 0; i < signers.length; i++) {
    const raw = signers[i]!.protectedHeader?.b64;
    if (raw === undefined) continue;
    if (decided === undefined) decided = raw;
    else if (decided !== raw) {
      throw new JWTError(
        `Inconsistent "b64" across signers (RFC 7797 §3 requires all signers use the same b64 value).`,
        "ERR_JWS_B64_INCONSISTENT",
      );
    }
  }
  return decided ?? true;
}

function _buildSignerProtectedHeader(
  signer: JWSMultiSigner,
  alg: JWSAlgorithm,
  payload: unknown,
  b64: boolean,
): JWSProtectedHeader {
  const userHeader = sanitizeObjectCopy<JWSHeaderParameters | undefined>(
    signer.protectedHeader as JWSHeaderParameters | undefined,
  );
  const header = {} as JWSProtectedHeader;
  // A `kid` can only be inferred from a JWK; a CryptoKey signer must set it on its header.
  if (isJWK(signer.key) && signer.key.kid) header.kid = signer.key.kid;
  if (userHeader) Object.assign(header, userHeader);
  header.alg = alg;
  applyTypCtyDefaults(header, payload);
  if (!b64) header.b64 = false;
  else delete header.b64;
  applyB64Crit(header);
  assertProducerCrit(header as Record<string, unknown>, "JWS");
  return header;
}

function _assertDisjointHeaders(
  protectedHeader: Record<string, unknown> | undefined,
  unprotectedHeader: Record<string, unknown> | undefined,
): void {
  if (!protectedHeader || !unprotectedHeader) return;
  for (const k of Object.keys(unprotectedHeader)) {
    if (k in protectedHeader) {
      throw new JWTError(
        `JWS header parameter "${k}" appears in both protected and unprotected headers of a signature; they must be disjoint (RFC 7515 §7.2.1).`,
        "ERR_JWS_HEADER_PARAMS_NOT_DISJOINT",
      );
    }
  }
}

function _mergeHeaders(
  protectedHeader: JWSHeaderParameters,
  unprotectedHeader: JWSHeaderParameters | undefined,
): JWSHeaderParameters {
  if (!unprotectedHeader) return protectedHeader;
  return { ...protectedHeader, ...unprotectedHeader };
}

function _normalizeSerialization(
  input: JWSGeneralSerialization | JWSFlattenedSerialization,
): JWSGeneralSerialization {
  if (!input || typeof input !== "object") {
    throw new JWTError(
      "Invalid JWS JSON Serialization: expected an object.",
      "ERR_JWS_INVALID_SERIALIZATION",
    );
  }

  const obj = input as unknown as Record<string, unknown>;

  if (Array.isArray(obj.signatures)) {
    // RFC 7515 §7.2 — General and Flattened are alternatives, never both: a document
    // carrying `signatures[]` next to a top-level `signature`/`protected` is ambiguous.
    if ("signature" in obj || "protected" in obj) {
      throw new JWTError(
        'Invalid JWS JSON Serialization: "signatures" must not be combined with a top-level "signature" or "protected".',
        "ERR_JWS_INVALID_SERIALIZATION",
      );
    }
    return obj as unknown as JWSGeneralSerialization;
  }

  if ("signature" in obj) {
    const flattened = obj as unknown as JWSFlattenedSerialization;
    const signature: JWSGeneralSignature = { signature: flattened.signature };
    if (flattened.protected !== undefined) signature.protected = flattened.protected;
    if (flattened.header !== undefined) signature.header = flattened.header;
    return { payload: flattened.payload, signatures: [signature] };
  }

  throw new JWTError(
    "Invalid JWS JSON Serialization: missing both signatures[] and flattened signature.",
    "ERR_JWS_INVALID_SERIALIZATION",
  );
}

function _signerKeyMatches(effectiveHeader: JWSHeaderParameters, keyMaterial: unknown): boolean {
  const headerKid = effectiveHeader.kid;
  if (isJWKSet(keyMaterial)) {
    return keyMaterial.keys.some((k) => !headerKid || k.kid === headerKid);
  }
  if (isJWK(keyMaterial)) {
    if (headerKid && keyMaterial.kid && headerKid !== keyMaterial.kid) return false;
    return true;
  }
  return !headerKid;
}

interface VerifyWithKeyOptions {
  signature: Uint8Array<ArrayBuffer>;
  signingInput: Uint8Array<ArrayBuffer>;
  kid: string | undefined;
  allowSymmetric: boolean | undefined;
  keyCandidates: number;
}

async function _verifyWithKey(
  alg: JWSAlgorithm,
  rawKeyMaterial: unknown,
  options: VerifyWithKeyOptions,
): Promise<boolean> {
  try {
    return await _verifyWithKeyMaterial(alg, rawKeyMaterial, options);
  } catch (err) {
    throw asKeyUsageError(err, alg);
  }
}

async function _verifyWithKeyMaterial(
  alg: JWSAlgorithm,
  rawKeyMaterial: unknown,
  options: VerifyWithKeyOptions,
): Promise<boolean> {
  const { signature, signingInput, kid, allowSymmetric, keyCandidates } = options;

  if (isJWKSet(rawKeyMaterial)) {
    const candidates = getJWKsFromSet(
      rawKeyMaterial,
      buildJWKSetFilter({ kid, alg }, { op: "sig", allowSymmetric }),
    );
    assertJWKSetCandidates(candidates, {
      limit: keyCandidates,
      notFound: "No key found in JWK Set.",
    });
    // A candidate that cannot verify this signature — unusable key material as
    // much as a signature mismatch — only means "try the next one"; the
    // collected reasons become the `cause` when none verifies.
    const attempts: JWTError[] = [];
    for (const candidate of candidates) {
      try {
        const verificationKey = await resolveSigningKey(
          alg,
          await importKey(candidate, { alg, expect: "public" }),
          "verify",
        );
        if (await joseVerify(alg, verificationKey, signature, signingInput)) {
          return true;
        }
        attempts.push(
          new JWTError("JWS signature verification failed.", "ERR_JWS_SIGNATURE_INVALID"),
        );
      } catch (error) {
        attempts.push(asKeyUsageError(error, alg));
      }
    }
    throw new JWTError("JWS signature verification failed.", "ERR_JWS_SIGNATURE_INVALID", attempts);
  }

  const verificationKey = await resolveSigningKey(
    alg,
    await importKey(rawKeyMaterial as any, { alg, expect: "public" }),
    "verify",
  );
  return joseVerify(alg, verificationKey, signature, signingInput);
}

async function _verifyOneSignature<T extends JOSEPayload>(
  payload: string,
  wireSig: JWSGeneralSignature,
  index: number,
  keyResolver: JWKLookupFunction,
  context: {
    options: JWSMultiVerifyAllOptions;
    payloadMode: JOSEPayloadMode;
    keyCandidates: number;
  },
): Promise<JWSMultiVerifyOutcome<T>> {
  const { options, payloadMode, keyCandidates } = context;
  const fail = (
    error: JWTError,
    protectedHeader?: JWSProtectedHeader,
    signerHeader?: JWSHeaderParameters,
  ): JWSMultiVerifyOutcome<T> => {
    const outcome = { signerIndex: index, verified: false, error } as JWSMultiVerifyOutcome<T> & {
      verified: false;
      protectedHeader?: JWSProtectedHeader;
      signerHeader?: JWSHeaderParameters;
    };
    if (protectedHeader) outcome.protectedHeader = protectedHeader;
    if (signerHeader) outcome.signerHeader = signerHeader;
    return outcome;
  };

  if (typeof wireSig.signature !== "string") {
    return fail(
      new JWTError(`Signature[${index}] is missing the "signature" field.`, "ERR_JWS_INVALID"),
    );
  }

  let protectedHeader: JWSProtectedHeader;
  try {
    protectedHeader = decodeProtectedHeader<JWSProtectedHeader>(wireSig.protected, "JWS");
  } catch (err) {
    return fail(_asJWTError(err, "ERR_JWS_INVALID"));
  }

  if (!protectedHeader.alg) {
    return fail(
      new JWTError(
        `Invalid JWS: Signature[${index}] protected header must have an "alg" property.`,
        "ERR_JWS_INVALID",
      ),
      protectedHeader,
    );
  }

  const alg = protectedHeader.alg;

  const unprotectedHeader = sanitizeObjectCopy(wireSig.header) as JWSHeaderParameters | undefined;

  const headerError =
    checkJWSAlgSupported(alg) ??
    checkJWSB64Crit(protectedHeader) ??
    _checkUnprotectedCrit(wireSig.header);
  if (headerError) return fail(headerError, protectedHeader, unprotectedHeader);

  try {
    _assertDisjointHeaders(protectedHeader, unprotectedHeader);
  } catch (err) {
    return fail(_asJWTError(err, "ERR_JWS_INVALID"), protectedHeader, unprotectedHeader);
  }

  const effective = _mergeHeaders(protectedHeader, unprotectedHeader);

  if (options.typ && !typMatches(options.typ, protectedHeader.typ)) {
    return fail(
      new JWTError(
        `Invalid JWS: "typ" Header Parameter mismatch on signature[${index}]. Expected "${options.typ}", got "${protectedHeader.typ}".`,
        "ERR_JWS_INVALID",
      ),
      protectedHeader,
      unprotectedHeader,
    );
  }

  let rawKeyMaterial: unknown;
  try {
    rawKeyMaterial = await keyResolver(
      effective as Parameters<JWKLookupFunction>[0],
      wireSig.protected ?? "",
    );
  } catch (err) {
    return fail(asKeyLookupError(err, `signature[${index}]`), protectedHeader, unprotectedHeader);
  }

  if (typeof rawKeyMaterial === "string") {
    return fail(stringKeyError(), protectedHeader, unprotectedHeader);
  }

  const algError = checkAlgAllowed(alg, rawKeyMaterial, {
    ctx: JWS_ALG_CTX,
    algorithms: options.algorithms,
    allowSymmetric: options.allowSymmetricJWKSet,
  });
  if (algError) return fail(algError, protectedHeader, unprotectedHeader);

  let signatureBytes: Uint8Array<ArrayBuffer>;
  try {
    signatureBytes = decodeSegment(wireSig.signature, { family: "JWS", what: "Signature" });
  } catch (err) {
    return fail(_asJWTError(err, "ERR_JWS_INVALID"), protectedHeader, unprotectedHeader);
  }
  const signingInputBytes = textEncoder.encode(`${wireSig.protected ?? ""}.${payload}`);

  let verified: boolean;
  try {
    verified = await _verifyWithKey(alg, rawKeyMaterial, {
      signature: signatureBytes,
      signingInput: signingInputBytes,
      kid: effective.kid,
      allowSymmetric: options.allowSymmetricJWKSet,
      keyCandidates,
    });
  } catch (err) {
    return fail(_asJWTError(err, "ERR_JWS_SIGNATURE_INVALID"), protectedHeader, unprotectedHeader);
  }
  if (!verified) {
    return fail(
      new JWTError(`JWS signature[${index}] verification failed.`, "ERR_JWS_SIGNATURE_INVALID"),
      protectedHeader,
      unprotectedHeader,
    );
  }

  try {
    validateCriticalHeadersJWS(protectedHeader, options.recognizedHeaders);
  } catch (err) {
    return fail(_asJWTError(err, "ERR_JWS_INVALID"), protectedHeader, unprotectedHeader);
  }

  let decodedPayload: T;
  try {
    const useB64 = protectedHeader.b64 !== false;
    decodedPayload = decodeJWSPayload<T>(payload, useB64, payloadMode);
  } catch (err) {
    return fail(_asJWTError(err, "ERR_JWS_INVALID"), protectedHeader, unprotectedHeader);
  }

  try {
    validateClaimsIfJson(decodedPayload, payloadMode, options);
  } catch (err) {
    return fail(_asJWTError(err, "ERR_JWT_CLAIM_INVALID"), protectedHeader, unprotectedHeader);
  }

  const outcome = {
    signerIndex: index,
    verified: true,
    payload: decodedPayload,
    protectedHeader,
  } as JWSMultiVerifyOutcome<T> & { verified: true; signerHeader?: JWSHeaderParameters };
  if (unprotectedHeader) outcome.signerHeader = unprotectedHeader;
  return outcome;
}

/** Normalise thrown values into a {@link JWTError}, preserving the cause. */
function _asJWTError(err: unknown, fallbackCode: JWTErrorCode, fallbackMessage?: string): JWTError {
  if (err instanceof JWTError) return err;
  const message =
    fallbackMessage ??
    (err instanceof Error ? err.message : typeof err === "string" ? err : "Unknown error");
  return new JWTError(message, fallbackCode, err);
}
