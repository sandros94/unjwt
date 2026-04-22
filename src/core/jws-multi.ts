import { sanitizeObjectCopy } from "unsecure/sanitize";
import { textEncoder, textDecoder, base64UrlEncode, base64UrlDecode } from "unsecure/utils";

import type {
  JWKSet,
  JWSSignJWK,
  JWSVerifyJWK,
  JWKLookupFunction,
  JWSAlgorithm,
  JWSHeaderParameters,
  JWSProtectedHeader,
  JOSEPayload,
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
  validateCriticalHeadersJWS,
} from "./utils";
import {
  JWS_ALG_CTX,
  buildJWKSetFilter,
  checkAlgAllowed,
  decodeJWSPayload,
  decodeProtectedHeader,
  resolveSigningKey,
  validateJwtClaimsIfJsonPayload,
} from "./_internal";

/**
 * Sign a payload with multiple signers using JWS General JSON Serialization
 * (RFC 7515 §7.2.1).
 *
 * The payload is shared across all signatures; each signer independently
 * produces a signature over `BASE64URL(its own protected header) . BASE64URL(payload)`
 * using its own key-declared algorithm. Per-signer `alg` is read from
 * `key.alg` and throws `ERR_JWS_SIGNER_ALG_INFERENCE` when absent.
 *
 * Per RFC 7797 §3, `b64` MUST be consistent across every signer. If one
 * signer sets `b64: false` in its protected header, every other signer
 * must match or this function throws `ERR_JWS_B64_INCONSISTENT`.
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

  const resolvedAlgs: JWSAlgorithm[] = signers.map((s, i) => _resolveSignerAlg(s.key, i));

  const b64 = _resolveB64(signers);

  const computedPayload: JWTClaims | undefined = computeJwtTimeClaims(payload, options);
  const payloadBytes = getPlaintextBytes(computedPayload || payload);

  const payloadEncoded = b64 ? base64UrlEncode(payloadBytes) : textDecoder.decode(payloadBytes);

  const wireSignatures: JWSGeneralSignature[] = [];
  for (let i = 0; i < signers.length; i++) {
    const signer = signers[i]!;
    const alg = resolvedAlgs[i]!;

    const protectedHeader = _buildSignerProtectedHeader(signer, alg, payload, b64);
    const unprotectedHeader = sanitizeObjectCopy(signer.unprotectedHeader) as
      | Record<string, unknown>
      | undefined;

    _assertDisjointHeaders(protectedHeader, unprotectedHeader);

    const protectedHeaderEncoded = base64UrlEncode(JSON.stringify(protectedHeader));
    const signingInputBytes = textEncoder.encode(`${protectedHeaderEncoded}.${payloadEncoded}`);

    const signingKey = await resolveSigningKey(
      alg,
      await importKey(signer.key, { alg, expect: "private" }),
      "sign",
    );
    const signatureBytes = await joseSign(alg, signingKey, signingInputBytes);

    const wireSig: JWSGeneralSignature = {
      protected: protectedHeaderEncoded,
      signature: base64UrlEncode(signatureBytes),
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
 * For compact (string) tokens, use {@link verify}.
 */
export async function verifyMulti<T extends JOSEPayload = JOSEPayload>(
  jws: JWSGeneralSerialization | JWSFlattenedSerialization,
  keyOrLookup: CryptoKey | JWKSet | JWSVerifyJWK | Uint8Array<ArrayBuffer> | JWKLookupFunction,
  options: JWSMultiVerifyOptions = {},
): Promise<JWSMultiVerifyResult<T>> {
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

    const unprotectedHeader = sanitizeObjectCopy(wireSig.header) as JWSHeaderParameters | undefined;
    _assertDisjointHeaders(protectedHeader, unprotectedHeader);

    const effective = _mergeHeaders(protectedHeader, unprotectedHeader);
    const alg = protectedHeader.alg;

    if (options.typ && protectedHeader.typ !== options.typ) {
      lastError = new JWTError(
        `Invalid JWS: "typ" Header Parameter mismatch on signature[${i}]. Expected "${options.typ}", got "${protectedHeader.typ}".`,
        "ERR_JWS_INVALID",
      );
      continue;
    }

    const rawKeyMaterial =
      typeof keyOrLookup === "function"
        ? await (keyOrLookup as JWKLookupFunction)(
            effective as Parameters<JWKLookupFunction>[0],
            wireSig.protected ?? "",
          )
        : keyOrLookup;

    const algError = checkAlgAllowed(alg, rawKeyMaterial, options.algorithms, JWS_ALG_CTX);
    if (algError) {
      lastError = algError;
      continue;
    }

    if (options.strictSignerMatch && !_signerKeyMatches(effective, rawKeyMaterial)) {
      continue;
    }

    const signatureBytes = base64UrlDecode(wireSig.signature, { returnAs: "uint8array" });
    const signingInputBytes = textEncoder.encode(`${wireSig.protected ?? ""}.${general.payload}`);

    cryptoAttempted = true;
    try {
      const verified = await _verifyWithKey(
        alg,
        rawKeyMaterial,
        signatureBytes,
        signingInputBytes,
        effective.kid,
      );
      if (!verified) {
        lastError = new JWTError("JWS signature verification failed.", "ERR_JWS_SIGNATURE_INVALID");
        continue;
      }

      const useB64 = protectedHeader.b64 !== false;
      const payload = decodeJWSPayload<T>(general.payload, useB64, options.forceUint8Array);

      validateCriticalHeadersJWS(protectedHeader, options.recognizedHeaders);

      validateJwtClaimsIfJsonPayload(payload, options);

      const result: JWSMultiVerifyResult<T> = {
        payload,
        protectedHeader,
        signerIndex: i,
      };
      if (unprotectedHeader) result.signerHeader = unprotectedHeader;
      return result;
    } catch (err) {
      if (
        err instanceof JWTError &&
        err.code !== "ERR_JWS_SIGNATURE_INVALID" &&
        err.code !== "ERR_JWK_KEY_NOT_FOUND"
      ) {
        throw err;
      }
      lastError = err instanceof JWTError ? err : undefined;
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
 * signature's failure — malformed protected headers, disallowed `alg`s,
 * `typ` mismatches, key-resolver errors, bad signatures, critical header
 * violations, and JWT claim failures are all collected into
 * {@link JWSMultiVerifyOutcome} entries with `verified: false`.
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
export async function verifyMultiAll<T extends JOSEPayload = JOSEPayload>(
  jws: JWSGeneralSerialization | JWSFlattenedSerialization,
  keyResolver: JWKLookupFunction,
  options: JWSMultiVerifyAllOptions = {},
): Promise<JWSMultiVerifyOutcome<T>[]> {
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

  const outcomes: JWSMultiVerifyOutcome<T>[] = [];
  for (let i = 0; i < general.signatures.length; i++) {
    outcomes.push(
      await _verifyOneSignature<T>(
        general.payload,
        general.signatures[i]!,
        i,
        keyResolver,
        options,
      ),
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

function _resolveSignerAlg(key: JWSSignJWK, index: number): JWSAlgorithm {
  if (!isJWK(key)) {
    throw new JWTError(`Signer[${index}] key is not a JWK.`, "ERR_JWS_SIGNER_ALG_INFERENCE");
  }
  const alg = key.alg as JWSAlgorithm | undefined;
  if (!alg) {
    throw new JWTError(
      `Cannot infer "alg" for signer[${index}]: the JWK has no "alg" property.`,
      "ERR_JWS_SIGNER_ALG_INFERENCE",
    );
  }
  if ((alg as string) === "none") {
    throw new JWTError('"none" is not a valid signing algorithm', "ERR_JWS_ALG_NOT_ALLOWED");
  }
  return alg;
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
  if (signer.key.kid) header.kid = signer.key.kid;
  if (userHeader) Object.assign(header, userHeader);
  header.alg = alg;
  applyTypCtyDefaults(header, payload);
  if (!b64) header.b64 = false;
  else delete header.b64;
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

async function _verifyWithKey(
  alg: JWSAlgorithm,
  rawKeyMaterial: unknown,
  signatureBytes: Uint8Array<ArrayBuffer>,
  signingInputBytes: Uint8Array<ArrayBuffer>,
  headerKid: string | undefined,
): Promise<boolean> {
  if (isJWKSet(rawKeyMaterial)) {
    const candidates = getJWKsFromSet(rawKeyMaterial, buildJWKSetFilter({ kid: headerKid, alg }));
    if (candidates.length === 0) {
      throw new JWTError("No key found in JWK Set.", "ERR_JWK_KEY_NOT_FOUND");
    }
    for (const candidate of candidates) {
      const verificationKey = await resolveSigningKey(
        alg,
        await importKey(candidate, { alg, expect: "public" }),
        "verify",
      );
      if (await joseVerify(alg, verificationKey, signatureBytes, signingInputBytes)) {
        return true;
      }
    }
    return false;
  }

  const verificationKey = await resolveSigningKey(
    alg,
    await importKey(rawKeyMaterial as any, { alg, expect: "public" }),
    "verify",
  );
  return joseVerify(alg, verificationKey, signatureBytes, signingInputBytes);
}

async function _verifyOneSignature<T extends JOSEPayload>(
  payload: string,
  wireSig: JWSGeneralSignature,
  index: number,
  keyResolver: JWKLookupFunction,
  options: JWSMultiVerifyAllOptions,
): Promise<JWSMultiVerifyOutcome<T>> {
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

  const unprotectedHeader = sanitizeObjectCopy(wireSig.header) as JWSHeaderParameters | undefined;
  try {
    _assertDisjointHeaders(protectedHeader, unprotectedHeader);
  } catch (err) {
    return fail(_asJWTError(err, "ERR_JWS_INVALID"), protectedHeader, unprotectedHeader);
  }

  const effective = _mergeHeaders(protectedHeader, unprotectedHeader);
  const alg = protectedHeader.alg;

  if (options.typ && protectedHeader.typ !== options.typ) {
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
    return fail(
      _asJWTError(err, "ERR_JWK_KEY_NOT_FOUND", `Key resolver failed for signature[${index}]`),
      protectedHeader,
      unprotectedHeader,
    );
  }

  const algError = checkAlgAllowed(alg, rawKeyMaterial, options.algorithms, JWS_ALG_CTX);
  if (algError) return fail(algError, protectedHeader, unprotectedHeader);

  const signatureBytes = base64UrlDecode(wireSig.signature, { returnAs: "uint8array" });
  const signingInputBytes = textEncoder.encode(`${wireSig.protected ?? ""}.${payload}`);

  let verified: boolean;
  try {
    verified = await _verifyWithKey(
      alg,
      rawKeyMaterial,
      signatureBytes,
      signingInputBytes,
      effective.kid,
    );
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

  let decodedPayload: T;
  try {
    const useB64 = protectedHeader.b64 !== false;
    decodedPayload = decodeJWSPayload<T>(payload, useB64, options.forceUint8Array);
  } catch (err) {
    return fail(_asJWTError(err, "ERR_JWS_INVALID"), protectedHeader, unprotectedHeader);
  }

  try {
    validateCriticalHeadersJWS(protectedHeader, options.recognizedHeaders);
    validateJwtClaimsIfJsonPayload(decodedPayload, options);
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
