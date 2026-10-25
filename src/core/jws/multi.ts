import { textEncoder } from "unsecure/utils";
import { base64UrlStringify } from "../../utils/base64.ts";
import type {
  JWKSet,
  JWSVerifyJWK,
  JWSKeyLookup,
  JWSAlgorithm,
  JOSEPayload,
  JOSEPayloadMode,
  JWTClaims,
  PayloadOf,
  JWSGeneralSerialization,
  JWSGeneralSignature,
  JWSFlattenedSerialization,
  JWSMultiSigner,
  JWSMultiSignOptions,
  JWSMultiVerifyOptions,
  JWSMultiVerifyResult,
  JWSMultiVerifyAllOptions,
  JWSMultiVerifyOutcome,
} from "../types/index.ts";
import { importKey } from "../_internal/import-key.ts";
import { sign as joseSign } from "../_crypto/index.ts";
import { JWTError } from "../../error.ts";
import {
  computeJwtTimeClaims,
  getPlaintextBytes,
  parsePayloadText,
  validateCriticalHeadersJWS,
} from "../_internal/jwt.ts";
import { JWS_ALG_CTX, checkAlgAllowed, keyMatchesHeader } from "../_internal/algorithms.ts";
import { assertB64Option, decodeJWSPayload } from "./_internal/b64.ts";
import {
  assertConsumerOptions,
  assertOptionEntry,
  assertProtectedOnlyOption,
  assertProducerKeyHeaders,
  assertProducerConfirmation,
  assertSerializationObject,
  serializeProtectedHeader,
  checkProtectedTyp,
  decodeSegment,
} from "../_internal/headers.ts";
import { asJWTError, asKeyLookupError, copyJsonObject } from "../_internal/errors.ts";
import { asKeyUsageError, assertNotStringKey, resolveSigningKey } from "./_internal/keys.ts";
import { createKeyAttemptBudget, resolveLimit } from "../_internal/limits.ts";
import type { ResolvedKeyInput } from "../_internal/keys.ts";
import { resolveKeyInput, stringKeyError } from "../_internal/keys.ts";
import { resolvePayloadMode, validateClaimsIfJson } from "../_internal/payload.ts";
import { buildJWSProtectedHeader, verifyWithKey } from "./_internal/sign-verify.ts";
import {
  INVALID_JWS,
  INVALID_SIGNATURE,
  PER_SIGNATURE_ERROR_CODES,
  _readSignatureHeaders,
  _resolveSignerAlg,
  _resolveB64,
  _assertDisjointHeaders,
  _readGeneralSerialization,
  _verifyOneSignature,
} from "./_internal/multi.ts";

/**
 * Signs a payload with multiple signers as a JWS General JSON Serialization (RFC 7515 §7.2.1).
 * Each signer's `alg` is inferred from its key when omitted (`ERR_JWS_SIGNER_ALG_INFERENCE`);
 * `b64` must match across signers (RFC 7797 §3, `ERR_JWS_B64_INCONSISTENT`).
 */
export async function signMulti(
  payload: JOSEPayload,
  signers: JWSMultiSigner[],
  options: JWSMultiSignOptions = {},
): Promise<JWSGeneralSerialization> {
  if (!Array.isArray(signers) || signers.length === 0) {
    throw new JWTError("signMulti requires at least one signer.", "ERR_JWS_INVALID");
  }

  for (const [index, signer] of signers.entries()) {
    assertOptionEntry(signer, {
      label: `signers[${index}]`,
      objects: ["protectedHeader", "unprotectedHeader"],
    });
    assertNotStringKey(signer.key);
    assertProtectedOnlyOption(signer.unprotectedHeader, { tier: "unprotected", family: "JWS" });
    assertProducerKeyHeaders(signer.protectedHeader, { tier: "protected", family: "JWS" });
    assertProducerKeyHeaders(signer.unprotectedHeader, { tier: "unprotected", family: "JWS" });
    assertB64Option(signer.protectedHeader);
  }
  assertProducerConfirmation(payload);

  const resolvedAlgs: JWSAlgorithm[] = signers.map((s, i) => _resolveSignerAlg(s, i));

  const b64 = _resolveB64(signers);

  const computedPayload: JWTClaims | undefined = computeJwtTimeClaims(payload, options);
  const payloadBytes = getPlaintextBytes(computedPayload || payload);

  // RFC 7797 §5.3: an unencoded payload must be UTF-8.
  const payloadEncoded = b64 ? base64UrlStringify(payloadBytes) : parsePayloadText(payloadBytes);

  const wireSignatures: JWSGeneralSignature[] = [];
  for (let i = 0; i < signers.length; i++) {
    const signer = signers[i];
    const alg = resolvedAlgs[i];

    const protectedHeader = buildJWSProtectedHeader(alg, signer.key, signer.protectedHeader, {
      payload,
      b64,
    });
    const unprotectedHeader = copyJsonObject(signer.unprotectedHeader, {
      code: "ERR_INVALID_OPTION",
      message: '"unprotectedHeader" must hold only JSON values.',
    });

    _assertDisjointHeaders(protectedHeader, unprotectedHeader);

    const protectedHeaderEncoded = base64UrlStringify(serializeProtectedHeader(protectedHeader));
    const signingInputBytes = textEncoder.encode(`${protectedHeaderEncoded}.${payloadEncoded}`);

    let signatureBytes: Uint8Array<ArrayBuffer>;
    try {
      const signingKey = await resolveSigningKey(
        alg,
        await importKey(signer.key, { alg, expect: "private" }),
        "sign",
      );
      signatureBytes = await joseSign(alg, signingKey, signingInputBytes);
    } catch (error) {
      throw asKeyUsageError(error, alg);
    }

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
 * Verifies a JWS General or Flattened JSON Serialization (RFC 7515 §7.2) and returns the first signature that verifies.
 * Per-signature failures are collected and the last one is thrown when none verifies.
 * The payload type follows `options.payload`, as in `verify`.
 */
export async function verifyMulti<T extends object = JWTClaims>(
  jws: JWSGeneralSerialization | JWSFlattenedSerialization,
  keyOrLookup: CryptoKey | JWKSet | JWSVerifyJWK | Uint8Array<ArrayBuffer> | JWSKeyLookup,
  options?: JWSMultiVerifyOptions<"json"> & { forceUint8Array?: false },
): Promise<JWSMultiVerifyResult<T>>;
/** @deprecated `forceUint8Array` is replaced by `payload: "bytes"`; removed in v0.9.0. */
export async function verifyMulti(
  jws: JWSGeneralSerialization | JWSFlattenedSerialization,
  keyOrLookup: CryptoKey | JWKSet | JWSVerifyJWK | Uint8Array<ArrayBuffer> | JWSKeyLookup,
  options: JWSMultiVerifyOptions & { forceUint8Array: true },
): Promise<JWSMultiVerifyResult<Uint8Array<ArrayBuffer>>>;
export async function verifyMulti<Mode extends JOSEPayloadMode = JOSEPayloadMode>(
  jws: JWSGeneralSerialization | JWSFlattenedSerialization,
  keyOrLookup: CryptoKey | JWKSet | JWSVerifyJWK | Uint8Array<ArrayBuffer> | JWSKeyLookup,
  options?: JWSMultiVerifyOptions<Mode>,
): Promise<JWSMultiVerifyResult<PayloadOf<Mode>>>;
export async function verifyMulti(
  jws: JWSGeneralSerialization | JWSFlattenedSerialization,
  keyOrLookup: CryptoKey | JWKSet | JWSVerifyJWK | Uint8Array<ArrayBuffer> | JWSKeyLookup,
  options: JWSMultiVerifyOptions = {},
): Promise<JWSMultiVerifyResult> {
  assertConsumerOptions(options);
  const payloadMode = resolvePayloadMode(options);
  const signatureLimit = resolveLimit(options.limits, "signatures");
  const keyCandidates = resolveLimit(options.limits, "keyCandidates");
  const keyAttempts = createKeyAttemptBudget(resolveLimit(options.limits, "keyAttempts"));

  const general = _readGeneralSerialization(jws, signatureLimit);

  let lastError: JWTError | undefined;
  let cryptoAttempted = false;
  for (let i = 0; i < general.signatures.length; i++) {
    const read = _readSignatureHeaders(general.signatures[i], i);
    if (read.error) {
      lastError = read.error;
      continue;
    }
    const { wireSig, protectedHeader, unprotectedHeader, effective, alg } = read;

    const typError = checkProtectedTyp(options.typ, protectedHeader, {
      family: "JWS",
      label: `signature[${i}]`,
    });
    if (typError) {
      lastError = typError;
      continue;
    }

    let rawKeyMaterial: ResolvedKeyInput<typeof keyOrLookup>;
    try {
      rawKeyMaterial = await resolveKeyInput(keyOrLookup, {
        header: effective,
        token: wireSig.protected ?? "",
        what: `signature[${i}]`,
      });
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
    });
    if (algError) {
      lastError = algError;
      continue;
    }

    if (
      options.strictSignerMatch &&
      !keyMatchesHeader(effective, rawKeyMaterial, {
        ctx: JWS_ALG_CTX,
      })
    ) {
      continue;
    }

    let signatureBytes: Uint8Array<ArrayBuffer>;
    try {
      signatureBytes = decodeSegment(wireSig.signature, { family: "JWS", what: "Signature" });
    } catch (err) {
      lastError = asJWTError(err, INVALID_JWS);
      continue;
    }
    const signingInputBytes = textEncoder.encode(`${wireSig.protected ?? ""}.${general.payload}`);

    cryptoAttempted = true;
    try {
      const verified = await verifyWithKey(alg, rawKeyMaterial, {
        signature: signatureBytes,
        signingInput: signingInputBytes,
        kid: effective.kid,
        keyCandidates,
        keyAttempts,
      });
      if (!verified) {
        lastError = new JWTError("JWS signature verification failed.", "ERR_JWS_SIGNATURE_INVALID");
        continue;
      }

      validateCriticalHeadersJWS(protectedHeader, options.recognizedHeaders);

      const useB64 = protectedHeader.b64 !== false;
      const payload = decodeJWSPayload(general.payload, useB64, payloadMode);

      validateClaimsIfJson(payload, payloadMode, options);

      const result: JWSMultiVerifyResult = {
        payload,
        protectedHeader,
        signerIndex: i,
      };
      if (unprotectedHeader) result.signerHeader = unprotectedHeader;
      return result;
    } catch (err) {
      if (keyAttempts.exhausted) throw keyAttempts.exhausted;
      const error = asJWTError(err, INVALID_SIGNATURE);
      if (!PER_SIGNATURE_ERROR_CODES.has(error.code)) throw error;
      lastError = error;
    }
  }

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
 * Verifies every signature independently and returns one outcome per signature; only
 * a malformed envelope (`ERR_JWS_INVALID_SERIALIZATION`) or a spent `limits.keyAttempts`
 * (`ERR_JWK_KEY_NOT_FOUND`) throws. The payload type follows `options.payload`.
 *
 * @example
 * const outcomes = await verifyMultiAll(jws, (header) => jwkSet);
 * if (!outcomes.every((o) => o.verified)) throw new Error("not all signatures verified");
 */
export async function verifyMultiAll<T extends object = JWTClaims>(
  jws: JWSGeneralSerialization | JWSFlattenedSerialization,
  keyResolver: JWSKeyLookup,
  options?: JWSMultiVerifyAllOptions<"json"> & { forceUint8Array?: false },
): Promise<JWSMultiVerifyOutcome<T>[]>;
/** @deprecated `forceUint8Array` is replaced by `payload: "bytes"`; removed in v0.9.0. */
export async function verifyMultiAll(
  jws: JWSGeneralSerialization | JWSFlattenedSerialization,
  keyResolver: JWSKeyLookup,
  options: JWSMultiVerifyAllOptions & { forceUint8Array: true },
): Promise<JWSMultiVerifyOutcome<Uint8Array<ArrayBuffer>>[]>;
export async function verifyMultiAll<Mode extends JOSEPayloadMode = JOSEPayloadMode>(
  jws: JWSGeneralSerialization | JWSFlattenedSerialization,
  keyResolver: JWSKeyLookup,
  options?: JWSMultiVerifyAllOptions<Mode>,
): Promise<JWSMultiVerifyOutcome<PayloadOf<Mode>>[]>;
export async function verifyMultiAll(
  jws: JWSGeneralSerialization | JWSFlattenedSerialization,
  keyResolver: JWSKeyLookup,
  options: JWSMultiVerifyAllOptions = {},
): Promise<JWSMultiVerifyOutcome[]> {
  assertConsumerOptions(options);
  const payloadMode = resolvePayloadMode(options);
  const signatureLimit = resolveLimit(options.limits, "signatures");
  const keyCandidates = resolveLimit(options.limits, "keyCandidates");
  const keyAttempts = createKeyAttemptBudget(resolveLimit(options.limits, "keyAttempts"));

  const general = _readGeneralSerialization(jws, signatureLimit);

  const outcomes: JWSMultiVerifyOutcome[] = [];
  for (let i = 0; i < general.signatures.length; i++) {
    outcomes.push(
      await _verifyOneSignature(general.payload, general.signatures[i], i, keyResolver, {
        options,
        payloadMode,
        keyCandidates,
        keyAttempts,
      }),
    );
  }
  return outcomes;
}

/** Converts a single-signature General JWS to Flattened form (RFC 7515 §7.2.2); otherwise `ERR_JWS_INVALID_SERIALIZATION`. */
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
  const [signature] = jws.signatures;
  const flattened: JWSFlattenedSerialization = {
    payload: jws.payload,
    signature: signature.signature,
  };
  if (signature.protected !== undefined) flattened.protected = signature.protected;
  if (signature.header !== undefined) flattened.header = signature.header;
  return flattened;
}
