import { sanitizeObjectCopy } from "unsecure/sanitize";
import { textEncoder } from "unsecure/utils";
import { base64UrlStringify } from "./utils/base64.ts";

import type {
  JWKSet,
  JWSVerifyJWK,
  JWSKeyLookup,
  JWSAlgorithm,
  JWSHeaderParameters,
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
} from "./types/index.ts";

import { importKey } from "./_import-key.ts";
import { sign as joseSign } from "./_crypto/index.ts";
import { JWTError } from "./error.ts";
import { isJWK } from "./utils/guards.ts";
import { inferJWSAllowedAlgorithms } from "./utils/algorithms.ts";
import {
  computeJwtTimeClaims,
  getPlaintextBytes,
  parsePayloadText,
  validateCriticalHeadersJWS,
} from "./_jwt-internal.ts";
import {
  JWS_ALG_CTX,
  assertB64Option,
  assertConsumerOptions,
  assertOptionEntry,
  assertProtectedOnlyOption,
  assertProducerKeyHeaders,
  assertProducerConfirmation,
  asJWTError,
  asKeyLookupError,
  asKeyUsageError,
  assertSerializationObject,
  assertEntryLimit,
  checkSerializationEntry,
  checkAlgAllowed,
  checkJWSAlgSupported,
  checkJWSB64,
  assertNotStringKey,
  decodeJWSPayload,
  decodeProtectedHeader,
  resolveKeyInput,
  resolveLimit,
  resolvePayloadMode,
  resolveSigningKey,
  serializeProtectedHeader,
  stringKeyError,
  checkProtectedTyp,
  validateClaimsIfJson,
  decodeSegment,
  keyMatchesHeader,
} from "./_internal.ts";
import { buildJWSProtectedHeader, verifyWithKey } from "./_jws-internal.ts";
import type { ResolvedKeyInput } from "./_internal.ts";

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
    const unprotectedHeader = sanitizeObjectCopy(signer.unprotectedHeader);

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
      allowSymmetric: options.allowSymmetricJWKSet,
    });
    if (algError) {
      lastError = algError;
      continue;
    }

    if (
      options.strictSignerMatch &&
      !keyMatchesHeader(effective, rawKeyMaterial, {
        ctx: JWS_ALG_CTX,
        allowSymmetric: options.allowSymmetricJWKSet,
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
        allowSymmetric: options.allowSymmetricJWKSet,
        keyCandidates,
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
 * a malformed envelope throws (`ERR_JWS_INVALID_SERIALIZATION`). The payload type follows `options.payload`.
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

  const general = _readGeneralSerialization(jws, signatureLimit);

  const outcomes: JWSMultiVerifyOutcome[] = [];
  for (let i = 0; i < general.signatures.length; i++) {
    outcomes.push(
      await _verifyOneSignature(general.payload, general.signatures[i], i, keyResolver, {
        options,
        payloadMode,
        keyCandidates,
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

/** How a non-`JWTError` raised at each step is reported. */
const INVALID_JWS = { code: "ERR_JWS_INVALID", message: "Invalid JWS." } as const;
const INVALID_SIGNATURE = {
  code: "ERR_JWS_SIGNATURE_INVALID",
  message: "JWS signature verification failed.",
} as const;
const INVALID_CLAIMS = {
  code: "ERR_JWT_CLAIM_INVALID",
  message: "JWT claim validation failed.",
} as const;

/** Error codes that condemn one signature rather than the whole token. */
const PER_SIGNATURE_ERROR_CODES: ReadonlySet<string> = /* @__PURE__ */ new Set([
  "ERR_JWS_SIGNATURE_INVALID",
  "ERR_JWK_KEY_NOT_FOUND",
  "ERR_JWK_INVALID",
]);

/** RFC 7515 §4.1.11 / RFC 7797 §3: `crit` and `b64` must be integrity protected. */
function _checkUnprotectedHeader(header: JWSHeaderParameters | undefined): JWTError | undefined {
  if (!header) return undefined;
  if (Object.hasOwn(header, "crit")) {
    return new JWTError('Invalid JWS: "crit" must be integrity protected.', "ERR_JWS_INVALID");
  }
  if (Object.hasOwn(header, "b64")) {
    return new JWTError('Invalid JWS: "b64" must be in the protected header.', "ERR_JWS_INVALID");
  }
  return undefined;
}

type SignatureHeaders =
  | {
      error?: undefined;
      wireSig: JWSGeneralSignature & { signature: string };
      protectedHeader: JWSHeaderParameters;
      unprotectedHeader: JWSHeaderParameters | undefined;
      effective: JWSHeaderParameters;
      alg: JWSAlgorithm;
    }
  | {
      error: JWTError;
      protectedHeader?: JWSHeaderParameters;
      unprotectedHeader?: JWSHeaderParameters;
    };

/** Reads and checks one `signatures[]` entry's headers; `alg` may sit in either tier (RFC 7515 §7.2.1). */
function _readSignatureHeaders(entry: JWSGeneralSignature, index: number): SignatureHeaders {
  const shapeError = checkSerializationEntry(entry, {
    family: "JWS",
    label: `Signature[${index}]`,
    objects: ["header"],
    strings: ["protected"],
  });
  if (shapeError) return { error: shapeError };
  const wireSig = entry;
  if (typeof wireSig.signature !== "string") {
    return {
      error: new JWTError(
        `Signature[${index}] is missing the "signature" field.`,
        "ERR_JWS_INVALID",
      ),
    };
  }

  let protectedHeader: JWSHeaderParameters;
  try {
    protectedHeader = decodeProtectedHeader(wireSig.protected, "JWS");
  } catch (err) {
    return { error: asJWTError(err, INVALID_JWS) };
  }

  const unprotectedHeader = sanitizeObjectCopy(wireSig.header);
  const failed = (error: JWTError): SignatureHeaders => ({
    error,
    protectedHeader,
    ...(unprotectedHeader ? { unprotectedHeader } : {}),
  });

  const unprotectedError = _checkUnprotectedHeader(unprotectedHeader);
  if (unprotectedError) return failed(unprotectedError);
  try {
    _assertDisjointHeaders(protectedHeader, unprotectedHeader);
  } catch (err) {
    return failed(asJWTError(err, INVALID_JWS));
  }

  const effective = _mergeHeaders(protectedHeader, unprotectedHeader);
  const alg = effective.alg;
  if (!alg) {
    return failed(
      new JWTError(
        `Invalid JWS: Signature[${index}] has no "alg" in its headers.`,
        "ERR_JWS_INVALID",
      ),
    );
  }

  const algError = checkJWSAlgSupported(alg) ?? checkJWSB64(protectedHeader);
  if (algError) return failed(algError);

  return {
    wireSig,
    protectedHeader,
    unprotectedHeader,
    effective,
    alg,
  };
}

function _resolveSignerAlg(signer: JWSMultiSigner, index: number): JWSAlgorithm {
  const alg = signer.alg ?? _inferSignerAlg(signer.key, index);
  const unsupported = checkJWSAlgSupported(alg);
  if (unsupported) throw unsupported;
  return alg;
}

function _inferSignerAlg(key: JWSMultiSigner["key"], index: number): JWSAlgorithm {
  if (isJWK(key)) {
    const alg = key.alg;
    if (!alg) {
      throw new JWTError(
        `Cannot infer "alg" for signer[${index}]: the JWK has no "alg" property.`,
        "ERR_JWS_SIGNER_ALG_INFERENCE",
      );
    }
    return alg;
  }
  const inferred = inferJWSAllowedAlgorithms(key);
  if (!inferred?.length) {
    throw new JWTError(
      `Cannot infer "alg" for signer[${index}]: pass it explicitly on the signer.`,
      "ERR_JWS_SIGNER_ALG_INFERENCE",
    );
  }
  return inferred[0];
}

/** RFC 7797 §3 — every signer uses the same `b64` value. */
function _resolveB64(signers: JWSMultiSigner[]): boolean {
  let decided: boolean | undefined;
  for (let i = 0; i < signers.length; i++) {
    const raw = signers[i].protectedHeader?.b64;
    if (raw === undefined) continue;
    if (decided === undefined) decided = raw;
    else if (decided !== raw) {
      throw new JWTError('Inconsistent "b64" across signers.', "ERR_JWS_B64_INCONSISTENT");
    }
  }
  return decided ?? true;
}

/** RFC 7515 §7.2.1 — a signature's protected and unprotected headers are disjoint. */
function _assertDisjointHeaders(
  protectedHeader: Record<string, unknown> | undefined,
  unprotectedHeader: Record<string, unknown> | undefined,
): void {
  if (!protectedHeader || !unprotectedHeader) return;
  for (const k of Object.keys(unprotectedHeader)) {
    if (k in protectedHeader) {
      throw new JWTError(
        `Invalid JWS: header parameter "${k}" is set in more than one header.`,
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

/** Normalizes to General form (RFC 7515 §7.2) and enforces the signature limit. */
function _readGeneralSerialization(
  input: JWSGeneralSerialization | JWSFlattenedSerialization,
  signatureLimit: number,
): JWSGeneralSerialization {
  const general = _normalizeSerialization(input);
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
  return general;
}

function _normalizeSerialization(
  input: JWSGeneralSerialization | JWSFlattenedSerialization,
): JWSGeneralSerialization {
  assertSerializationObject(input, "JWS");

  if ("signatures" in input && Array.isArray(input.signatures)) {
    // RFC 7515 §7.2: General and Flattened members must not be mixed.
    if ("signature" in input || "protected" in input) {
      throw new JWTError(
        'Invalid JWS JSON Serialization: "signatures" excludes top-level "signature" and "protected".',
        "ERR_JWS_INVALID_SERIALIZATION",
      );
    }
    return input;
  }

  if ("signature" in input) {
    const flattened = input;
    const signature: JWSGeneralSignature = { signature: flattened.signature };
    if (flattened.protected !== undefined) signature.protected = flattened.protected;
    if (flattened.header !== undefined) signature.header = flattened.header;
    return { payload: flattened.payload, signatures: [signature] };
  }

  throw new JWTError(
    'Invalid JWS JSON Serialization: missing "signatures" or "signature".',
    "ERR_JWS_INVALID_SERIALIZATION",
  );
}

async function _verifyOneSignature(
  payload: string,
  entry: JWSGeneralSignature,
  index: number,
  keyResolver: JWSKeyLookup,
  context: {
    options: JWSMultiVerifyAllOptions;
    payloadMode: JOSEPayloadMode;
    keyCandidates: number;
  },
): Promise<JWSMultiVerifyOutcome> {
  const { options, payloadMode, keyCandidates } = context;
  const fail = (
    error: JWTError,
    protectedHeader?: JWSHeaderParameters,
    signerHeader?: JWSHeaderParameters,
  ): JWSMultiVerifyOutcome => {
    const outcome = {
      signerIndex: index,
      verified: false,
      error,
    } as JWSMultiVerifyOutcome & {
      verified: false;
      protectedHeader?: JWSHeaderParameters;
      signerHeader?: JWSHeaderParameters;
    };
    if (protectedHeader) outcome.protectedHeader = protectedHeader;
    if (signerHeader) outcome.signerHeader = signerHeader;
    return outcome;
  };

  const read = _readSignatureHeaders(entry, index);
  if (read.error) return fail(read.error, read.protectedHeader, read.unprotectedHeader);
  const { wireSig, protectedHeader, unprotectedHeader, effective, alg } = read;

  const typError = checkProtectedTyp(options.typ, protectedHeader, {
    family: "JWS",
    label: `signature[${index}]`,
  });
  if (typError) return fail(typError, protectedHeader, unprotectedHeader);

  let rawKeyMaterial: ResolvedKeyInput<JWSKeyLookup>;
  try {
    rawKeyMaterial = await resolveKeyInput(keyResolver, {
      header: effective,
      token: wireSig.protected ?? "",
      what: `signature[${index}]`,
    });
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
    return fail(asJWTError(err, INVALID_JWS), protectedHeader, unprotectedHeader);
  }
  const signingInputBytes = textEncoder.encode(`${wireSig.protected ?? ""}.${payload}`);

  let verified: boolean;
  try {
    verified = await verifyWithKey(alg, rawKeyMaterial, {
      signature: signatureBytes,
      signingInput: signingInputBytes,
      kid: effective.kid,
      allowSymmetric: options.allowSymmetricJWKSet,
      keyCandidates,
    });
  } catch (err) {
    return fail(asJWTError(err, INVALID_SIGNATURE), protectedHeader, unprotectedHeader);
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
    return fail(asJWTError(err, INVALID_JWS), protectedHeader, unprotectedHeader);
  }

  let decodedPayload: JOSEPayload;
  try {
    const useB64 = protectedHeader.b64 !== false;
    decodedPayload = decodeJWSPayload(payload, useB64, payloadMode);
  } catch (err) {
    return fail(asJWTError(err, INVALID_JWS), protectedHeader, unprotectedHeader);
  }

  try {
    validateClaimsIfJson(decodedPayload, payloadMode, options);
  } catch (err) {
    return fail(asJWTError(err, INVALID_CLAIMS), protectedHeader, unprotectedHeader);
  }

  const outcome = {
    signerIndex: index,
    verified: true,
    payload: decodedPayload,
    protectedHeader,
  } as JWSMultiVerifyOutcome & { verified: true; signerHeader?: JWSHeaderParameters };
  if (unprotectedHeader) outcome.signerHeader = unprotectedHeader;
  return outcome;
}
