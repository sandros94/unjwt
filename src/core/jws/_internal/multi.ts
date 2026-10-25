import { textEncoder } from "unsecure/utils";
import type {
  JWSKeyLookup,
  JWSAlgorithm,
  JWSHeaderParameters,
  JOSEPayload,
  JOSEPayloadMode,
  JWSGeneralSerialization,
  JWSGeneralSignature,
  JWSFlattenedSerialization,
  JWSMultiSigner,
  JWSMultiVerifyAllOptions,
  JWSMultiVerifyOutcome,
} from "../../types/index.ts";
import { JWTError } from "../../../error.ts";
import { isJWK } from "../../../utils/guards.ts";
import { inferJWSAllowedAlgorithms } from "../../../utils/algorithms.ts";
import { validateCriticalHeadersJWS } from "../../_internal/jwt.ts";
import { JWS_ALG_CTX, checkAlgAllowed } from "../../_internal/algorithms.ts";
import { checkJWSB64, decodeJWSPayload } from "./b64.ts";
import {
  assertSerializationObject,
  checkSerializationEntry,
  decodeProtectedHeader,
  checkProtectedTyp,
  decodeSegment,
} from "../../_internal/headers.ts";
import { asJWTError, asKeyLookupError, copyJsonObject } from "../../_internal/errors.ts";
import { assertEntryLimit } from "../../_internal/limits.ts";
import { checkJWSAlgSupported } from "./algorithms.ts";
import type { ResolvedKeyInput } from "../../_internal/keys.ts";
import { resolveKeyInput, stringKeyError } from "../../_internal/keys.ts";
import { validateClaimsIfJson } from "../../_internal/payload.ts";
import { verifyWithKey } from "./sign-verify.ts";

/** How a non-`JWTError` raised at each step is reported. */
export const INVALID_JWS = { code: "ERR_JWS_INVALID", message: "Invalid JWS." } as const;
export const INVALID_SIGNATURE = {
  code: "ERR_JWS_SIGNATURE_INVALID",
  message: "JWS signature verification failed.",
} as const;
const INVALID_CLAIMS = {
  code: "ERR_JWT_CLAIM_INVALID",
  message: "JWT claim validation failed.",
} as const;

/** Error codes that condemn one signature rather than the whole token. */
export const PER_SIGNATURE_ERROR_CODES: ReadonlySet<string> = /* @__PURE__ */ new Set([
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
export function _readSignatureHeaders(entry: JWSGeneralSignature, index: number): SignatureHeaders {
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
  let unprotectedHeader: JWSHeaderParameters | undefined;
  try {
    protectedHeader = decodeProtectedHeader(wireSig.protected, "JWS");
    unprotectedHeader = copyJsonObject(wireSig.header, INVALID_JWS);
  } catch (err) {
    return { error: asJWTError(err, INVALID_JWS) };
  }

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

export function _resolveSignerAlg(signer: JWSMultiSigner, index: number): JWSAlgorithm {
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
export function _resolveB64(signers: JWSMultiSigner[]): boolean {
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
export function _assertDisjointHeaders(
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
export function _readGeneralSerialization(
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

export async function _verifyOneSignature(
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
