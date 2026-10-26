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
 * Signs `payload` once per signer and returns a JWS General JSON Serialization (RFC 7515 §7.2.1).
 * A signer without `alg` takes it from its JWK or `CryptoKey`.
 * Signers that set `b64` must agree, and the value applies to every signer (RFC 7797 §3).
 *
 * @throws `ERR_JWS_INVALID` if `signers` is empty or not an array.
 * @throws `ERR_JWS_SIGNER_ALG_INFERENCE` if a signer has no `alg` and its key does not name one.
 * @throws `ERR_JWS_B64_INCONSISTENT` if two signers set different `b64` values.
 * @throws `ERR_JWS_HEADER_PARAMS_NOT_DISJOINT` if a signer sets one parameter in both of its headers.
 * @throws `ERR_JWS_ALG_NOT_ALLOWED` if an `alg` is `"none"` or not a supported signing algorithm.
 * @throws `ERR_JWK_INVALID` if a key is a string or cannot sign with its `alg`.
 * @throws `ERR_INVALID_OPTION` if an option is malformed, or a time option is set on a string or bytes payload.
 * @throws `ERR_JWT_CLAIM_INVALID` if both members of a time option pair are set, or `cnf.jwk` is not a public JWK.
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
 * Signatures are tried in order, and a failure scoped to one signature moves on to the next.
 * Once a signature verifies, a `crit`, payload or claim failure throws at once.
 * The payload type follows `options.payload`, as in `verify`.
 *
 * @throws `ERR_JWS_SIGNATURE_INVALID` if no signature verifies, with one `JWTError` per signature as `cause`, in order.
 * @throws `ERR_JWS_NO_MATCHING_SIGNER` if `strictSignerMatch` is set and no signature fits the key.
 * @throws `ERR_JWS_INVALID_SERIALIZATION` if the object is not a General or Flattened JWS.
 * @throws `ERR_JWS_INVALID` if the signatures exceed `limits.signatures`, or the verified signature fails `crit` or payload decoding.
 * @throws `ERR_JWK_KEY_NOT_FOUND` if the key trials exceed `limits.keyAttempts`.
 * @throws `ERR_INVALID_OPTION` if an option is malformed, or a claim option is set where claims are not validated.
 * @throws `ERR_JWT_EXPIRED` if `exp` has passed or the token is older than `maxTokenAge`.
 * @throws `ERR_JWT_NBF` if `nbf` is in the future.
 * @throws `ERR_JWT_CLAIM_INVALID` if a claim does not match its option or has the wrong type.
 * @throws `ERR_JWT_CLAIM_MISSING` if a claim in `requiredClaims` or one an option checks is absent.
 */
export async function verifyMulti<T extends object = JWTClaims>(
  jws: JWSGeneralSerialization | JWSFlattenedSerialization,
  keyOrLookup: CryptoKey | JWKSet | JWSVerifyJWK | Uint8Array<ArrayBuffer> | JWSKeyLookup,
  options?: JWSMultiVerifyOptions<"json">,
): Promise<JWSMultiVerifyResult<T>>;
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

  const failures: JWTError[] = [];
  let cryptoAttempted = false;
  for (let i = 0; i < general.signatures.length; i++) {
    const read = _readSignatureHeaders(general.signatures[i], i);
    if (read.error) {
      failures.push(read.error);
      continue;
    }
    const { wireSig, protectedHeader, unprotectedHeader, effective, alg } = read;

    const typError = checkProtectedTyp(options.typ, protectedHeader, {
      family: "JWS",
      label: `signature[${i}]`,
    });
    if (typError) {
      failures.push(typError);
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
      failures.push(asKeyLookupError(err, `signature[${i}]`));
      continue;
    }

    if (typeof rawKeyMaterial === "string") {
      failures.push(stringKeyError());
      continue;
    }

    const algError = checkAlgAllowed(alg, rawKeyMaterial, {
      ctx: JWS_ALG_CTX,
      algorithms: options.algorithms,
    });
    if (algError) {
      failures.push(algError);
      continue;
    }

    if (
      options.strictSignerMatch &&
      !keyMatchesHeader(effective, rawKeyMaterial, {
        ctx: JWS_ALG_CTX,
      })
    ) {
      failures.push(
        new JWTError(
          `JWS signature[${i}] does not match the key under strictSignerMatch.`,
          "ERR_JWS_NO_MATCHING_SIGNER",
        ),
      );
      continue;
    }

    let signatureBytes: Uint8Array<ArrayBuffer>;
    try {
      signatureBytes = decodeSegment(wireSig.signature, { family: "JWS", what: "Signature" });
    } catch (err) {
      failures.push(asJWTError(err, INVALID_JWS));
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
        failures.push(
          new JWTError("JWS signature verification failed.", "ERR_JWS_SIGNATURE_INVALID"),
        );
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
      failures.push(error);
    }
  }

  if (options.strictSignerMatch && !cryptoAttempted) {
    throw new JWTError(
      "No signature matched the provided key under strictSignerMatch.",
      "ERR_JWS_NO_MATCHING_SIGNER",
    );
  }
  throw new JWTError(INVALID_SIGNATURE.message, INVALID_SIGNATURE.code, failures);
}

/**
 * Verifies every signature on its own and returns one outcome per signature, in signature order.
 * A failed signature is an outcome with `verified: false` and its `error`.
 * The payload type follows `options.payload`.
 *
 * @throws `ERR_JWS_INVALID_SERIALIZATION` if the object is not a General or Flattened JWS.
 * @throws `ERR_JWS_INVALID` if the signatures exceed `limits.signatures`.
 * @throws `ERR_JWK_KEY_NOT_FOUND` if the key trials exceed `limits.keyAttempts`.
 * @throws `ERR_INVALID_OPTION` if an option is malformed, or a claim option is set where claims are not validated.
 *
 * @example
 * const outcomes = await verifyMultiAll(jws, (header) => jwkSet);
 * if (!outcomes.every((o) => o.verified)) throw new Error("not all signatures verified");
 */
export async function verifyMultiAll<T extends object = JWTClaims>(
  jws: JWSGeneralSerialization | JWSFlattenedSerialization,
  keyResolver: JWSKeyLookup,
  options?: JWSMultiVerifyAllOptions<"json">,
): Promise<JWSMultiVerifyOutcome<T>[]>;
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

/**
 * Converts a General JWS with exactly one signature to the Flattened form (RFC 7515 §7.2.2).
 *
 * @throws `ERR_JWS_INVALID_SERIALIZATION` if the input has no `signatures` array, or not exactly one signature.
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
  const [signature] = jws.signatures;
  const flattened: JWSFlattenedSerialization = {
    payload: jws.payload,
    signature: signature.signature,
  };
  if (signature.protected !== undefined) flattened.protected = signature.protected;
  if (signature.header !== undefined) flattened.header = signature.header;
  return flattened;
}
