import { secureRandomBytes } from "unsecure/random";
import { sanitizeObjectCopy } from "unsecure/sanitize";
import { textEncoder } from "unsecure/utils";
import { base64UrlStringify } from "./utils/base64";

import type {
  JWK,
  KeyManagementAlgorithm,
  ContentEncryptionAlgorithm,
  UnwrapKeyOptions,
} from "./types/jwk";
import type { JOSEPayload, JWTClaims } from "./types/jwt";
import type {
  JWEEncryptJWK,
  JWEHeaderParameters,
  JWEKeyManagementHeaderParameters,
  JWEGeneralSerialization,
  JWEGeneralRecipient,
  JWEFlattenedSerialization,
  JWEMultiRecipient,
  JWEMultiEncryptOptions,
  JWEMultiDecryptKey,
  JWEMultiDecryptOptions,
  JWEMultiDecryptResult,
} from "./types/jwe";

import { importKey, unwrapKey, getJWKsFromSet } from "./jwk";
import {
  encrypt as joseEncrypt,
  decrypt as joseDecrypt,
  assertPBES2Params,
  generateIV,
  generateCEK,
  encryptKey,
} from "./_crypto";
import { JWTError } from "./error";
import type { PBES2Budget, ResolvedKeyInput } from "./_internal";
import { isContentEncryptionAlgorithm } from "./utils/algorithms";
import {
  isJWK,
  isJWKSet,
  isCryptoKey,
  inferJWEAllowedAlgorithms,
  applyTypCtyDefaults,
  computeJwtTimeClaims,
  decodePayloadFromBytes,
  getPlaintextBytes,
  validateCriticalHeadersJWE,
} from "./utils";
import {
  DEFAULT_PBES2_ITERATIONS,
  JWE_ALG_CTX,
  JWE_DIRECT_ALGS,
  assertDirectKeyRole,
  checkProtectedTyp,
  assertJWKSetCandidates,
  assertEntryLimit,
  assertNoZipOption,
  assertProducerCEK,
  assertProducerCrit,
  assertProducerIV,
  assertProducerPartyInfo,
  asKeyLookupError,
  assertConsumerOptions,
  assertOptionEntry,
  assertProtectedOnlyOption,
  assertSerializationObject,
  buildJWKSetFilter,
  buildUnwrapKeyOptions,
  checkAlgAllowed,
  checkJWEAlgSupported,
  checkJWEContentSegments,
  checkJWEDirectEncryptedKey,
  checkJWEEncAllowed,
  checkJWEEncSupported,
  checkJWEUnprotectedCrit,
  checkJWEZip,
  checkSerializationEntry,
  createPBES2Budget,
  decodeProtectedHeader,
  exportReturnedCek,
  parseEphemeralKey,
  resolveKeyInput,
  resolveLimit,
  resolvePasswordKey,
  resolvePayloadMode,
  serializeProtectedHeader,
  validateClaimsIfJson,
  decodeSegment,
} from "./_internal";

/**
 * Encrypt a payload to multiple recipients using JWE General JSON Serialization
 * (RFC 7516 §7.2.1).
 *
 * One shared CEK encrypts the payload once; the CEK is then wrapped
 * independently per recipient using each recipient's key-management algorithm.
 * Per-recipient `alg` is read from `key.alg` and throws `ERR_JWE_RECIPIENT_ALG_INFERENCE`
 * when absent.
 *
 * Throws `ERR_JWE_ALG_FORBIDDEN_IN_MULTI` when any recipient resolves to `dir`
 * or bare `ECDH-ES` — those algorithms require exactly one recipient; use
 * {@link encrypt} instead.
 *
 * @example
 * const jwe = await encryptMulti({ sub: "u1" }, [
 *   { key: aliceRsaPublicJwk },
 *   { key: bobEcdhPublicJwk },
 * ], { enc: "A256GCM", expiresIn: "1h" });
 */
export async function encryptMulti(
  payload: JOSEPayload,
  recipients: JWEMultiRecipient[],
  options: JWEMultiEncryptOptions = {},
): Promise<JWEGeneralSerialization> {
  if (!Array.isArray(recipients) || recipients.length === 0) {
    throw new JWTError("encryptMulti requires at least one recipient.", "ERR_JWE_INVALID");
  }

  assertOptionEntry(options, {
    label: "options",
    objects: ["protectedHeader", "sharedUnprotectedHeader"],
  });
  _assertAADOption(options.aad);
  assertNoZipOption(options.protectedHeader, "protected");
  assertNoZipOption(options.sharedUnprotectedHeader, "shared unprotected");
  assertProtectedOnlyOption(options.sharedUnprotectedHeader, {
    tier: "shared unprotected",
    family: "JWE",
  });
  for (const [index, recipient] of recipients.entries()) {
    assertOptionEntry(recipient, { label: `recipients[${index}]`, objects: ["header"] });
    assertNoZipOption(recipient.header, "per-recipient");
    assertProtectedOnlyOption(recipient.header, { tier: "per-recipient", family: "JWE" });
  }

  const resolvedAlgs: KeyManagementAlgorithm[] = recipients.map((r, i) =>
    _resolveRecipientAlg(r.key, i),
  );

  const enc: ContentEncryptionAlgorithm = options.enc ?? "A256GCM";
  const encError = checkJWEEncSupported(enc);
  if (encError) throw encError;

  assertProducerCEK(options.cek, enc);
  assertProducerIV(options.contentEncryptionIV, enc);

  for (const [index, recipient] of recipients.entries()) {
    if (resolvedAlgs[index]!.startsWith("PBES2")) {
      assertPBES2Params({ p2s: recipient.p2s, p2c: recipient.p2c });
    }
  }

  const userProtected = sanitizeObjectCopy(options.protectedHeader) as
    | JWEHeaderParameters
    | undefined;
  const sharedUnprotected = sanitizeObjectCopy(options.sharedUnprotectedHeader) as
    | Record<string, unknown>
    | undefined;

  const protectedHeader = {} as JWEHeaderParameters;
  if (userProtected) Object.assign(protectedHeader, userProtected);
  protectedHeader.enc = enc;
  applyTypCtyDefaults(protectedHeader, payload);
  assertProducerCrit(protectedHeader as Record<string, unknown>, "JWE");

  const computedPayload: JWTClaims | undefined = computeJwtTimeClaims(payload, options);
  const plaintextBytes = getPlaintextBytes(computedPayload || payload);

  const cek: Uint8Array<ArrayBuffer> = options.cek ?? generateCEK(enc);

  const wireRecipients: JWEGeneralRecipient[] = [];
  for (let i = 0; i < recipients.length; i++) {
    const recipient = recipients[i]!;
    const alg = resolvedAlgs[i]!;

    const keyMgmtParams = _buildRecipientKeyMgmtParams(recipient, alg);

    const wrappingKey = await importKey(recipient.key, { alg, expect: "public" });
    const { encryptedKey, parameters: keyMgmtOut } = await encryptKey(
      alg,
      enc,
      wrappingKey,
      cek,
      keyMgmtParams,
    );

    const perRecipientHeader = _buildPerRecipientHeader(recipient, alg, keyMgmtOut);

    _assertDisjointHeaders(protectedHeader, sharedUnprotected, perRecipientHeader);

    const wireRecipient: JWEGeneralRecipient = {};
    if (Object.keys(perRecipientHeader).length > 0) {
      wireRecipient.header = perRecipientHeader;
    }
    if (encryptedKey) wireRecipient.encrypted_key = base64UrlStringify(encryptedKey);
    wireRecipients.push(wireRecipient);
  }

  const protectedHeaderEncoded = base64UrlStringify(serializeProtectedHeader(protectedHeader));

  let aadEncoded: string | undefined;
  let aadForCipher: string = protectedHeaderEncoded;
  const aadBytes = typeof options.aad === "string" ? textEncoder.encode(options.aad) : options.aad;
  // RFC 7516 §7.2.1 — the "aad" member is present only for a non-empty JWE AAD.
  if (aadBytes !== undefined && aadBytes.length > 0) {
    aadEncoded = base64UrlStringify(aadBytes);
    aadForCipher = `${protectedHeaderEncoded}.${aadEncoded}`;
  }

  const contentAadBytes = textEncoder.encode(aadForCipher);
  const contentIVBytes = options.contentEncryptionIV ?? generateIV(enc);

  const {
    ciphertext: contentCiphertext,
    tag: contentAuthTag,
    iv: actualContentIV,
  } = await joseEncrypt(enc, plaintextBytes, cek, contentIVBytes, contentAadBytes);

  if (!actualContentIV || !contentAuthTag) {
    throw new JWTError("Content encryption did not return an IV / auth tag.", "ERR_JWE_INVALID");
  }

  const output: JWEGeneralSerialization = {
    protected: protectedHeaderEncoded,
    recipients: wireRecipients,
    iv: base64UrlStringify(actualContentIV),
    ciphertext: base64UrlStringify(contentCiphertext),
    tag: base64UrlStringify(contentAuthTag),
  };
  if (sharedUnprotected && Object.keys(sharedUnprotected).length > 0) {
    output.unprotected = sharedUnprotected;
  }
  if (aadEncoded !== undefined) output.aad = aadEncoded;

  return output;
}

/**
 * Decrypt a JWE in JSON Serialization object form (General RFC 7516 §7.2.1 or
 * Flattened §7.2.2 — both accepted).
 *
 * Recipients are tried in order until one unwraps. `recipients[]` is outside the
 * AAD, so any failure scoped to a single recipient only means "try the next one"
 * and surfaces just when no recipient works; the protected header, the shared
 * unprotected header, the content segments and the decrypted claims are verdicts
 * on the token itself and throw immediately.
 *
 * `strictRecipientMatch: true` restricts the loop to recipients the key material
 * could plausibly open — a differing `kid`, an incompatible `kty`/curve/length
 * for the recipient's `alg`, or a mismatched `epk` curve skips it — and throws
 * `ERR_JWE_NO_MATCHING_RECIPIENT` when none qualifies.
 *
 * For compact (string) tokens, use {@link decrypt}.
 */
export async function decryptMulti(
  jwe: JWEGeneralSerialization | JWEFlattenedSerialization,
  keyOrLookup: JWEMultiDecryptKey,
  options: JWEMultiDecryptOptions & { payload: "bytes" },
): Promise<JWEMultiDecryptResult<Uint8Array<ArrayBuffer>>>;
export async function decryptMulti(
  jwe: JWEGeneralSerialization | JWEFlattenedSerialization,
  keyOrLookup: JWEMultiDecryptKey,
  options: JWEMultiDecryptOptions & { payload: "string" },
): Promise<JWEMultiDecryptResult<string>>;
export async function decryptMulti(
  jwe: JWEGeneralSerialization | JWEFlattenedSerialization,
  keyOrLookup: JWEMultiDecryptKey,
  options: JWEMultiDecryptOptions & { forceUint8Array: true },
): Promise<JWEMultiDecryptResult<Uint8Array<ArrayBuffer>>>;
export async function decryptMulti<T extends Record<string, unknown> = JWTClaims>(
  jwe: JWEGeneralSerialization | JWEFlattenedSerialization,
  keyOrLookup: JWEMultiDecryptKey,
  options?: JWEMultiDecryptOptions,
): Promise<JWEMultiDecryptResult<T>>;
export async function decryptMulti<T extends JOSEPayload = JOSEPayload>(
  jwe: JWEGeneralSerialization | JWEFlattenedSerialization,
  keyOrLookup: JWEMultiDecryptKey,
  options: JWEMultiDecryptOptions = {},
): Promise<JWEMultiDecryptResult<T>> {
  assertConsumerOptions(options);
  const payloadMode = resolvePayloadMode(options);
  const recipientLimit = resolveLimit(options.limits, "recipients");
  const keyCandidates = resolveLimit(options.limits, "keyCandidates");
  const pbes2Budget = createPBES2Budget(resolveLimit(options.limits, "pbes2Iterations"));

  const general = _normalizeSerialization(jwe);

  if (
    typeof general.iv !== "string" ||
    typeof general.ciphertext !== "string" ||
    typeof general.tag !== "string" ||
    !Array.isArray(general.recipients) ||
    general.recipients.length === 0
  ) {
    throw new JWTError(
      "Invalid JWE JSON Serialization: missing iv/ciphertext/tag/recipients.",
      "ERR_JWE_INVALID_SERIALIZATION",
    );
  }

  assertEntryLimit(general.recipients.length, recipientLimit, {
    family: "JWE",
    what: "recipients",
  });

  const envelopeError = checkSerializationEntry(general, {
    family: "JWE",
    label: "JSON Serialization",
    objects: ["unprotected"],
    strings: ["protected", "aad"],
  });
  if (envelopeError) throw envelopeError;

  const protectedHeaderEncoded = general.protected ?? "";
  const protectedHeader = decodeProtectedHeader<JWEHeaderParameters>(
    protectedHeaderEncoded || undefined,
    "JWE",
  );
  const sharedUnprotected = sanitizeObjectCopy(general.unprotected) as
    | JWEHeaderParameters
    | undefined;

  // Token-wide verdicts: the protected header, the shared unprotected header and
  // the single content ciphertext are the same for every recipient, so they are
  // settled once, before any recipient is tried.
  const sharedError =
    checkJWEZip(protectedHeader) ??
    checkJWEUnprotectedCrit(sharedUnprotected) ??
    checkJWEZip(sharedUnprotected);
  if (sharedError) throw sharedError;
  _assertDisjointHeaders(protectedHeader, sharedUnprotected, undefined);

  // RFC 7516 §7.2.1 — `enc` is shared by every recipient, so it sits in the
  // protected or the shared unprotected header, never in a per-recipient one.
  const enc = (protectedHeader.enc ?? sharedUnprotected?.enc) as
    | ContentEncryptionAlgorithm
    | undefined;
  if (!enc) {
    throw new JWTError(
      'Invalid JWE: "enc" is missing from the protected and shared unprotected headers.',
      "ERR_JWE_INVALID",
    );
  }
  const encError =
    checkJWEEncSupported(enc) ?? checkJWEEncAllowed(enc, options.encryptionAlgorithms);
  if (encError) throw encError;

  validateCriticalHeadersJWE(protectedHeader, options.recognizedHeaders);

  const typError = checkProtectedTyp(options.typ, protectedHeader, { family: "JWE" });
  if (typError) throw typError;

  const ivBytes = decodeSegment(general.iv, { family: "JWE", what: "Initialization vector" });
  const ciphertextBytes = decodeSegment(general.ciphertext, {
    family: "JWE",
    what: "Ciphertext",
  });
  const tagBytes = decodeSegment(general.tag, { family: "JWE", what: "Authentication tag" });

  const segmentError = checkJWEContentSegments(enc, ivBytes, tagBytes);
  if (segmentError) throw segmentError;

  // RFC 7516 §5.2 step 15 — a present `aad` member takes part even when empty.
  const contentAadBytes = textEncoder.encode(
    general.aad === undefined ? protectedHeaderEncoded : `${protectedHeaderEncoded}.${general.aad}`,
  );

  let lastError: JWTError | undefined;
  let cryptoAttempted = false;
  for (let i = 0; i < general.recipients.length; i++) {
    // `recipients[]` is outside the AAD: anyone can append or rewrite an entry.
    // Every failure scoped to one recipient therefore only means "try the next
    // one" — it is collected as `lastError` and never aborts the loop.
    const shapeError = checkSerializationEntry(general.recipients[i], {
      family: "JWE",
      label: `Recipient[${i}]`,
      objects: ["header"],
      strings: ["encrypted_key"],
    });
    if (shapeError) {
      lastError = shapeError;
      continue;
    }
    const wireRecipient = general.recipients[i]!;
    const recipientHeader = sanitizeObjectCopy(wireRecipient.header) as
      | JWEHeaderParameters
      | undefined;

    const recipientError = checkJWEUnprotectedCrit(recipientHeader) ?? checkJWEZip(recipientHeader);
    if (recipientError) {
      lastError = recipientError;
      continue;
    }

    try {
      _assertDisjointHeaders(protectedHeader, sharedUnprotected, recipientHeader);
    } catch (err) {
      lastError = _asJWTError(err);
      continue;
    }

    const effective = _mergeHeaders(protectedHeader, sharedUnprotected, recipientHeader);
    const alg = effective.alg as KeyManagementAlgorithm | undefined;
    if (!alg) {
      lastError = new JWTError(
        `Recipient[${i}] has no "alg" in the effective header.`,
        "ERR_JWE_INVALID",
      );
      continue;
    }

    const algSupportError =
      checkJWEAlgSupported(alg) ?? checkJWEDirectEncryptedKey(alg, wireRecipient.encrypted_key);
    if (algSupportError) {
      lastError = algSupportError;
      continue;
    }

    let rawKeyMaterial: ResolvedKeyInput<JWEMultiDecryptKey>;
    try {
      rawKeyMaterial = await resolveKeyInput(keyOrLookup, {
        header: effective,
        token: protectedHeaderEncoded,
        what: `recipient[${i}]`,
      });
    } catch (err) {
      lastError = asKeyLookupError(err, `recipient[${i}]`);
      continue;
    }

    const algError = checkAlgAllowed(alg, rawKeyMaterial, {
      ctx: JWE_ALG_CTX,
      algorithms: options.algorithms,
      allowSymmetric: options.allowSymmetricJWKSet,
    });
    if (algError) {
      lastError = algError;
      continue;
    }

    if (options.strictRecipientMatch && !_recipientKeyMatches(effective, rawKeyMaterial)) {
      continue;
    }

    let encryptedKeyBytes: Uint8Array<ArrayBuffer>;
    try {
      encryptedKeyBytes = decodeSegment(wireRecipient.encrypted_key ?? "", {
        family: "JWE",
        what: "Encrypted key",
      });
    } catch (err) {
      lastError = _asJWTError(err);
      continue;
    }

    const unwrapKeyOpts = buildUnwrapKeyOptions(effective, { alg, enc }, options);

    cryptoAttempted = true;
    let cek: Uint8Array<ArrayBuffer> | CryptoKey;
    let plaintextBytes: Uint8Array<ArrayBuffer>;
    try {
      ({ cek, plaintextBytes } = await _unwrapAndDecrypt(alg, rawKeyMaterial, {
        enc,
        encryptedKey: encryptedKeyBytes,
        unwrapKeyOptions: unwrapKeyOpts,
        ciphertext: ciphertextBytes,
        iv: ivBytes,
        tag: tagBytes,
        aad: contentAadBytes,
        kid: effective.kid,
        allowSymmetric: options.allowSymmetricJWKSet,
        keyCandidates,
        pbes2Budget,
      }));
    } catch (err) {
      lastError = _asJWTError(err);
      continue;
    }

    // The content cipher authenticated the token: from here a failure is a
    // verdict on the token itself, not on this recipient, and propagates.
    const payload = decodePayloadFromBytes<T>(plaintextBytes, {
      payload: payloadMode,
      family: "JWE",
    }) as T;

    validateClaimsIfJson(payload, payloadMode, options);

    const result: JWEMultiDecryptResult<T> = {
      payload,
      protectedHeader,
      recipientIndex: i,
    };
    if (sharedUnprotected) result.sharedUnprotectedHeader = sharedUnprotected;
    if (recipientHeader) result.recipientHeader = recipientHeader;
    if (options.returnCek) {
      result.cek = await exportReturnedCek(cek);
      result.aad = contentAadBytes;
    }
    return result;
  }

  // Strict mode: if no crypto was ever attempted (every recipient filtered out
  // by alg / kid / kty mismatch), signal the match failure rather than the
  // filter reason. Crypto-level failures still surface as-is.
  if (options.strictRecipientMatch && !cryptoAttempted) {
    throw new JWTError(
      "No recipient matched the provided key under strictRecipientMatch.",
      "ERR_JWE_NO_MATCHING_RECIPIENT",
    );
  }
  throw lastError ?? new JWTError("JWE decryption failed.", "ERR_JWE_DECRYPTION_FAILED");
}

/**
 * Convert a {@link JWEGeneralSerialization} with exactly one recipient into
 * the {@link JWEFlattenedSerialization} form (RFC 7516 §7.2.2). Throws
 * `ERR_JWE_INVALID_SERIALIZATION` when the input has zero or multiple
 * recipients — Flattened is strictly single-recipient.
 *
 * `encryptMulti` never emits Flattened itself (stable return shape across
 * recipient counts); this is the canonical post-processing step when
 * interoperating with a strict Flattened-only consumer.
 *
 * @example
 * const general = await encryptMulti(payload, [recipient], opts);
 * const flattened = generalToFlattened(general);
 */
export function generalToFlattened(jwe: JWEGeneralSerialization): JWEFlattenedSerialization {
  assertSerializationObject(jwe, "JWE");
  if (!Array.isArray(jwe.recipients)) {
    throw new JWTError(
      'Invalid JWE JSON Serialization: missing "recipients".',
      "ERR_JWE_INVALID_SERIALIZATION",
    );
  }
  if (jwe.recipients.length !== 1) {
    throw new JWTError(
      `Flattened JWE Serialization requires exactly one recipient, got ${jwe.recipients.length}.`,
      "ERR_JWE_INVALID_SERIALIZATION",
    );
  }
  const { recipients, ...rest } = jwe;
  const [recipient] = recipients as [JWEGeneralRecipient];
  const flattened: JWEFlattenedSerialization = { ...rest };
  if (recipient.header !== undefined) flattened.header = recipient.header;
  if (recipient.encrypted_key !== undefined) flattened.encrypted_key = recipient.encrypted_key;
  return flattened;
}

// --- Internal helpers ---

function _resolveRecipientAlg(key: JWEEncryptJWK, index: number): KeyManagementAlgorithm {
  if (!isJWK(key)) {
    throw new JWTError(`Recipient[${index}] key is not a JWK.`, "ERR_JWE_RECIPIENT_ALG_INFERENCE");
  }
  const declared = key.alg as KeyManagementAlgorithm | undefined;
  if (!declared) {
    throw new JWTError(
      `Cannot infer "alg" for recipient[${index}]: the JWK has no "alg" property.`,
      "ERR_JWE_RECIPIENT_ALG_INFERENCE",
    );
  }
  // An `oct` JWK declaring a content encryption algorithm is a CEK, whose only
  // key management algorithm is `dir` — which General Serialization forbids.
  const alg = key.kty === "oct" && isContentEncryptionAlgorithm(declared) ? "dir" : declared;
  if (JWE_DIRECT_ALGS.has(alg)) {
    throw new JWTError(
      `Recipient[${index}] resolves to "${alg}", which requires exactly one recipient. Use encrypt() instead.`,
      "ERR_JWE_ALG_FORBIDDEN_IN_MULTI",
    );
  }
  const unsupported = checkJWEAlgSupported(alg);
  if (unsupported) throw unsupported;
  return alg;
}

function _buildRecipientKeyMgmtParams(
  recipient: JWEMultiRecipient,
  alg: KeyManagementAlgorithm,
): JWEKeyManagementHeaderParameters {
  const params: JWEKeyManagementHeaderParameters = {};
  if (recipient.keyManagementIV) params.iv = recipient.keyManagementIV;
  if (recipient.p2s !== undefined) params.p2s = recipient.p2s;
  else if (alg.startsWith("PBES2")) params.p2s = secureRandomBytes(16);
  if (recipient.p2c !== undefined) params.p2c = recipient.p2c;
  else if (alg.startsWith("PBES2")) params.p2c = DEFAULT_PBES2_ITERATIONS;
  if (recipient.ecdh?.partyUInfo !== undefined) {
    assertProducerPartyInfo("apu", recipient.ecdh.partyUInfo);
    params.apu = recipient.ecdh.partyUInfo;
  }
  if (recipient.ecdh?.partyVInfo !== undefined) {
    assertProducerPartyInfo("apv", recipient.ecdh.partyVInfo);
    params.apv = recipient.ecdh.partyVInfo;
  }
  if (recipient.ecdh?.ephemeralKey) {
    const { epk, epkPrivateKey } = parseEphemeralKey(recipient.ecdh.ephemeralKey);
    params.epk = epk;
    params.epkPrivateKey = epkPrivateKey;
  }
  return params;
}

function _buildPerRecipientHeader(
  recipient: JWEMultiRecipient,
  alg: KeyManagementAlgorithm,
  keyMgmtOut: JWEHeaderParameters | undefined,
): JWEHeaderParameters {
  const header = {} as JWEHeaderParameters;
  if (recipient.key.kid) header.kid = recipient.key.kid;
  const userHeader = sanitizeObjectCopy(recipient.header as JWEHeaderParameters | undefined);
  if (userHeader) Object.assign(header, userHeader);
  if (keyMgmtOut) Object.assign(header, keyMgmtOut);
  header.alg = alg;
  return header;
}

function _assertDisjointHeaders(
  protectedHeader: Record<string, unknown> | undefined,
  sharedUnprotected: Record<string, unknown> | undefined,
  recipientHeader: Record<string, unknown> | undefined,
): void {
  const seen = new Set<string>();
  const check = (obj: Record<string, unknown> | undefined) => {
    if (!obj) return;
    for (const k of Object.keys(obj)) {
      if (seen.has(k)) {
        throw new JWTError(
          `JWE header parameter "${k}" appears in multiple header tiers; protected, shared unprotected, and per-recipient headers must be disjoint (RFC 7516 §7.2.1).`,
          "ERR_JWE_HEADER_PARAMS_NOT_DISJOINT",
        );
      }
      seen.add(k);
    }
  };
  check(protectedHeader);
  check(sharedUnprotected);
  check(recipientHeader);
}

function _mergeHeaders(
  protectedHeader: JWEHeaderParameters,
  sharedUnprotected: JWEHeaderParameters | undefined,
  recipientHeader: JWEHeaderParameters | undefined,
): JWEHeaderParameters {
  const merged: JWEHeaderParameters = { ...protectedHeader };
  if (sharedUnprotected) Object.assign(merged, sharedUnprotected);
  if (recipientHeader) Object.assign(merged, recipientHeader);
  return merged;
}

function _normalizeSerialization(
  input: JWEGeneralSerialization | JWEFlattenedSerialization,
): JWEGeneralSerialization {
  if (!input || typeof input !== "object") {
    throw new JWTError(
      "Invalid JWE JSON Serialization: expected an object.",
      "ERR_JWE_INVALID_SERIALIZATION",
    );
  }

  const obj = input as unknown as Record<string, unknown>;

  // RFC 7516 §7.2 — General and Flattened are alternatives, never both. Only
  // `recipients` tells them apart: the Flattened `header` and `encrypted_key`
  // are both OPTIONAL (§7.2.2), and a `dir` or `ECDH-ES` token carries neither.
  if ("recipients" in obj) {
    if ("encrypted_key" in obj || "header" in obj) {
      throw new JWTError(
        'Invalid JWE JSON Serialization: "recipients" must not be combined with a top-level "header" or "encrypted_key".',
        "ERR_JWE_INVALID_SERIALIZATION",
      );
    }
    return obj as unknown as JWEGeneralSerialization;
  }

  const flattened = obj as unknown as JWEFlattenedSerialization;
  const recipient: JWEGeneralRecipient = {};
  if (flattened.header !== undefined) recipient.header = flattened.header;
  if (flattened.encrypted_key !== undefined) recipient.encrypted_key = flattened.encrypted_key;
  const general: JWEGeneralSerialization = {
    recipients: [recipient],
    iv: flattened.iv,
    ciphertext: flattened.ciphertext,
    tag: flattened.tag,
  };
  if (flattened.protected !== undefined) general.protected = flattened.protected;
  if (flattened.unprotected !== undefined) general.unprotected = flattened.unprotected;
  if (flattened.aad !== undefined) general.aad = flattened.aad;
  return general;
}

/**
 * `strictRecipientMatch` gate: is this recipient one the key material could
 * possibly open?
 *
 * A recipient is skipped only on a *definite* mismatch — a different `kid` on
 * both sides, or key material whose shape cannot serve the recipient's `alg`
 * (`kty` / curve / length, plus the `epk` curve for ECDH-ES). Key material that
 * carries no identity of its own (a `CryptoKey`, raw bytes, a password) is
 * unknown, not mismatched: it falls through to the compatibility check rather
 * than being filtered out.
 */
function _recipientKeyMatches(effectiveHeader: JWEHeaderParameters, keyMaterial: unknown): boolean {
  if (isJWKSet(keyMaterial)) {
    return keyMaterial.keys.some((k) => _jwkMatchesRecipient(effectiveHeader, k));
  }
  if (isJWK(keyMaterial)) return _jwkMatchesRecipient(effectiveHeader, keyMaterial);
  if (isCryptoKey(keyMaterial)) return _keyServesRecipientAlg(effectiveHeader, keyMaterial);
  // Raw bytes and passwords carry neither a `kid` nor an unambiguous shape.
  return true;
}

function _jwkMatchesRecipient(effectiveHeader: JWEHeaderParameters, jwk: JWK): boolean {
  const headerKid = effectiveHeader.kid;
  if (headerKid && jwk.kid && headerKid !== jwk.kid) return false;
  return _keyServesRecipientAlg(effectiveHeader, jwk);
}

function _keyServesRecipientAlg(
  effectiveHeader: JWEHeaderParameters,
  key: JWK | CryptoKey,
): boolean {
  const alg = effectiveHeader.alg;
  if (!alg) return false;

  const inferred = inferJWEAllowedAlgorithms(key);
  if (inferred && !inferred.includes(alg as KeyManagementAlgorithm)) return false;

  if (!alg.startsWith("ECDH-ES")) return true;
  const epkCurve = (effectiveHeader.epk as { crv?: string } | undefined)?.crv;
  const keyCurve = _keyCurve(key);
  return !epkCurve || !keyCurve || epkCurve === keyCurve;
}

function _keyCurve(key: JWK | CryptoKey): string | undefined {
  if (isCryptoKey(key)) {
    const algorithm = key.algorithm as EcKeyAlgorithm;
    if (typeof algorithm.namedCurve === "string") return algorithm.namedCurve;
    return algorithm.name === "X25519" || algorithm.name === "X448" ? algorithm.name : undefined;
  }
  return (key as { crv?: string }).crv;
}

/** RFC 7516 §7.2.1 — the JWE AAD is octets, given as bytes or as text to UTF-8 encode. */
function _assertAADOption(aad: unknown): void {
  if (aad === undefined || typeof aad === "string" || aad instanceof Uint8Array) return;
  throw new JWTError('"aad" must be a string or a Uint8Array.', "ERR_INVALID_OPTION");
}

/** Normalize anything thrown while trying one recipient into a collectable error. */
function _asJWTError(error: unknown): JWTError {
  if (error instanceof JWTError) return error;
  return new JWTError("JWE decryption failed.", "ERR_JWE_DECRYPTION_FAILED", error);
}

interface UnwrapAndDecryptOptions {
  enc: ContentEncryptionAlgorithm;
  encryptedKey: Uint8Array<ArrayBuffer>;
  unwrapKeyOptions: UnwrapKeyOptions;
  ciphertext: Uint8Array<ArrayBuffer>;
  iv: Uint8Array<ArrayBuffer>;
  tag: Uint8Array<ArrayBuffer>;
  aad: Uint8Array<ArrayBuffer>;
  kid: string | undefined;
  allowSymmetric: boolean | undefined;
  keyCandidates: number;
  pbes2Budget: PBES2Budget;
}

async function _unwrapAndDecrypt(
  alg: KeyManagementAlgorithm,
  rawKeyMaterial: ResolvedKeyInput<JWEMultiDecryptKey>,
  options: UnwrapAndDecryptOptions,
): Promise<{
  cek: Uint8Array<ArrayBuffer> | CryptoKey;
  plaintextBytes: Uint8Array<ArrayBuffer>;
}> {
  const {
    enc,
    encryptedKey,
    unwrapKeyOptions,
    ciphertext,
    iv,
    tag,
    aad,
    kid,
    allowSymmetric,
    keyCandidates,
    pbes2Budget,
  } = options;

  if (isJWKSet(rawKeyMaterial)) {
    const candidates = getJWKsFromSet(
      rawKeyMaterial,
      buildJWKSetFilter({ kid, alg }, { op: "enc", allowSymmetric }),
    );
    assertJWKSetCandidates(candidates, { limit: keyCandidates, kid });
    // A candidate this recipient was not encrypted to — unusable key material
    // as much as a failed unwrap — only means "try the next one"; the collected
    // reasons become the `cause` when none decrypts.
    const attempts: JWTError[] = [];
    for (const candidate of candidates) {
      try {
        if (alg === "dir") assertDirectKeyRole(candidate, enc);
        pbes2Budget.spend(unwrapKeyOptions);
        const unwrappingKey = await importKey(candidate as any, { alg, expect: "private" });
        const cek = await unwrapKey(encryptedKey, unwrappingKey, unwrapKeyOptions);
        const plaintextBytes = await joseDecrypt(enc, cek, ciphertext, iv, tag, aad);
        return { cek, plaintextBytes };
      } catch (err) {
        attempts.push(_asJWTError(err));
      }
    }
    throw new JWTError("JWE decryption failed.", "ERR_JWE_DECRYPTION_FAILED", attempts);
  }

  if (alg === "dir") assertDirectKeyRole(rawKeyMaterial, enc);
  pbes2Budget.spend(unwrapKeyOptions);
  try {
    const unwrappingKey = await importKey(resolvePasswordKey(alg, rawKeyMaterial), {
      alg,
      expect: "private",
    });
    const cek = await unwrapKey(encryptedKey, unwrappingKey, unwrapKeyOptions);
    const plaintextBytes = await joseDecrypt(enc, cek, ciphertext, iv, tag, aad);
    return { cek, plaintextBytes };
  } catch (err) {
    if (err instanceof JWTError) throw err;
    throw new JWTError("JWE decryption failed.", "ERR_JWE_DECRYPTION_FAILED", err);
  }
}
