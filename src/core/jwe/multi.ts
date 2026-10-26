import { textEncoder } from "unsecure/utils";
import { base64UrlStringify } from "../../utils/base64.ts";
import type { KeyManagementAlgorithm, ContentEncryptionAlgorithm } from "../types/jwk.ts";
import type { JOSEPayload, JOSEPayloadMode, JWTClaims, PayloadOf } from "../types/jwt.ts";
import type {
  JWEHeaderParameters,
  JWEGeneralSerialization,
  JWEGeneralRecipient,
  JWEFlattenedSerialization,
  JWEMultiRecipient,
  JWEMultiEncryptOptions,
  JWEMultiDecryptKey,
  JWEMultiDecryptOptions,
  JWEMultiDecryptResult,
} from "../types/jwe.ts";
import { importKey } from "../_internal/import-key.ts";
import {
  encrypt as joseEncrypt,
  assertPBES2Params,
  generateIV,
  generateCEK,
  encryptKey,
} from "../_crypto/index.ts";
import { JWTError } from "../../error.ts";
import type { ResolvedKeyInput } from "../_internal/keys.ts";
import { resolveKeyInput } from "../_internal/keys.ts";
import {
  applyTypDefault,
  computeJwtTimeClaims,
  getPlaintextBytes,
  validateCriticalHeadersJWE,
} from "../_internal/jwt.ts";
import { JWE_ALG_CTX, checkJWEAlgSupported, checkJWEEncAllowed } from "./_internal/algorithms.ts";
import {
  checkProtectedTyp,
  assertProducerCrit,
  assertConsumerOptions,
  assertOptionEntry,
  assertProtectedOnlyOption,
  assertProducerKeyHeaders,
  assertProducerConfirmation,
  assertSerializationObject,
  checkSerializationEntry,
  decodeProtectedHeader,
  serializeProtectedHeader,
  decodeSegment,
} from "../_internal/headers.ts";
import { assertEntryLimit, createKeyAttemptBudget, resolveLimit } from "../_internal/limits.ts";
import {
  assertNoZipOption,
  assertProducerCEK,
  assertProducerIV,
  checkJWEContentSegments,
  checkJWEDirectEncryptedKey,
  checkJWEUnprotectedCrit,
  checkJWEZip,
} from "./_internal/checks.ts";
import { asDecryptionError, asKeyLookupError, copyJsonObject } from "../_internal/errors.ts";
import { buildUnwrapKeyOptions, createPBES2Budget, exportReturnedCek } from "./_internal/keys.ts";
import {
  checkAlgAllowed,
  checkJWEEncSupported,
  assertJWEEncSupported,
  keyMatchesHeader,
} from "../_internal/algorithms.ts";
import { resolvePayloadMode, validateClaimsIfJson } from "../_internal/payload.ts";
import {
  buildKeyManagementParams,
  decodeJWEPayload,
  unwrapAndDecrypt,
} from "./_internal/encrypt-decrypt.ts";
import {
  _resolveRecipientAlg,
  _buildPerRecipientHeader,
  _assertDisjointHeaders,
  _mergeHeaders,
  _normalizeSerialization,
  _assertAADOption,
} from "./_internal/multi.ts";

/**
 * Encrypt a payload to multiple recipients as JWE General JSON Serialization (RFC 7516 §7.2.1).
 * Each recipient's `alg` comes from `key.alg` (`ERR_JWE_RECIPIENT_ALG_INFERENCE` when absent);
 * `dir` and bare `ECDH-ES` throw `ERR_JWE_ALG_FORBIDDEN_IN_MULTI`.
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
  assertProducerKeyHeaders(options.protectedHeader, { tier: "protected", family: "JWE" });
  assertProducerKeyHeaders(options.sharedUnprotectedHeader, {
    tier: "shared unprotected",
    family: "JWE",
  });
  assertProducerConfirmation(payload);
  for (const [index, recipient] of recipients.entries()) {
    assertOptionEntry(recipient, { label: `recipients[${index}]`, objects: ["header"] });
    assertNoZipOption(recipient.header, "per-recipient");
    assertProtectedOnlyOption(recipient.header, { tier: "per-recipient", family: "JWE" });
    assertProducerKeyHeaders(recipient.header, { tier: "per-recipient", family: "JWE" });
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
    if (resolvedAlgs[index].startsWith("PBES2")) {
      assertPBES2Params({ p2s: recipient.p2s, p2c: recipient.p2c });
    }
  }

  const userProtected = copyJsonObject(options.protectedHeader, {
    code: "ERR_INVALID_OPTION",
    message: '"protectedHeader" must hold only JSON values.',
  });
  const sharedUnprotected = copyJsonObject(options.sharedUnprotectedHeader, {
    code: "ERR_INVALID_OPTION",
    message: '"sharedUnprotectedHeader" must hold only JSON values.',
  });

  const protectedHeader = {} as JWEHeaderParameters;
  if (userProtected) Object.assign(protectedHeader, userProtected);
  protectedHeader.enc = enc;
  applyTypDefault(protectedHeader, payload);
  assertProducerCrit(protectedHeader, "JWE");

  const computedPayload: JWTClaims | undefined = computeJwtTimeClaims(payload, options);
  const plaintextBytes = getPlaintextBytes(computedPayload || payload);

  const cek: Uint8Array<ArrayBuffer> = options.cek ?? generateCEK(enc);

  const wireRecipients: JWEGeneralRecipient[] = [];
  for (let i = 0; i < recipients.length; i++) {
    const recipient = recipients[i];
    const alg = resolvedAlgs[i];

    const keyMgmtParams = buildKeyManagementParams(alg, recipient);

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
 * Decrypt a JWE General (RFC 7516 §7.2.1) or Flattened (§7.2.2) JSON Serialization.
 * Recipients are tried in order; when none opens, the call throws `ERR_JWE_DECRYPTION_FAILED`
 * with every recipient's error as `cause`, in recipient order. `strictRecipientMatch` skips
 * recipients the key cannot open and throws `ERR_JWE_NO_MATCHING_RECIPIENT` when none qualifies.
 * The payload type follows `options.payload`.
 */
export async function decryptMulti<T extends object = JWTClaims>(
  jwe: JWEGeneralSerialization | JWEFlattenedSerialization,
  keyOrLookup: JWEMultiDecryptKey,
  options?: JWEMultiDecryptOptions<"json">,
): Promise<JWEMultiDecryptResult<T>>;
/** Decrypts a JWE JSON Serialization whose plaintext decodes under `options.payload`; see {@link PayloadOf}. */
export async function decryptMulti<Mode extends JOSEPayloadMode = JOSEPayloadMode>(
  jwe: JWEGeneralSerialization | JWEFlattenedSerialization,
  keyOrLookup: JWEMultiDecryptKey,
  options?: JWEMultiDecryptOptions<Mode>,
): Promise<JWEMultiDecryptResult<PayloadOf<Mode>>>;
export async function decryptMulti(
  jwe: JWEGeneralSerialization | JWEFlattenedSerialization,
  keyOrLookup: JWEMultiDecryptKey,
  options: JWEMultiDecryptOptions = {},
): Promise<JWEMultiDecryptResult> {
  assertConsumerOptions(options);
  const payloadMode = resolvePayloadMode(options);
  const recipientLimit = resolveLimit(options.limits, "recipients");
  const keyCandidates = resolveLimit(options.limits, "keyCandidates");
  const keyAttempts = createKeyAttemptBudget(resolveLimit(options.limits, "keyAttempts"));
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
  const protectedHeader = decodeProtectedHeader(protectedHeaderEncoded || undefined, "JWE");
  const sharedUnprotected = copyJsonObject(general.unprotected, {
    code: "ERR_JWE_INVALID",
    message: 'Invalid JWE JSON Serialization: "unprotected" must hold only JSON values.',
  });

  const sharedError =
    checkJWEZip(protectedHeader) ??
    checkJWEUnprotectedCrit(sharedUnprotected) ??
    checkJWEZip(sharedUnprotected);
  if (sharedError) throw sharedError;
  _assertDisjointHeaders(protectedHeader, sharedUnprotected, undefined);

  // RFC 7516 §7.2.1 — `enc` never sits in a per-recipient header.
  const enc = protectedHeader.enc ?? sharedUnprotected?.enc;
  if (!enc) {
    throw new JWTError(
      'Invalid JWE: "enc" is missing from the protected and shared unprotected headers.',
      "ERR_JWE_INVALID",
    );
  }
  assertJWEEncSupported(enc);
  const encError = checkJWEEncAllowed(enc, options.encryptionAlgorithms);
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

  const failures: JWTError[] = [];
  let cryptoAttempted = false;
  for (let i = 0; i < general.recipients.length; i++) {
    const shapeError = checkSerializationEntry(general.recipients[i], {
      family: "JWE",
      label: `Recipient[${i}]`,
      objects: ["header"],
      strings: ["encrypted_key"],
    });
    if (shapeError) {
      failures.push(shapeError);
      continue;
    }
    const wireRecipient = general.recipients[i];
    const recipientHeader = copyJsonObject(wireRecipient.header, {
      code: "ERR_JWE_INVALID",
      message: 'Invalid JWE JSON Serialization: a recipient "header" must hold only JSON values.',
    });

    const recipientError = checkJWEUnprotectedCrit(recipientHeader) ?? checkJWEZip(recipientHeader);
    if (recipientError) {
      failures.push(recipientError);
      continue;
    }

    try {
      _assertDisjointHeaders(protectedHeader, sharedUnprotected, recipientHeader);
    } catch (err) {
      failures.push(asDecryptionError(err));
      continue;
    }

    const effective = _mergeHeaders(protectedHeader, sharedUnprotected, recipientHeader);
    const alg = effective.alg;
    if (!alg) {
      failures.push(
        new JWTError(`Recipient[${i}] has no "alg" in the effective header.`, "ERR_JWE_INVALID"),
      );
      continue;
    }

    const supportError = checkJWEAlgSupported(alg);
    if (supportError) {
      failures.push(supportError);
      continue;
    }
    const directKeyError = checkJWEDirectEncryptedKey(alg, wireRecipient.encrypted_key);
    if (directKeyError) {
      failures.push(directKeyError);
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
      failures.push(asKeyLookupError(err, `recipient[${i}]`));
      continue;
    }

    const algError = checkAlgAllowed(alg, rawKeyMaterial, {
      ctx: JWE_ALG_CTX,
      algorithms: options.algorithms,
    });
    if (algError) {
      failures.push(algError);
      continue;
    }

    if (
      options.strictRecipientMatch &&
      !keyMatchesHeader(effective, rawKeyMaterial, {
        ctx: JWE_ALG_CTX,
      })
    ) {
      failures.push(
        new JWTError(
          `JWE recipient[${i}] does not match the key under strictRecipientMatch.`,
          "ERR_JWE_NO_MATCHING_RECIPIENT",
        ),
      );
      continue;
    }

    let encryptedKeyBytes: Uint8Array<ArrayBuffer>;
    try {
      encryptedKeyBytes = decodeSegment(wireRecipient.encrypted_key ?? "", {
        family: "JWE",
        what: "Encrypted key",
      });
    } catch (err) {
      failures.push(asDecryptionError(err));
      continue;
    }

    const unwrapKeyOpts = buildUnwrapKeyOptions(effective, { alg, enc }, options);

    cryptoAttempted = true;
    let cek: Uint8Array<ArrayBuffer> | CryptoKey;
    let plaintextBytes: Uint8Array<ArrayBuffer>;
    try {
      ({ cek, plaintextBytes } = await unwrapAndDecrypt(alg, rawKeyMaterial, {
        enc,
        encryptedKey: encryptedKeyBytes,
        unwrapKeyOptions: unwrapKeyOpts,
        ciphertext: ciphertextBytes,
        iv: ivBytes,
        tag: tagBytes,
        aad: contentAadBytes,
        kid: effective.kid,
        keyCandidates,
        pbes2Budget,
        keyAttempts,
      }));
    } catch (err) {
      if (keyAttempts.exhausted) throw keyAttempts.exhausted;
      failures.push(asDecryptionError(err));
      continue;
    }

    const payload = decodeJWEPayload(plaintextBytes, payloadMode);

    validateClaimsIfJson(payload, payloadMode, options);

    const result: JWEMultiDecryptResult = {
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

  if (options.strictRecipientMatch && !cryptoAttempted) {
    throw new JWTError(
      "No recipient matched the provided key under strictRecipientMatch.",
      "ERR_JWE_NO_MATCHING_RECIPIENT",
    );
  }
  throw new JWTError("JWE decryption failed.", "ERR_JWE_DECRYPTION_FAILED", failures);
}

/**
 * Convert a single-recipient General JWE to the Flattened form (RFC 7516 §7.2.2).
 * Throws `ERR_JWE_INVALID_SERIALIZATION` for zero or multiple recipients.
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
  const [recipient] = recipients;
  const flattened: JWEFlattenedSerialization = { ...rest };
  if (recipient.header !== undefined) flattened.header = recipient.header;
  if (recipient.encrypted_key !== undefined) flattened.encrypted_key = recipient.encrypted_key;
  return flattened;
}
