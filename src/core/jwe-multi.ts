import { secureRandomBytes } from "unsecure/random";
import { sanitizeObjectCopy } from "unsecure/sanitize";
import { textEncoder } from "unsecure/utils";
import { base64UrlStringify } from "./utils/base64";

import type {
  JWK,
  JWKLookupFunction,
  KeyManagementAlgorithm,
  ContentEncryptionAlgorithm,
  UnwrapKeyOptions,
} from "./types/jwk";
import type { JOSEPayload, JWTClaims } from "./types/jwt";
import type {
  JWEEncryptJWK,
  JWEHeaderParameters,
  JWEProtectedHeader,
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
  generateIV,
  generateCEK,
  encryptKey,
} from "./_crypto";
import { JWTError } from "./error";
import type { PBES2Budget } from "./_internal";
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
  JWE_ALG_CTX,
  JWE_DIRECT_ALGS,
  assertCandidateLimit,
  assertDirectKeyRole,
  assertEntryLimit,
  assertNoZipOption,
  buildJWKSetFilter,
  cekFormatForEnc,
  checkAlgAllowed,
  checkJWEAlgSupported,
  checkJWEContentSegments,
  checkJWEDirectEncryptedKey,
  checkJWEEncSupported,
  checkJWEUnprotectedCrit,
  checkJWEZip,
  createPBES2Budget,
  decodeProtectedHeader,
  parseEphemeralKey,
  typMatches,
  resolveLimit,
  resolvePasswordKey,
  resolvePayloadMode,
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

  assertNoZipOption(options.protectedHeader, "protected");
  assertNoZipOption(options.sharedUnprotectedHeader, "shared unprotected");
  for (const recipient of recipients) assertNoZipOption(recipient?.header, "per-recipient");

  const resolvedAlgs: KeyManagementAlgorithm[] = recipients.map((r, i) =>
    _resolveRecipientAlg(r.key, i),
  );

  const enc: ContentEncryptionAlgorithm = options.enc ?? "A256GCM";

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

  const protectedHeaderEncoded = base64UrlStringify(JSON.stringify(protectedHeader));

  let aadEncoded: string | undefined;
  let aadForCipher: string = protectedHeaderEncoded;
  if (options.aad !== undefined) {
    const aadBytes =
      typeof options.aad === "string" ? textEncoder.encode(options.aad) : options.aad;
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

  const protectedHeaderEncoded = general.protected ?? "";
  const protectedHeader = decodeProtectedHeader<JWEHeaderParameters>(
    protectedHeaderEncoded || undefined,
    "JWE",
  );

  const enc = protectedHeader.enc as ContentEncryptionAlgorithm | undefined;
  if (!enc) {
    throw new JWTError('Invalid JWE: Protected header is missing "enc".', "ERR_JWE_INVALID");
  }

  const sharedUnprotected = sanitizeObjectCopy(general.unprotected) as
    | JWEHeaderParameters
    | undefined;

  // Token-wide verdicts: the protected header, the shared unprotected header and
  // the single content ciphertext are the same for every recipient, so they are
  // settled once, before any recipient is tried.
  const tokenError =
    checkJWEEncSupported(enc) ??
    checkJWEZip(protectedHeader) ??
    checkJWEUnprotectedCrit(sharedUnprotected) ??
    checkJWEZip(sharedUnprotected);
  if (tokenError) throw tokenError;

  if (options.encryptionAlgorithms && !options.encryptionAlgorithms.includes(enc)) {
    throw new JWTError(
      `Content encryption algorithm not allowed: ${enc}`,
      "ERR_JWE_ALG_NOT_ALLOWED",
    );
  }

  validateCriticalHeadersJWE(protectedHeader, options.recognizedHeaders);

  if (options.typ && !typMatches(options.typ, protectedHeader.typ)) {
    throw new JWTError(
      `Invalid JWE: "typ" (Type) Header Parameter mismatch. Expected "${options.typ}", got "${protectedHeader.typ}".`,
      "ERR_JWE_INVALID",
    );
  }

  const ivBytes = decodeSegment(general.iv, { family: "JWE", what: "Initialization vector" });
  const ciphertextBytes = decodeSegment(general.ciphertext, {
    family: "JWE",
    what: "Ciphertext",
  });
  const tagBytes = decodeSegment(general.tag, { family: "JWE", what: "Authentication tag" });

  const segmentError = checkJWEContentSegments(enc, ivBytes, tagBytes);
  if (segmentError) throw segmentError;

  const contentAadBytes = textEncoder.encode(
    general.aad ? `${protectedHeaderEncoded}.${general.aad}` : protectedHeaderEncoded,
  );

  let lastError: JWTError | undefined;
  let cryptoAttempted = false;
  for (let i = 0; i < general.recipients.length; i++) {
    // `recipients[]` is outside the AAD: anyone can append or rewrite an entry.
    // Every failure scoped to one recipient therefore only means "try the next
    // one" — it is collected as `lastError` and never aborts the loop.
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

    const rawKeyMaterial =
      typeof keyOrLookup === "function"
        ? await (keyOrLookup as JWKLookupFunction)(
            effective as Parameters<JWKLookupFunction>[0],
            protectedHeaderEncoded,
          )
        : keyOrLookup;

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

    const unwrapKeyOpts = _buildUnwrapKeyOptions(effective, { alg, enc }, options);

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
      protectedHeader: { ...protectedHeader, alg, enc } as JWEProtectedHeader,
      recipientIndex: i,
    };
    if (sharedUnprotected) result.sharedUnprotectedHeader = sharedUnprotected;
    if (recipientHeader) result.recipientHeader = recipientHeader;
    if (options.returnCek) {
      result.cek = isCryptoKey(cek)
        ? new Uint8Array(await crypto.subtle.exportKey("raw", cek))
        : cek;
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
  const alg = key.alg as KeyManagementAlgorithm | undefined;
  if (!alg) {
    throw new JWTError(
      `Cannot infer "alg" for recipient[${index}]: the JWK has no "alg" property.`,
      "ERR_JWE_RECIPIENT_ALG_INFERENCE",
    );
  }
  if (JWE_DIRECT_ALGS.has(alg)) {
    throw new JWTError(
      `Recipient[${index}] resolves to "${alg}", which requires exactly one recipient. Use encrypt() instead.`,
      "ERR_JWE_ALG_FORBIDDEN_IN_MULTI",
    );
  }
  return alg;
}

function _buildRecipientKeyMgmtParams(
  recipient: JWEMultiRecipient,
  alg: KeyManagementAlgorithm,
): JWEKeyManagementHeaderParameters {
  const params: JWEKeyManagementHeaderParameters = {};
  if (recipient.keyManagementIV) params.iv = recipient.keyManagementIV;
  if (recipient.p2s) params.p2s = recipient.p2s;
  else if (alg.startsWith("PBES2")) params.p2s = secureRandomBytes(16);
  if (recipient.p2c) params.p2c = recipient.p2c;
  else if (alg.startsWith("PBES2")) params.p2c = 600_000;
  if (recipient.ecdh?.partyUInfo) params.apu = recipient.ecdh.partyUInfo;
  if (recipient.ecdh?.partyVInfo) params.apv = recipient.ecdh.partyVInfo;
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

  if (Array.isArray(obj.recipients)) {
    return obj as unknown as JWEGeneralSerialization;
  }

  if ("encrypted_key" in obj || "header" in obj) {
    const flattened = obj as unknown as JWEFlattenedSerialization;
    const general: JWEGeneralSerialization = {
      recipients: [
        {
          ...(flattened.header !== undefined ? { header: flattened.header } : {}),
          ...(flattened.encrypted_key !== undefined
            ? { encrypted_key: flattened.encrypted_key }
            : {}),
        },
      ],
      iv: flattened.iv,
      ciphertext: flattened.ciphertext,
      tag: flattened.tag,
    };
    if (flattened.protected !== undefined) general.protected = flattened.protected;
    if (flattened.unprotected !== undefined) general.unprotected = flattened.unprotected;
    if (flattened.aad !== undefined) general.aad = flattened.aad;
    return general;
  }

  throw new JWTError(
    "Invalid JWE JSON Serialization: missing both recipients[] and flattened header/encrypted_key.",
    "ERR_JWE_INVALID_SERIALIZATION",
  );
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

/** Normalize anything thrown while trying one recipient into a collectable error. */
function _asJWTError(error: unknown): JWTError {
  if (error instanceof JWTError) return error;
  return new JWTError("JWE decryption failed.", "ERR_JWE_DECRYPTION_FAILED", error);
}

function _buildUnwrapKeyOptions(
  effectiveHeader: JWEHeaderParameters,
  algorithms: { alg: KeyManagementAlgorithm; enc: ContentEncryptionAlgorithm },
  options: JWEMultiDecryptOptions,
): UnwrapKeyOptions {
  const { alg, enc } = algorithms;
  const opts: UnwrapKeyOptions = {
    alg,
    enc,
    format: cekFormatForEnc(enc),
    keyUsage: options.keyUsage || ["decrypt"],
  };
  if (effectiveHeader.iv) opts.iv = effectiveHeader.iv;
  if (effectiveHeader.tag) opts.tag = effectiveHeader.tag;
  if (effectiveHeader.p2s) opts.p2s = effectiveHeader.p2s;
  if (effectiveHeader.p2c) opts.p2c = effectiveHeader.p2c;
  if (effectiveHeader.epk) opts.epk = effectiveHeader.epk;
  if (effectiveHeader.apu) opts.apu = effectiveHeader.apu;
  if (effectiveHeader.apv) opts.apv = effectiveHeader.apv;
  if (options.unwrappedKeyAlgorithm) opts.unwrappedKeyAlgorithm = options.unwrappedKeyAlgorithm;
  if (options.extractable) opts.extractable = options.extractable;
  if (options.minIterations !== undefined) opts.minIterations = options.minIterations;
  if (options.maxIterations !== undefined) opts.maxIterations = options.maxIterations;
  return opts;
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
  rawKeyMaterial: unknown,
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
    if (candidates.length === 0) {
      throw new JWTError("No key found in JWK Set.", "ERR_JWK_KEY_NOT_FOUND");
    }
    assertCandidateLimit(candidates.length, keyCandidates);
    // A candidate this recipient was not encrypted to — unusable key material
    // as much as a failed unwrap — only means "try the next one"; the collected
    // reasons become the `cause` when none decrypts.
    const attempts: JWTError[] = [];
    for (const candidate of candidates) {
      try {
        if (alg === "dir") assertDirectKeyRole(candidate, enc);
        pbes2Budget.spend(alg, unwrapKeyOptions.p2c);
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
  pbes2Budget.spend(alg, unwrapKeyOptions.p2c);
  const unwrappingKey = await importKey(resolvePasswordKey(alg, rawKeyMaterial) as any, {
    alg,
    expect: "private",
  });
  try {
    const cek = await unwrapKey(encryptedKey, unwrappingKey, unwrapKeyOptions);
    const plaintextBytes = await joseDecrypt(enc, cek, ciphertext, iv, tag, aad);
    return { cek, plaintextBytes };
  } catch (err) {
    if (err instanceof JWTError) throw err;
    throw new JWTError("JWE decryption failed.", "ERR_JWE_DECRYPTION_FAILED", err);
  }
}
