import type {
  JWK,
  JWKSet,
  JWK_Private,
  JWK_Symmetric,
  JWKLookupFunction,
  KeyManagementAlgorithm,
  ContentEncryptionAlgorithm,
  UnwrapKeyOptions,
} from "./types/jwk";
import type { JOSEPayload, JWTClaims } from "./types/jwt";
import type {
  JWEHeaderParameters,
  JWEProtectedHeader,
  JWEKeyManagementHeaderParameters,
  JWEGeneralSerialization,
  JWEGeneralRecipient,
  JWEFlattenedSerialization,
  JWEMultiRecipient,
  JWEMultiEncryptOptions,
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
import {
  base64UrlEncode,
  base64UrlDecode,
  randomBytes,
  textEncoder,
  isJWK,
  isJWKSet,
  isCryptoKey,
  sanitizeObject,
  applyTypCtyDefaults,
  computeJwtTimeClaims,
  decodePayloadFromBytes,
  getPlaintextBytes,
  validateCriticalHeadersJWE,
} from "./utils";
import {
  JWE_ALG_CTX,
  buildJWKSetFilter,
  checkAlgAllowed,
  decodeProtectedHeader,
  parseEphemeralKey,
  validateJwtClaimsIfJsonPayload,
} from "./_internal";

const DIRECT_ALGS: ReadonlySet<string> = /* @__PURE__ */ new Set(["dir", "ECDH-ES"]);

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

  const resolvedAlgs: KeyManagementAlgorithm[] = recipients.map((r, i) =>
    _resolveRecipientAlg(r.key, i),
  );

  const enc: ContentEncryptionAlgorithm = options.enc ?? "A256GCM";

  const userProtected = sanitizeObject(options.protectedHeader) as JWEHeaderParameters | undefined;
  const sharedUnprotected = sanitizeObject(options.sharedUnprotectedHeader) as
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
    if (encryptedKey) wireRecipient.encrypted_key = base64UrlEncode(encryptedKey);
    wireRecipients.push(wireRecipient);
  }

  const protectedHeaderEncoded = base64UrlEncode(JSON.stringify(protectedHeader));

  let aadEncoded: string | undefined;
  let aadForCipher: string = protectedHeaderEncoded;
  if (options.aad !== undefined) {
    const aadBytes =
      typeof options.aad === "string" ? textEncoder.encode(options.aad) : options.aad;
    aadEncoded = base64UrlEncode(aadBytes);
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
    iv: base64UrlEncode(actualContentIV),
    ciphertext: base64UrlEncode(contentCiphertext),
    tag: base64UrlEncode(contentAuthTag),
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
 * Matches recipients by, in order: `kid` equality, `kty`/`crv`/length
 * compatibility, then trial decryption. Set `strictRecipientMatch: true` to
 * disable the trial fallback.
 *
 * For compact (string) tokens, use {@link decrypt}.
 */
export async function decryptMulti<T extends JOSEPayload = JOSEPayload>(
  jwe: JWEGeneralSerialization | JWEFlattenedSerialization,
  keyOrLookup:
    | CryptoKey
    | JWKSet
    | JWK_Private
    | JWK_Symmetric
    | string
    | Uint8Array<ArrayBuffer>
    | JWKLookupFunction,
  options: JWEMultiDecryptOptions = {},
): Promise<JWEMultiDecryptResult<T>> {
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

  const protectedHeaderEncoded = general.protected ?? "";
  const protectedHeader = decodeProtectedHeader<JWEHeaderParameters>(
    protectedHeaderEncoded || undefined,
    "JWE",
  );

  const enc = protectedHeader.enc as ContentEncryptionAlgorithm | undefined;
  if (!enc) {
    throw new JWTError('Invalid JWE: Protected header is missing "enc".', "ERR_JWE_INVALID");
  }

  if (options.encryptionAlgorithms && !options.encryptionAlgorithms.includes(enc)) {
    throw new JWTError(
      `Content encryption algorithm not allowed: ${enc}`,
      "ERR_JWE_ALG_NOT_ALLOWED",
    );
  }

  const sharedUnprotected = sanitizeObject(general.unprotected) as JWEHeaderParameters | undefined;

  const ivBytes = base64UrlDecode(general.iv, false);
  const ciphertextBytes = base64UrlDecode(general.ciphertext, false);
  const tagBytes = base64UrlDecode(general.tag, false);
  const contentAadBytes = textEncoder.encode(
    general.aad ? `${protectedHeaderEncoded}.${general.aad}` : protectedHeaderEncoded,
  );

  let lastError: JWTError | undefined;
  let cryptoAttempted = false;
  for (let i = 0; i < general.recipients.length; i++) {
    const wireRecipient = general.recipients[i]!;
    const recipientHeader = sanitizeObject(wireRecipient.header) as JWEHeaderParameters | undefined;

    _assertDisjointHeaders(protectedHeader, sharedUnprotected, recipientHeader);

    const effective = _mergeHeaders(protectedHeader, sharedUnprotected, recipientHeader);
    const alg = effective.alg as KeyManagementAlgorithm | undefined;
    if (!alg) {
      lastError = new JWTError(
        `Recipient[${i}] has no "alg" in the effective header.`,
        "ERR_JWE_INVALID",
      );
      continue;
    }

    const rawKeyMaterial =
      typeof keyOrLookup === "function"
        ? await (keyOrLookup as JWKLookupFunction)(
            effective as Parameters<JWKLookupFunction>[0],
            protectedHeaderEncoded,
          )
        : keyOrLookup;

    const algError = checkAlgAllowed(alg, rawKeyMaterial, options.algorithms, JWE_ALG_CTX);
    if (algError) {
      lastError = algError;
      continue;
    }

    if (options.strictRecipientMatch && !_recipientKeyMatches(effective, rawKeyMaterial)) {
      continue;
    }

    const encryptedKeyBytes = base64UrlDecode(wireRecipient.encrypted_key, false);
    const unwrapKeyOpts = _buildUnwrapKeyOptions(effective, enc, options);

    cryptoAttempted = true;
    try {
      const { cek, plaintextBytes } = await _unwrapAndDecrypt(
        alg,
        enc,
        rawKeyMaterial,
        encryptedKeyBytes,
        unwrapKeyOpts,
        ciphertextBytes,
        ivBytes,
        tagBytes,
        contentAadBytes,
        effective.kid,
      );

      const payload = decodePayloadFromBytes<T>(plaintextBytes, options.forceUint8Array) as T;

      if (protectedHeader.crit || options.recognizedHeaders?.length) {
        validateCriticalHeadersJWE(protectedHeader, options.recognizedHeaders);
      }

      validateJwtClaimsIfJsonPayload(payload, options);

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
    } catch (err) {
      if (
        err instanceof JWTError &&
        err.code !== "ERR_JWE_DECRYPTION_FAILED" &&
        err.code !== "ERR_JWK_KEY_NOT_FOUND"
      ) {
        throw err;
      }
      lastError = err instanceof JWTError ? err : undefined;
    }
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

function _resolveRecipientAlg(key: JWK, index: number): KeyManagementAlgorithm {
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
  if (DIRECT_ALGS.has(alg)) {
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
  else if (alg.startsWith("PBES2")) params.p2s = randomBytes(16);
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
  const userHeader = sanitizeObject(recipient.header as JWEHeaderParameters | undefined);
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

function _recipientKeyMatches(effectiveHeader: JWEHeaderParameters, keyMaterial: unknown): boolean {
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

function _buildUnwrapKeyOptions(
  effectiveHeader: JWEHeaderParameters,
  enc: ContentEncryptionAlgorithm,
  options: JWEMultiDecryptOptions,
): UnwrapKeyOptions {
  const opts: UnwrapKeyOptions = {
    enc,
    format: enc.includes("GCM") ? "cryptokey" : "raw",
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

async function _unwrapAndDecrypt(
  alg: KeyManagementAlgorithm,
  enc: ContentEncryptionAlgorithm,
  rawKeyMaterial: unknown,
  encryptedKeyBytes: Uint8Array<ArrayBuffer>,
  unwrapKeyOpts: UnwrapKeyOptions,
  ciphertextBytes: Uint8Array<ArrayBuffer>,
  ivBytes: Uint8Array<ArrayBuffer>,
  tagBytes: Uint8Array<ArrayBuffer>,
  contentAadBytes: Uint8Array<ArrayBuffer>,
  headerKid: string | undefined,
): Promise<{
  cek: Uint8Array<ArrayBuffer> | CryptoKey;
  plaintextBytes: Uint8Array<ArrayBuffer>;
}> {
  if (isJWKSet(rawKeyMaterial)) {
    const candidates = getJWKsFromSet(rawKeyMaterial, buildJWKSetFilter({ kid: headerKid, alg }));
    if (candidates.length === 0) {
      throw new JWTError("No key found in JWK Set.", "ERR_JWK_KEY_NOT_FOUND");
    }
    let lastErr: unknown;
    for (const candidate of candidates) {
      const unwrappingKey = await importKey(candidate as any, { alg, expect: "private" });
      try {
        const cek = await unwrapKey(alg, encryptedKeyBytes, unwrappingKey, unwrapKeyOpts);
        const plaintextBytes = await joseDecrypt(
          enc,
          cek,
          ciphertextBytes,
          ivBytes,
          tagBytes,
          contentAadBytes,
        );
        return { cek, plaintextBytes };
      } catch (err) {
        if (err instanceof JWTError && err.code !== "ERR_JWE_DECRYPTION_FAILED") throw err;
        lastErr = err;
      }
    }
    throw lastErr ?? new JWTError("JWE decryption failed.", "ERR_JWE_DECRYPTION_FAILED");
  }

  const unwrappingKey = await importKey(rawKeyMaterial as any, { alg, expect: "private" });
  try {
    const cek = await unwrapKey(alg, encryptedKeyBytes, unwrappingKey, unwrapKeyOpts);
    const plaintextBytes = await joseDecrypt(
      enc,
      cek,
      ciphertextBytes,
      ivBytes,
      tagBytes,
      contentAadBytes,
    );
    return { cek, plaintextBytes };
  } catch (err) {
    if (err instanceof JWTError) throw err;
    throw new JWTError("JWE decryption failed.", "ERR_JWE_DECRYPTION_FAILED", err);
  }
}
