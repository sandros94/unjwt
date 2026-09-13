import { secureRandomBytes } from "unsecure/random";
import { sanitizeObjectCopy } from "unsecure/sanitize";
import { textEncoder } from "unsecure/utils";
import { base64UrlStringify } from "./utils/base64";

import type {
  JWKSet,
  JWKLookupFunction,
  KeyManagementAlgorithm,
  ContentEncryptionAlgorithm,
  UnwrapKeyOptions,
} from "./types/jwk";
import type { JOSEPayload, JWTClaims } from "./types/jwt";
import type {
  JWEEncryptJWK,
  JWEDecryptJWK,
  JWEEncryptOptions,
  JWEDecryptOptions,
  JWEDecryptResult,
  JWEHeaderParameters,
  JWEProtectedHeader,
  JWEKeyManagementHeaderParameters,
} from "./types/jwe";

import { importKey, unwrapKey, getJWKsFromSet } from "./jwk";
import { encrypt as joseEncrypt, decrypt as joseDecrypt, generateIV, encryptKey } from "./_crypto";
import { JWTError } from "./error";
import {
  isJWK,
  isJWKSet,
  isCryptoKey,
  applyTypCtyDefaults,
  computeJwtTimeClaims,
  decodePayloadFromBytes,
  getPlaintextBytes,
  validateCriticalHeadersJWE,
} from "./utils";
import {
  JWE_ALG_CTX,
  assertDirectKeyRole,
  assertNoZipOption,
  asKeyUsageError,
  buildJWKSetFilter,
  cekFormatForEnc,
  checkAlgAllowed,
  checkJWEAlgSupported,
  checkJWEContentSegments,
  checkJWEDirectEncryptedKey,
  checkJWEEncSupported,
  checkJWEZip,
  decodeProtectedHeader,
  parseEphemeralKey,
  resolvePasswordKey,
  resolvePayloadMode,
  typMatches,
  validateClaimsIfJson,
  decodeSegment,
} from "./_internal";

export type * from "./types/jwe";
export {
  type JWTErrorCode,
  type KnownJWTErrorCode,
  type JWTErrorCauseMap,
  type UnsecureErrorCode,
  JWTError,
  isJWTError,
  UnsecureError,
  isUnsecureError,
} from "./error";
export { encryptMulti, decryptMulti, generalToFlattened } from "./jwe-multi";

/**
 * Encrypts a payload to produce a JWE Compact Serialization string.
 *
 * @param payload The payload to encrypt. Can be a string, Uint8Array, or a JSON-serializable object.
 * @param key The key encryption key (KEK). Can be a CryptoKey, JWK, or for PBES2, a password string/Uint8Array.
 * @param options JWE encryption options, including `alg` (key management algorithm) and `enc` (content encryption algorithm).
 * @returns A Promise resolving to the JWE Compact Serialization string.
 */
export async function encrypt(
  payload: JOSEPayload,
  key: JWEEncryptJWK | string | Uint8Array<ArrayBuffer>,
  options?: JWEEncryptOptions,
): Promise<string>;
export async function encrypt(
  payload: JOSEPayload,
  key: CryptoKey | Extract<JWEEncryptJWK, { kty: "oct" }> | Uint8Array<ArrayBuffer>,
  options: JWEEncryptOptions & { alg: "dir"; enc: ContentEncryptionAlgorithm },
): Promise<string>;
export async function encrypt(
  payload: JOSEPayload,
  key: CryptoKey,
  options: JWEEncryptOptions & {
    alg: KeyManagementAlgorithm;
    enc: ContentEncryptionAlgorithm;
  },
): Promise<string>;
export async function encrypt(
  payload: JOSEPayload,
  key: CryptoKey | JWEEncryptJWK | string | Uint8Array<ArrayBuffer>,
  options: JWEEncryptOptions & {
    alg: KeyManagementAlgorithm;
    enc: ContentEncryptionAlgorithm;
  },
): Promise<string>;
export async function encrypt(
  payload: string | Uint8Array<ArrayBuffer> | Record<string, unknown>,
  key: CryptoKey | JWEEncryptJWK | string | Uint8Array<ArrayBuffer>,
  options: JWEEncryptOptions = {},
): Promise<string> {
  const {
    protectedHeader: userHeader,
    cek: providedCek,
    contentEncryptionIV: providedContentIV,
    keyManagementIV,
    p2s,
    p2c,
    ecdh,
  } = options;
  let { alg, enc } = options;

  assertNoZipOption(userHeader, "protected");

  if (!alg) {
    if (typeof key === "string" || key instanceof Uint8Array) {
      alg = "PBES2-HS256+A128KW";
    } else if (isJWK(key)) {
      alg = key.alg as KeyManagementAlgorithm;
    }
  }
  if (!alg) {
    throw new JWTError(
      'JWE "alg" (Key Management Algorithm) must be provided in options or inferable from the key',
      "ERR_JWE_ALG_MISSING",
    );
  }
  if (!enc) {
    if (alg === "dir") {
      // Allow `enc` to ride on the JWK when `alg: "dir"`.
      enc = isJWK(key) && "enc" in key ? (key.enc as ContentEncryptionAlgorithm) : undefined;
      if (!enc) {
        throw new JWTError('JWE "enc" must be provided when alg is "dir"', "ERR_JWE_ENC_MISSING");
      }
    } else {
      enc = isJWK(key) && "enc" in key ? (key.enc as ContentEncryptionAlgorithm) : "A128GCM";
    }
  }

  const jweKeyManagementParams: JWEKeyManagementHeaderParameters = {};
  if (keyManagementIV) jweKeyManagementParams.iv = keyManagementIV;
  if (p2s) jweKeyManagementParams.p2s = p2s;
  else if (alg?.startsWith("PBES2")) jweKeyManagementParams.p2s = secureRandomBytes(16);
  if (p2c) jweKeyManagementParams.p2c = p2c;
  else if (alg?.startsWith("PBES2")) jweKeyManagementParams.p2c = 600_000;
  if (ecdh?.partyUInfo) jweKeyManagementParams.apu = ecdh.partyUInfo;
  if (ecdh?.partyVInfo) jweKeyManagementParams.apv = ecdh.partyVInfo;
  if (ecdh?.ephemeralKey) {
    const parsed = parseEphemeralKey(ecdh.ephemeralKey);
    jweKeyManagementParams.epk = parsed.epk;
    jweKeyManagementParams.epkPrivateKey = parsed.epkPrivateKey;
  }

  const wrappingKeyMaterial = await importKey(resolvePasswordKey(alg, key), {
    alg,
    expect: "public",
  });
  if (alg === "dir") assertDirectKeyRole(key, enc);

  const {
    cek: finalCek,
    encryptedKey: jweEncryptedKey,
    parameters: keyManagementHeaderParams,
  } = await encryptKey(alg, enc, wrappingKeyMaterial, providedCek, jweKeyManagementParams);

  const protectedHeader = _buildJWEHeader(
    alg,
    enc,
    key,
    userHeader,
    keyManagementHeaderParams,
    payload,
  );

  const computedPayload: JWTClaims | undefined = computeJwtTimeClaims(payload, options);

  const plaintextBytes = getPlaintextBytes(computedPayload || payload);

  const protectedHeaderSerialized = JSON.stringify(protectedHeader);
  const protectedHeaderEncoded = base64UrlStringify(protectedHeaderSerialized);

  const aadBytes = textEncoder.encode(protectedHeaderEncoded);
  const contentIVBytes = providedContentIV ?? generateIV(enc);

  const {
    ciphertext: contentCiphertext,
    tag: contentAuthTag,
    iv: actualContentIV,
  } = await joseEncrypt(enc, plaintextBytes, finalCek, contentIVBytes, aadBytes);

  if (!actualContentIV) {
    throw new JWTError("Content encryption IV was not generated or returned.", "ERR_JWE_INVALID");
  }
  if (!contentAuthTag) {
    throw new JWTError(
      "Content encryption auth tag was not generated or returned.",
      "ERR_JWE_INVALID",
    );
  }

  // `dir` and `ECDH-ES` (direct key agreement) have no encrypted key — RFC 7516 §4.5.
  const encryptedKeyEncoded = jweEncryptedKey ? base64UrlStringify(jweEncryptedKey) : "";

  const jweParts: string[] = [
    protectedHeaderEncoded,
    encryptedKeyEncoded,
    base64UrlStringify(actualContentIV),
    base64UrlStringify(contentCiphertext),
    base64UrlStringify(contentAuthTag),
  ];

  return jweParts.join(".");
}

/**
 * Decrypts a JWE Compact Serialization string.
 *
 * @param jwe The JWE Compact Serialization string.
 * @param key The key decryption key (KEK) or a function to look up the key.
 * @param options JWE decryption options.
 * @returns A Promise resolving to an object containing the decrypted plaintext, protected header, CEK, and AAD.
 * @throws If JWE is invalid, decryption fails, or options are not met.
 */
export async function decrypt(
  jwe: string,
  key: CryptoKey | JWKSet | JWEDecryptJWK | string | Uint8Array<ArrayBuffer> | JWKLookupFunction,
  options: JWEDecryptOptions & { payload: "bytes" },
): Promise<JWEDecryptResult<Uint8Array<ArrayBuffer>>>;
export async function decrypt(
  jwe: string,
  key: CryptoKey | JWKSet | JWEDecryptJWK | string | Uint8Array<ArrayBuffer> | JWKLookupFunction,
  options: JWEDecryptOptions & { payload: "string" },
): Promise<JWEDecryptResult<string>>;
export async function decrypt(
  jwe: string,
  key: CryptoKey | JWKSet | JWEDecryptJWK | string | Uint8Array<ArrayBuffer> | JWKLookupFunction,
  options: JWEDecryptOptions & { forceUint8Array: true },
): Promise<JWEDecryptResult<Uint8Array<ArrayBuffer>>>;
export async function decrypt<T extends Record<string, unknown> = JWTClaims>(
  jwe: string,
  key: CryptoKey | JWKSet | JWEDecryptJWK | string | Uint8Array<ArrayBuffer> | JWKLookupFunction,
  options?: JWEDecryptOptions,
): Promise<JWEDecryptResult<T>>;
export async function decrypt<T extends JOSEPayload>(
  jwe: string,
  key: CryptoKey | JWKSet | JWEDecryptJWK | string | Uint8Array<ArrayBuffer> | JWKLookupFunction,
  options: JWEDecryptOptions = {},
): Promise<JWEDecryptResult<T>> {
  const payloadMode = resolvePayloadMode(options);

  const parts = jwe.split(".");
  if (parts.length !== 5) {
    throw new JWTError(
      "Invalid JWE: Must contain five sections (RFC7516, section-3).",
      "ERR_JWE_INVALID",
    );
  }
  const [
    protectedHeaderEncoded,
    encryptedKeyEncoded,
    ivEncoded,
    ciphertextEncoded,
    authTagEncoded,
  ] = parts;

  const protectedHeader = decodeProtectedHeader<JWEHeaderParameters>(protectedHeaderEncoded, "JWE");

  if (!protectedHeader.alg || !protectedHeader.enc) {
    throw new JWTError(
      'Invalid JWE: Protected header must be an object with "alg" and "enc" properties.',
      "ERR_JWE_INVALID",
    );
  }

  const alg = protectedHeader.alg as KeyManagementAlgorithm;
  const enc = protectedHeader.enc as ContentEncryptionAlgorithm;

  // Everything the protected header alone decides — algorithm support, `enc`,
  // compression, `crit`, `typ` — is settled before any key is resolved or
  // imported, so a malformed token never reaches key management.
  const headerError =
    checkJWEAlgSupported(alg) ?? checkJWEEncSupported(enc) ?? checkJWEZip(protectedHeader);
  if (headerError) throw headerError;

  if (options?.encryptionAlgorithms && !options.encryptionAlgorithms.includes(enc)) {
    throw new JWTError(
      `Content encryption algorithm not allowed: ${enc}`,
      "ERR_JWE_ALG_NOT_ALLOWED",
    );
  }

  validateCriticalHeadersJWE(protectedHeader, options?.recognizedHeaders);

  if (options.typ && !typMatches(options.typ, protectedHeader.typ)) {
    throw new JWTError(
      `Invalid JWE: "typ" (Type) Header Parameter mismatch. Expected "${options.typ}", got "${protectedHeader.typ}".`,
      "ERR_JWE_INVALID",
    );
  }

  const directKeyError = checkJWEDirectEncryptedKey(alg, encryptedKeyEncoded);
  if (directKeyError) throw directKeyError;

  const encryptedKeyBytes = decodeSegment(encryptedKeyEncoded, {
    family: "JWE",
    what: "Encrypted key",
  });
  const contentIVBytes = decodeSegment(ivEncoded, {
    family: "JWE",
    what: "Initialization vector",
  });
  const contentAuthTagBytes = decodeSegment(authTagEncoded, {
    family: "JWE",
    what: "Authentication tag",
  });
  const ciphertextBytes = decodeSegment(ciphertextEncoded, { family: "JWE", what: "Ciphertext" });

  const segmentError = checkJWEContentSegments(enc, contentIVBytes, contentAuthTagBytes);
  if (segmentError) throw segmentError;

  const rawKeyMaterial = typeof key === "function" ? await key(protectedHeader, jwe) : key;

  const algError = checkAlgAllowed(alg, rawKeyMaterial, {
    ctx: JWE_ALG_CTX,
    algorithms: options?.algorithms,
    allowSymmetric: options?.allowSymmetricJWKSet,
  });
  if (algError) throw algError;

  const unwrapKeyOpts: UnwrapKeyOptions = {
    alg,
    enc,
    format: cekFormatForEnc(enc),
    keyUsage: options?.keyUsage || ["decrypt"],
  };
  if (protectedHeader.iv) unwrapKeyOpts.iv = protectedHeader.iv;
  if (protectedHeader.tag) unwrapKeyOpts.tag = protectedHeader.tag;
  if (protectedHeader.p2s) unwrapKeyOpts.p2s = protectedHeader.p2s;
  if (protectedHeader.p2c) unwrapKeyOpts.p2c = protectedHeader.p2c;
  if (protectedHeader.epk) unwrapKeyOpts.epk = protectedHeader.epk;
  if (protectedHeader.apu) unwrapKeyOpts.apu = protectedHeader.apu;
  if (protectedHeader.apv) unwrapKeyOpts.apv = protectedHeader.apv;
  if (options?.unwrappedKeyAlgorithm)
    unwrapKeyOpts.unwrappedKeyAlgorithm = options.unwrappedKeyAlgorithm;
  if (options?.extractable) unwrapKeyOpts.extractable = options.extractable;
  if (options?.minIterations !== undefined) unwrapKeyOpts.minIterations = options.minIterations;
  if (options?.maxIterations !== undefined) unwrapKeyOpts.maxIterations = options.maxIterations;

  const aadBytes = textEncoder.encode(protectedHeaderEncoded);

  let cek!: Uint8Array<ArrayBuffer> | CryptoKey;
  let plaintextBytes!: Uint8Array<ArrayBuffer>;

  if (isJWKSet(rawKeyMaterial)) {
    const candidates = getJWKsFromSet(
      rawKeyMaterial,
      buildJWKSetFilter(protectedHeader, {
        op: "enc",
        allowSymmetric: options?.allowSymmetricJWKSet,
      }),
    );
    if (candidates.length === 0) {
      throw new JWTError(
        `No key found in JWK Set${protectedHeader.kid ? ` with kid "${protectedHeader.kid}"` : ""}.`,
        "ERR_JWK_KEY_NOT_FOUND",
      );
    }
    // A candidate this token was not encrypted to — unusable key material as
    // much as a failed unwrap — only means "try the next one"; the collected
    // reasons become the `cause` when none decrypts.
    let decrypted = false;
    const attempts: JWTError[] = [];
    for (const candidate of candidates) {
      try {
        if (alg === "dir") assertDirectKeyRole(candidate, enc);
        const unwrappingKey = await importKey(candidate as any, { alg, expect: "private" });
        const candidateCek = await unwrapKey(encryptedKeyBytes, unwrappingKey, unwrapKeyOpts);
        plaintextBytes = await joseDecrypt(
          enc,
          candidateCek,
          ciphertextBytes,
          contentIVBytes,
          contentAuthTagBytes,
          aadBytes,
        );
        cek = candidateCek;
        decrypted = true;
        break;
      } catch (err) {
        attempts.push(asKeyUsageError(err, alg));
      }
    }
    if (!decrypted) {
      throw new JWTError("JWE decryption failed.", "ERR_JWE_DECRYPTION_FAILED", attempts);
    }
  } else {
    if (alg === "dir") assertDirectKeyRole(rawKeyMaterial, enc);
    const unwrappingKey = await importKey(resolvePasswordKey(alg, rawKeyMaterial), {
      alg,
      expect: "private",
    });
    try {
      cek = await unwrapKey(encryptedKeyBytes, unwrappingKey, unwrapKeyOpts);
      plaintextBytes = await joseDecrypt(
        enc,
        cek,
        ciphertextBytes,
        contentIVBytes,
        contentAuthTagBytes,
        aadBytes,
      );
    } catch (error_) {
      if (error_ instanceof JWTError) throw error_;
      throw new JWTError("JWE decryption failed.", "ERR_JWE_DECRYPTION_FAILED", error_);
    }
  }

  const payload = decodePayloadFromBytes<T>(plaintextBytes, {
    payload: payloadMode,
    family: "JWE",
  }) as T;

  validateClaimsIfJson(payload, payloadMode, options);

  const result: JWEDecryptResult<T> = {
    payload,
    protectedHeader: protectedHeader as JWEProtectedHeader,
  };

  if (options.returnCek) {
    result.cek = isCryptoKey(cek) ? new Uint8Array(await crypto.subtle.exportKey("raw", cek)) : cek;
    result.aad = aadBytes;
  }

  return result;
}

function _buildJWEHeader(
  alg: KeyManagementAlgorithm,
  enc: ContentEncryptionAlgorithm,
  key: CryptoKey | JWEEncryptJWK | string | Uint8Array<ArrayBuffer>,
  userHeader: JWEEncryptOptions["protectedHeader"],
  keyManagementParams: JWEHeaderParameters | undefined,
  payload: unknown,
): JWEHeaderParameters {
  const safeHeader = sanitizeObjectCopy<JWEHeaderParameters | undefined>(
    userHeader as JWEHeaderParameters | undefined,
  );
  // Precedence: top-level `alg`/`enc` > key management params > user header > JWK `kid`.
  // Build imperatively to avoid the intermediate `{ kid }` / spread-output allocations.
  const header = {} as JWEHeaderParameters;
  if (isJWK(key) && key.kid) header.kid = key.kid;
  if (safeHeader) Object.assign(header, safeHeader);
  if (keyManagementParams) Object.assign(header, keyManagementParams);
  header.alg = alg;
  header.enc = enc;
  return applyTypCtyDefaults(header, payload);
}
