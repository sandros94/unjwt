import type {
  JWK,
  JWKSet,
  JWK_Symmetric,
  JWK_Private,
  JWK_EC_Public,
  JWK_EC_Private,
  JWKLookupFunction,
  KeyManagementAlgorithm,
  ContentEncryptionAlgorithm,
  UnwrapKeyOptions,
} from "./types/jwk";
import type { JOSEPayload, JWTClaims } from "./types/jwt";
import type {
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
  base64UrlEncode,
  base64UrlDecode,
  randomBytes,
  textEncoder,
  isJWK,
  isJWKSet,
  isCryptoKey,
  isCryptoKeyPair,
  sanitizeObject,
  applyTypCtyDefaults,
  computeJwtTimeClaims,
  decodePayloadFromBytes,
  getPlaintextBytes,
  inferJWEAllowedAlgorithms,
  validateCriticalHeadersJWE,
  validateJwtClaims,
} from "./utils";

export type * from "./types/jwe";
export { type JWTErrorCode, type JWTErrorCauseMap, JWTError, isJWTError } from "./error";

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
  key: JWK | string | Uint8Array<ArrayBuffer>,
  options?: JWEEncryptOptions,
): Promise<string>;
export async function encrypt(
  payload: JOSEPayload,
  key: CryptoKey | JWK_Symmetric | Uint8Array<ArrayBuffer>,
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
  key: CryptoKey | JWK | string | Uint8Array<ArrayBuffer>,
  options: JWEEncryptOptions & {
    alg: KeyManagementAlgorithm;
    enc: ContentEncryptionAlgorithm;
  },
): Promise<string>;
export async function encrypt(
  payload: string | Uint8Array<ArrayBuffer> | Record<string, unknown>,
  key: CryptoKey | JWK | string | Uint8Array<ArrayBuffer>,
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
  else if (alg?.startsWith("PBES2")) jweKeyManagementParams.p2s = randomBytes(16);
  if (p2c) jweKeyManagementParams.p2c = p2c;
  else if (alg?.startsWith("PBES2")) jweKeyManagementParams.p2c = 600_000;
  if (ecdh?.partyUInfo) jweKeyManagementParams.apu = ecdh.partyUInfo;
  if (ecdh?.partyVInfo) jweKeyManagementParams.apv = ecdh.partyVInfo;
  if (ecdh?.ephemeralKey) {
    const { epk, epkPrivateKey } = parseEphemeralKey(ecdh.ephemeralKey);
    jweKeyManagementParams.epk = epk;
    jweKeyManagementParams.epkPrivateKey = epkPrivateKey;
  }

  const wrappingKeyMaterial = await importKey(key, { alg, expect: "public" });

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

  const computedPayload: JWTClaims | undefined = computeJwtTimeClaims(
    payload,
    options.expiresIn,
    options.currentDate,
  );

  const plaintextBytes = getPlaintextBytes(computedPayload || payload);

  const protectedHeaderSerialized = JSON.stringify(protectedHeader);
  const protectedHeaderEncoded = base64UrlEncode(protectedHeaderSerialized);

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
  const encryptedKeyEncoded = jweEncryptedKey ? base64UrlEncode(jweEncryptedKey) : "";

  const jweParts: string[] = [
    protectedHeaderEncoded,
    encryptedKeyEncoded,
    base64UrlEncode(actualContentIV),
    base64UrlEncode(contentCiphertext),
    base64UrlEncode(contentAuthTag),
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
export async function decrypt<T extends JOSEPayload>(
  jwe: string,
  key:
    | CryptoKey
    | JWKSet
    | JWK_Private
    | JWK_Symmetric
    | string
    | Uint8Array<ArrayBuffer>
    | JWKLookupFunction,
  options?: JWEDecryptOptions,
): Promise<JWEDecryptResult<T>>;
export async function decrypt(
  jwe: string,
  key:
    | CryptoKey
    | JWKSet
    | JWK_Private
    | JWK_Symmetric
    | string
    | Uint8Array<ArrayBuffer>
    | JWKLookupFunction,
  options: JWEDecryptOptions & {
    forceUint8Array: true;
  },
): Promise<JWEDecryptResult<Uint8Array<ArrayBuffer>>>;
export async function decrypt<T extends string | Uint8Array<ArrayBuffer> | Record<string, unknown>>(
  jwe: string,
  key:
    | CryptoKey
    | JWKSet
    | JWK_Private
    | JWK_Symmetric
    | string
    | Uint8Array<ArrayBuffer>
    | JWKLookupFunction,
  options: JWEDecryptOptions = {},
): Promise<JWEDecryptResult<T>> {
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

  let protectedHeader: JWEHeaderParameters;
  try {
    const protectedHeaderJson = base64UrlDecode(protectedHeaderEncoded);
    protectedHeader = sanitizeObject<JWEHeaderParameters>(JSON.parse(protectedHeaderJson));
  } catch {
    throw new JWTError("Invalid JWE: Protected header could not be decoded.", "ERR_JWE_INVALID");
  }

  if (
    !protectedHeader ||
    typeof protectedHeader !== "object" ||
    !protectedHeader.alg ||
    !protectedHeader.enc
  ) {
    throw new JWTError(
      'Invalid JWE: Protected header must be an object with "alg" and "enc" properties.',
      "ERR_JWE_INVALID",
    );
  }

  const alg = protectedHeader.alg as KeyManagementAlgorithm;
  const enc = protectedHeader.enc as ContentEncryptionAlgorithm;

  if (options?.algorithms && !options.algorithms.includes(alg)) {
    throw new JWTError(`Key management algorithm not allowed: ${alg}`, "ERR_JWE_ALG_NOT_ALLOWED");
  }
  if (options?.encryptionAlgorithms && !options.encryptionAlgorithms.includes(enc)) {
    throw new JWTError(
      `Content encryption algorithm not allowed: ${enc}`,
      "ERR_JWE_ALG_NOT_ALLOWED",
    );
  }

  const rawKeyMaterial = typeof key === "function" ? await key(protectedHeader, jwe) : key;

  // Without an explicit allowlist, infer from the key shape — prevents
  // sender-controlled `alg` from dictating key management.
  if (!options?.algorithms) {
    // Fast-path: non-oct JWK with `alg` names the only allowed algorithm.
    // `oct` is excluded because its `alg` aliases to `dir` / A*GCMKW variants.
    if (
      isJWK(rawKeyMaterial) &&
      rawKeyMaterial.kty !== "oct" &&
      typeof rawKeyMaterial.alg === "string"
    ) {
      if (rawKeyMaterial.alg !== alg) {
        throw new JWTError(
          `Key management algorithm not allowed: ${alg}`,
          "ERR_JWE_ALG_NOT_ALLOWED",
        );
      }
    } else {
      const inferred = inferJWEAllowedAlgorithms(rawKeyMaterial);
      if (!inferred) {
        throw new JWTError(
          'Cannot infer allowed key management algorithms from this key; pass "options.algorithms" explicitly.',
          "ERR_JWE_ALG_NOT_ALLOWED",
        );
      }
      if (!inferred.includes(alg)) {
        throw new JWTError(
          `Key management algorithm not allowed: ${alg}`,
          "ERR_JWE_ALG_NOT_ALLOWED",
        );
      }
    }
  }

  const encryptedKeyBytes = base64UrlDecode(encryptedKeyEncoded, false);
  const contentIVBytes = base64UrlDecode(ivEncoded, false);
  const contentAuthTagBytes = base64UrlDecode(authTagEncoded, false);
  const ciphertextBytes = base64UrlDecode(ciphertextEncoded, false);

  const unwrapKeyOpts: UnwrapKeyOptions = {
    enc,
    format: enc.includes("GCM") ? "cryptokey" : "raw",
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
    const candidates = getJWKsFromSet(rawKeyMaterial, _buildJWESetFilter(protectedHeader));
    if (candidates.length === 0) {
      throw new JWTError(
        `No key found in JWK Set${protectedHeader.kid ? ` with kid "${protectedHeader.kid}"` : ""}.`,
        "ERR_JWK_KEY_NOT_FOUND",
      );
    }
    // `importKey` runs outside the catch: malformed candidates surface rather than being
    // silently skipped. Only unwrap/AEAD failures count as "try next".
    let decrypted = false;
    for (const candidate of candidates) {
      const unwrappingKey = await importKey(candidate as any, { alg, expect: "private" });
      try {
        const candidateCek = await unwrapKey(alg, encryptedKeyBytes, unwrappingKey, unwrapKeyOpts);
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
        if (err instanceof JWTError && err.code !== "ERR_JWE_DECRYPTION_FAILED") throw err;
      }
    }
    if (!decrypted) {
      throw new JWTError("JWE decryption failed.", "ERR_JWE_DECRYPTION_FAILED");
    }
  } else {
    const unwrappingKey = await importKey(rawKeyMaterial, { alg, expect: "private" });
    try {
      cek = await unwrapKey(alg, encryptedKeyBytes, unwrappingKey, unwrapKeyOpts);
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

  const payload = decodePayloadFromBytes<T>(plaintextBytes, options?.forceUint8Array) as T;

  if (protectedHeader.crit || options?.recognizedHeaders?.length) {
    validateCriticalHeadersJWE(protectedHeader, options?.recognizedHeaders);
  }

  // RFC 7519 JWT claim validation runs for any JSON-object payload; opt out via `validateClaims: false`.
  if (
    payload &&
    typeof payload === "object" &&
    !(payload instanceof Uint8Array) &&
    !options.forceUint8Array &&
    options.validateClaims !== false
  ) {
    validateJwtClaims(payload as JWTClaims, options);
  }

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

function parseEphemeralKey(ephemeralKey: Required<JWEEncryptOptions>["ecdh"]["ephemeralKey"]) {
  let epk: CryptoKey | JWK_EC_Public;
  let epkPrivateKey: CryptoKey | JWK_EC_Private;
  if (isCryptoKeyPair(ephemeralKey)) {
    epk = ephemeralKey.publicKey;
    epkPrivateKey = ephemeralKey.privateKey;
  } else if (
    typeof ephemeralKey === "object" &&
    ephemeralKey !== null &&
    "publicKey" in ephemeralKey &&
    "privateKey" in ephemeralKey
  ) {
    const candidate = ephemeralKey;
    if (!candidate.publicKey || !candidate.privateKey) {
      throw new JWTError(
        "ECDH-ES custom ephemeral key must include both publicKey and privateKey.",
        "ERR_JWK_INVALID",
      );
    }
    epk = candidate.publicKey;
    epkPrivateKey = candidate.privateKey;
  } else if (isCryptoKey(ephemeralKey)) {
    if (ephemeralKey.type !== "private") {
      throw new JWTError(
        "ECDH-ES custom ephemeral CryptoKey must include private key material.",
        "ERR_JWK_INVALID",
      );
    }
    epk = ephemeralKey;
    epkPrivateKey = ephemeralKey;
  } else if (isJWK(ephemeralKey)) {
    if (!("d" in ephemeralKey) || typeof ephemeralKey.d !== "string") {
      throw new JWTError(
        'ECDH-ES custom ephemeral JWK must include private parameter "d".',
        "ERR_JWK_INVALID",
      );
    }
    epk = ephemeralKey;
    epkPrivateKey = ephemeralKey;
  } else {
    throw new JWTError(
      "Unsupported ECDH-ES ephemeral key material provided in options.",
      "ERR_JWK_INVALID",
    );
  }

  return {
    epk,
    epkPrivateKey,
  };
}

function _buildJWESetFilter(header: JWEHeaderParameters): (k: JWK) => boolean {
  const { kid, alg } = header;
  return (k: JWK) => (!kid || k.kid === kid) && (!k.alg || k.alg === alg);
}

function _buildJWEHeader(
  alg: KeyManagementAlgorithm,
  enc: ContentEncryptionAlgorithm,
  key: CryptoKey | JWK | string | Uint8Array<ArrayBuffer>,
  userHeader: JWEEncryptOptions["protectedHeader"],
  keyManagementParams: JWEHeaderParameters | undefined,
  payload: unknown,
): JWEHeaderParameters {
  const safeHeader = sanitizeObject<JWEHeaderParameters | undefined>(
    userHeader as JWEHeaderParameters | undefined,
  );
  const header: JWEHeaderParameters = {
    ...(isJWK(key) && key.kid ? { kid: key.kid } : {}),
    ...safeHeader,
    ...keyManagementParams,
    alg,
    enc,
  };
  return applyTypCtyDefaults(header, payload);
}
