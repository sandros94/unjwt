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
import type { JWTClaims } from "./types/jwt";
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
  payload: JWTClaims,
  key: JWK | string | Uint8Array<ArrayBuffer>,
  options?: JWEEncryptOptions,
): Promise<string>;
export async function encrypt(
  payload: string | Uint8Array<ArrayBuffer> | Record<string, any>,
  key: JWK | string | Uint8Array<ArrayBuffer>,
  options?: JWEEncryptOptions,
): Promise<string>;
export async function encrypt(
  payload: string | Uint8Array<ArrayBuffer> | Record<string, any>,
  key: CryptoKey | JWK_Symmetric | Uint8Array<ArrayBuffer>,
  options: JWEEncryptOptions & { alg: "dir"; enc: ContentEncryptionAlgorithm },
): Promise<string>;
export async function encrypt(
  payload: JWTClaims,
  key: CryptoKey,
  options: JWEEncryptOptions & {
    alg: KeyManagementAlgorithm;
    enc: ContentEncryptionAlgorithm;
  },
): Promise<string>;
export async function encrypt(
  payload: string | Uint8Array<ArrayBuffer> | Record<string, any>,
  key: CryptoKey,
  options: JWEEncryptOptions & {
    alg: KeyManagementAlgorithm;
    enc: ContentEncryptionAlgorithm;
  },
): Promise<string>;
export async function encrypt(
  payload: string | Uint8Array<ArrayBuffer> | Record<string, any>,
  key: CryptoKey | JWK | string | Uint8Array<ArrayBuffer>,
  options: JWEEncryptOptions & {
    alg: KeyManagementAlgorithm;
    enc: ContentEncryptionAlgorithm;
  },
): Promise<string>;
export async function encrypt(
  payload: string | Uint8Array<ArrayBuffer> | Record<string, any>,
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

  // Fallback logic for alg and enc
  if (!alg) {
    if (typeof key === "string" || key instanceof Uint8Array) {
      alg = "PBES2-HS256+A128KW";
    } else if (isJWK(key)) {
      // Use AES-GCM keys for Key Wrapping
      alg =
        key.alg === "A128GCM" || key.alg === "A192GCM" || key.alg === "A256GCM"
          ? (`${key.alg}KW` as KeyManagementAlgorithm)
          : (key.alg as KeyManagementAlgorithm);
    }
  }
  if (!alg) {
    throw new TypeError(
      'JWE "alg" (Key Management Algorithm) must be provided in options or inferable from the key',
    );
  }
  if (!enc) {
    if (alg === "dir") {
      // Allow enc to be carried on the JWK itself as a non-standard hint.
      enc = isJWK(key) && "enc" in key ? (key.enc as ContentEncryptionAlgorithm) : undefined;
      if (!enc) throw new TypeError('JWE "enc" must be provided when alg is "dir"');
    } else {
      enc = isJWK(key) && "enc" in key ? (key.enc as ContentEncryptionAlgorithm) : "A128GCM";
    }
  }

  // Prepare parameters for encryptKey
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

  const wrappingKeyMaterial = await importKey(key, alg);

  const {
    cek: finalCek, // This is the CEK (CryptoKey | Uint8Array) to be used for content encryption
    encryptedKey: jweEncryptedKey, // This is the JWE Encrypted Key (Uint8Array | undefined)
    parameters: keyManagementHeaderParams, // JWE header params from key encryption (e.g., epk, p2s, iv, tag)
  } = await encryptKey(alg, enc, wrappingKeyMaterial, providedCek, jweKeyManagementParams);

  const protectedHeader = _buildJWEHeader(
    alg,
    enc,
    key,
    userHeader,
    keyManagementHeaderParams,
    payload,
  );

  // Calculate expiresIn for JWT
  const computedPayload: JWTClaims | undefined = computeJwtTimeClaims(
    payload,
    protectedHeader.typ,
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

  // For 'dir' or 'ECDH-ES' (direct key agreement), jweEncryptedKey will be undefined.
  // The JWE Encrypted Key part should be an empty string in these cases.
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
export async function decrypt<T extends JWTClaims | Uint8Array<ArrayBuffer> | string>(
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
export async function decrypt<T extends JWTClaims | Uint8Array<ArrayBuffer> | string>(
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
    let decrypted = false;
    for (const candidate of candidates) {
      try {
        const unwrappingKey = await importKey(candidate as any, alg);
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
      } catch {
        // this candidate did not work, try the next one
      }
    }
    if (!decrypted) {
      throw new JWTError("JWE decryption failed.", "ERR_JWE_DECRYPTION_FAILED");
    }
  } else {
    const unwrappingKey = await importKey(rawKeyMaterial, alg);
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

  const payload = decodePayloadFromBytes<T>(
    plaintextBytes,
    protectedHeader,
    options?.forceUint8Array,
  ) as T;

  if (protectedHeader.crit || options?.recognizedHeaders?.length) {
    validateCriticalHeadersJWE(protectedHeader, options?.recognizedHeaders);
  }

  if (
    payload &&
    typeof payload === "object" &&
    options.validateJWT !== false &&
    (options.validateJWT === true || protectedHeader.typ?.toLowerCase().includes("jwt")) &&
    !options.forceUint8Array &&
    !(payload instanceof Uint8Array)
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
      throw new TypeError(
        "ECDH-ES custom ephemeral key must include both publicKey and privateKey.",
      );
    }
    epk = candidate.publicKey;
    epkPrivateKey = candidate.privateKey;
  } else if (isCryptoKey(ephemeralKey)) {
    if (ephemeralKey.type !== "private") {
      throw new TypeError("ECDH-ES custom ephemeral CryptoKey must include private key material.");
    }
    epk = ephemeralKey;
    epkPrivateKey = ephemeralKey;
  } else if (isJWK(ephemeralKey)) {
    if (!("d" in ephemeralKey) || typeof ephemeralKey.d !== "string") {
      throw new TypeError('ECDH-ES custom ephemeral JWK must include private parameter "d".');
    }
    epk = ephemeralKey;
    epkPrivateKey = ephemeralKey;
  } else {
    throw new TypeError("Unsupported ECDH-ES ephemeral key material provided in options.");
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
