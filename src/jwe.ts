import type {
  JWK,
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
  JWEKeyLookupFunction,
  JWEKeyManagementHeaderParameters,
} from "./types/jwe";

import { importKey, unwrapKey } from "./jwk";
import {
  encrypt as joseEncrypt,
  decrypt as joseDecrypt,
  generateIV,
  encryptKey,
} from "./jose";
import {
  base64UrlEncode,
  base64UrlDecode,
  randomBytes,
  textEncoder,
  isJWK,
  applyTypCtyDefaults,
  computeJwtTimeClaims,
  decodePayloadFromBytes,
  getPlaintextBytes,
  validateCriticalHeadersJWE,
} from "./utils";
import { sanitizeObject } from "./utils";

export type * from "./types/jwe";
export type * from "./types/jwt";

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
    protectedHeader: additionalProtectedHeader,
    cek: providedCek,
    contentEncryptionIV: providedContentIV,
    keyManagementIV,
    p2s = randomBytes(16),
    p2c = 2048,
    ecdhPartyUInfo,
    ecdhPartyVInfo,
  } = options;
  let { alg, enc } = options;

  // Fallback logic for alg and enc
  if (!alg) {
    if (typeof key === "string" || key instanceof Uint8Array) {
      alg = "PBES2-HS256+A128KW";
    } else if (isJWK(key)) {
      alg = key.alg as KeyManagementAlgorithm;
    }
  }
  if (!alg) {
    throw new TypeError(
      'JWE "alg" (Key Management Algorithm) must be provided in options or inferable from the key',
    );
  }
  if (!enc) {
    enc =
      isJWK(key) && "enc" in key
        ? (key.enc as ContentEncryptionAlgorithm)
        : "A128GCM";
  }

  // Prepare parameters for encryptKey
  const jweKeyManagementParams: JWEKeyManagementHeaderParameters = {};
  if (keyManagementIV) jweKeyManagementParams.iv = keyManagementIV;
  if (p2s) jweKeyManagementParams.p2s = p2s;
  if (p2c) jweKeyManagementParams.p2c = p2c;
  if (ecdhPartyUInfo) jweKeyManagementParams.apu = ecdhPartyUInfo;
  if (ecdhPartyVInfo) jweKeyManagementParams.apv = ecdhPartyVInfo;
  if (additionalProtectedHeader?.epk instanceof CryptoKey) {
    jweKeyManagementParams.epk = additionalProtectedHeader.epk;
  }

  const wrappingKeyMaterial = await importKey(key, alg);

  const {
    cek: finalCek, // This is the CEK (CryptoKey | Uint8Array) to be used for content encryption
    encryptedKey: jweEncryptedKey, // This is the JWE Encrypted Key (Uint8Array | undefined)
    parameters: keyManagementHeaderParams, // JWE header params from key encryption (e.g., epk, p2s, iv, tag)
  } = await encryptKey(
    alg,
    enc,
    wrappingKeyMaterial,
    providedCek,
    jweKeyManagementParams,
  );

  const baseProtectedHeader = { ...additionalProtectedHeader };
  delete baseProtectedHeader.alg;
  delete baseProtectedHeader.enc;

  const jweProtectedHeader = sanitizeObject<JWEHeaderParameters>({
    ...baseProtectedHeader,
    ...keyManagementHeaderParams,
    alg,
    enc,
  });

  const protectedHeader = applyTypCtyDefaults(jweProtectedHeader, payload);

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
  } = await joseEncrypt(
    enc,
    plaintextBytes,
    finalCek,
    contentIVBytes,
    aadBytes,
  );

  if (!actualContentIV) {
    throw new Error("Content encryption IV was not generated or returned.");
  }
  if (!contentAuthTag) {
    throw new Error(
      "Content encryption auth tag was not generated or returned.",
    );
  }

  // For 'dir' or 'ECDH-ES' (direct key agreement), jweEncryptedKey will be undefined.
  // The JWE Encrypted Key part should be an empty string in these cases.
  const encryptedKeyEncoded = jweEncryptedKey
    ? base64UrlEncode(jweEncryptedKey)
    : "";

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
export async function decrypt<
  T extends JWTClaims | Uint8Array<ArrayBuffer> | string,
>(
  jwe: string,
  key:
    | CryptoKey
    | JWK
    | string
    | Uint8Array<ArrayBuffer>
    | JWEKeyLookupFunction,
  options?: JWEDecryptOptions,
): Promise<JWEDecryptResult<T>>;
export async function decrypt(
  jwe: string,
  key:
    | CryptoKey
    | JWK
    | string
    | Uint8Array<ArrayBuffer>
    | JWEKeyLookupFunction,
  options: JWEDecryptOptions & {
    forceUint8Array: true;
  },
): Promise<JWEDecryptResult<Uint8Array<ArrayBuffer>>>;
export async function decrypt<
  T extends JWTClaims | Uint8Array<ArrayBuffer> | string,
>(
  jwe: string,
  key:
    | CryptoKey
    | JWK
    | string
    | Uint8Array<ArrayBuffer>
    | JWEKeyLookupFunction,
  options?: JWEDecryptOptions,
): Promise<JWEDecryptResult<T>> {
  const parts = jwe.split(".");
  if (parts.length !== 5) {
    throw new Error(
      "Invalid JWE: Must contain five sections (RFC7516, section-3).",
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
    protectedHeader = sanitizeObject<JWEHeaderParameters>(
      JSON.parse(protectedHeaderJson),
    );
  } catch (error_) {
    throw new Error(
      `Invalid JWE: Protected header is not valid Base64URL or JSON (${error_ instanceof Error ? error_.message : error_})`,
    );
  }

  if (
    !protectedHeader ||
    typeof protectedHeader !== "object" ||
    !protectedHeader.alg ||
    !protectedHeader.enc
  ) {
    throw new Error(
      'Invalid JWE: Protected header must be an object with "alg" and "enc" properties.',
    );
  }

  const alg = protectedHeader.alg as KeyManagementAlgorithm;
  const enc = protectedHeader.enc as ContentEncryptionAlgorithm;

  if (options?.algorithms && !options.algorithms.includes(alg)) {
    throw new Error(`Key management algorithm not allowed: ${alg}`);
  }
  if (
    options?.encryptionAlgorithms &&
    !options.encryptionAlgorithms.includes(enc)
  ) {
    throw new Error(`Content encryption algorithm not allowed: ${enc}`);
  }

  const resolvedKeyMaterial =
    typeof key === "function" ? await key(protectedHeader, jwe) : key;
  const unwrappingKey = await importKey(resolvedKeyMaterial, alg);

  const encryptedKeyBytes = base64UrlDecode(encryptedKeyEncoded, false);
  const contentIVBytes = base64UrlDecode(ivEncoded, false);
  const contentAuthTagBytes = base64UrlDecode(authTagEncoded, false);
  const ciphertextBytes = base64UrlDecode(ciphertextEncoded, false);

  const unwrapKeyOpts = {
    iv: protectedHeader.iv,
    tag: protectedHeader.tag,
    p2s: protectedHeader.p2s,
    p2c: protectedHeader.p2c,
    epk: protectedHeader.epk,
    apu: protectedHeader.apu,
    apv: protectedHeader.apv,
    unwrappedKeyAlgorithm: options?.unwrappedKeyAlgorithm,
    keyUsage: options?.keyUsage,
    extractable: options?.extractable,
    returnAs: false, // Returning CEK as Uint8Array<ArrayBuffer>
  } as const satisfies UnwrapKeyOptions;

  const cekBytes = await unwrapKey(
    alg,
    encryptedKeyBytes,
    unwrappingKey,
    unwrapKeyOpts,
  );

  const aadBytes = textEncoder.encode(protectedHeaderEncoded);

  const plaintextBytes = await joseDecrypt(
    enc,
    cekBytes,
    ciphertextBytes,
    contentIVBytes,
    contentAuthTagBytes,
    aadBytes,
  );

  const payload = decodePayloadFromBytes<T>(
    plaintextBytes,
    protectedHeader,
    options?.forceUint8Array,
  ) as T;

  validateCriticalHeadersJWE(protectedHeader, [
    ...(options?.critical || []),
    ...(options?.requiredHeaders || []),
  ]);

  return {
    payload,
    protectedHeader,
    cek: cekBytes,
    aad: aadBytes,
  };
}
