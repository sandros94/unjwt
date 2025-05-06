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
  textDecoder,
  isJWK,
} from "./utils";

export * from "./types/jwe";

/**
 * Encrypts a plaintext to produce a JWE Compact Serialization string.
 *
 * @param plaintext The plaintext to encrypt. Can be a string, Uint8Array, or a JSON-serializable object.
 * @param key The key encryption key (KEK). Can be a CryptoKey, JWK, or for PBES2, a password string/Uint8Array.
 * @param options JWE encryption options, including `alg` (key management algorithm) and `enc` (content encryption algorithm).
 * @returns A Promise resolving to the JWE Compact Serialization string.
 */
export async function encrypt(
  plaintext: string | Uint8Array | Record<string, any>,
  key: JWK | string | Uint8Array,
  options?: JWEEncryptOptions,
): Promise<string>;
export async function encrypt(
  plaintext: string | Uint8Array | Record<string, any>,
  key: CryptoKey,
  options: JWEEncryptOptions & {
    alg: KeyManagementAlgorithm;
    enc: ContentEncryptionAlgorithm;
  },
): Promise<string>;
export async function encrypt(
  plaintext: string | Uint8Array | Record<string, any>,
  key: CryptoKey | JWK | string | Uint8Array,
  options: JWEEncryptOptions & {
    alg: KeyManagementAlgorithm;
    enc: ContentEncryptionAlgorithm;
  },
): Promise<string>;
export async function encrypt(
  plaintext: string | Uint8Array | Record<string, any>,
  key: CryptoKey | JWK | string | Uint8Array,
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
  if (!enc) {
    if (typeof key === "string" || key instanceof Uint8Array) {
      enc = "A128GCM";
    } else if (isJWK(key) && "enc" in key) {
      enc = key.enc as ContentEncryptionAlgorithm;
    }
  }

  if (!alg) {
    throw new TypeError(
      'JWE "alg" (Key Management Algorithm) must be provided in options or inferable from the key',
    );
  }
  if (!enc) {
    throw new TypeError(
      'JWE "enc" (Content Encryption Algorithm) must be provided in options or inferable from the key',
    );
  }

  const plaintextBytes = getPlaintextBytes(plaintext);

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

  const jweProtectedHeader: JWEHeaderParameters = {
    ...additionalProtectedHeader,
    ...keyManagementHeaderParams,
    alg,
    enc,
  };

  if (
    !jweProtectedHeader.typ &&
    typeof plaintext === "object" &&
    !(plaintext instanceof Uint8Array)
  ) {
    jweProtectedHeader.typ = "JWT";
  }

  const protectedHeaderSerialized = JSON.stringify(jweProtectedHeader);
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
export async function decrypt<T = JWTClaims | string>(
  jwe: string,
  key: CryptoKey | JWK | string | Uint8Array | JWEKeyLookupFunction,
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
    protectedHeader = JSON.parse(protectedHeaderJson);
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
    typeof key === "function" ? await key(protectedHeader) : key;
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
    returnAs: false, // Returning CEK as Uint8Array
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

  let plaintext: T;
  try {
    const isJsonOutput =
      protectedHeader.typ === "JWT" ||
      (protectedHeader.cty &&
        protectedHeader.cty.toLowerCase().includes("json"));

    if (isJsonOutput) {
      const decodedString = textDecoder.decode(plaintextBytes);
      // Attempt to parse only if it looks like JSON
      if (decodedString.startsWith("{") && decodedString.endsWith("}")) {
        try {
          plaintext = JSON.parse(decodedString) as T;
        } catch {
          // Malformed JSON, return as string
          plaintext = decodedString as T;
        }
      } else {
        plaintext = decodedString as T;
      }
    } else {
      plaintext = textDecoder.decode(plaintextBytes) as T;
    }
  } catch {
    // Should not happen if plaintextBytes is valid, but as a fallback
    plaintext = textDecoder.decode(plaintextBytes) as T;
  }

  if (options?.critical && protectedHeader.crit) {
    const understoodParams = new Set([
      ...(options.critical || []),
      // JWE specific standard headers:
      "alg",
      "enc",
      "typ",
      "cty",
      "kid",
      "jwk",
      "jku",
      "x5c",
      "x5t",
      "x5u",
      "iv",
      "tag",
      "p2s",
      "p2c",
      "epk",
      "apu",
      "apv",
    ]);

    for (const critParam of protectedHeader.crit) {
      // As per RFC 7516, Section 4.1.13:
      // The parameter must also be present in the protected header.
      if (!Object.prototype.hasOwnProperty.call(protectedHeader, critParam)) {
        throw new Error(
          `Critical header parameter "${critParam}" listed in "crit" but not present in the protected header.`,
        );
      }
      if (!understoodParams.has(critParam)) {
        throw new Error(
          `Critical header parameter not understood: ${critParam}`,
        );
      }
    }
  } else if (!options?.critical && protectedHeader.crit) {
    // If 'crit' is present, but the application didn't provide 'options.critical',
    // it means the application hasn't declared which critical headers it supports.
    throw new Error(
      `Unprocessed critical header parameters: ${protectedHeader.crit.join(", ")}`,
    );
  }

  return {
    plaintext,
    protectedHeader,
    cek: cekBytes,
    aad: aadBytes,
  };
}

function getPlaintextBytes(
  payload: string | Uint8Array | Record<string, any>,
): Uint8Array {
  if (payload instanceof Uint8Array) {
    return payload;
  }
  if (typeof payload === "string") {
    return textEncoder.encode(payload);
  }
  if (typeof payload === "object" && payload !== null) {
    return textEncoder.encode(JSON.stringify(payload));
  }
  throw new TypeError(
    "Plaintext must be a string, Uint8Array, or a JSON-serializable object.",
  );
}
