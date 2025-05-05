import type {
  JWEHeaderParameters,
  JWEOptions,
  JWK,
  JoseAlgorithm,
  KeyWrappingAlgorithm,
  ContentEncryptionAlgorithm,
  AesGcmAlgorithm,
} from "./types";
import {
  base64UrlEncode,
  base64UrlDecode,
  textEncoder,
  textDecoder,
  randomBytes,
  concatUint8Arrays,
  isJWK,
} from "./utils";
import { importKey, generateKey } from "./jwk";
import {
  JWE_KEY_WRAPPING,
  JWE_CONTENT_ENCRYPTION_ALGORITHMS,
} from "./utils/defaults";

export * from "./types/defaults";
export * from "./types/jwe";

/**
 * Encrypts a plaintext payload and produces a JWE Compact Serialization string.
 * Currently supports AES-GCM for content encryption ('enc') and
 * AES-KW or RSA-OAEP for key wrapping ('alg'). PBES2 is experimental.
 *
 * @param plaintext The plaintext to encrypt (string, ArrayBuffer, or Uint8Array).
 * @param key The encryption key (CryptoKey or JWK) used for wrapping the CEK.
 * @param options JWE options including protected header parameters ('alg', 'enc').
 * @returns A Promise resolving to the JWE Compact Serialization string.
 * @throws Error if algorithms are missing/unsupported, key is invalid, or encryption fails.
 */
export async function encrypt(
  plaintext: string | ArrayBuffer | Uint8Array,
  key: CryptoKey | JWK,
  options: JWEOptions & {
    protectedHeader: JWEHeaderParameters & { alg: string; enc: string };
  },
): Promise<string> {
  const { protectedHeader } = options;

  if (!protectedHeader.alg || !(protectedHeader.alg in JWE_KEY_WRAPPING)) {
    throw new Error(
      `Algorithm ('alg') must be specified in protectedHeader and must be a supported JWE key wrapping algorithm. Got: ${protectedHeader.alg}`,
    );
  }
  if (
    !protectedHeader.enc ||
    !(protectedHeader.enc in JWE_CONTENT_ENCRYPTION_ALGORITHMS)
  ) {
    throw new Error(
      `Encryption algorithm ('enc') must be specified in protectedHeader and must be a supported JWE content encryption algorithm. Got: ${protectedHeader.enc}`,
    );
  }

  const alg = protectedHeader.alg as KeyWrappingAlgorithm;
  const enc = protectedHeader.enc as ContentEncryptionAlgorithm; // Assume GCM for now

  // 1. Generate CEK and IV
  const { cek, iv } = await _generateCekAndIv(enc);

  // 2. Encrypt (wrap) the CEK
  const encryptedCek = await _wrapCek(cek, key, alg, protectedHeader);

  // 3. Encode Protected Header
  const encodedProtectedHeader = base64UrlEncode(
    JSON.stringify(protectedHeader),
  );
  const aad = textEncoder.encode(encodedProtectedHeader);

  // 4. Encrypt Plaintext
  const plaintextBytes =
    typeof plaintext === "string"
      ? textEncoder.encode(plaintext)
      : plaintext instanceof Uint8Array
        ? plaintext
        : new Uint8Array(plaintext); // Assume ArrayBuffer

  const { ciphertext, tag } = await _encryptContent(
    plaintextBytes,
    cek,
    iv,
    enc as AesGcmAlgorithm, // Cast as only GCM supported atm
    aad,
  );

  // 5. Assemble JWE
  return `${encodedProtectedHeader}.${base64UrlEncode(encryptedCek)}.${base64UrlEncode(iv)}.${base64UrlEncode(ciphertext)}.${base64UrlEncode(tag)}`;
}

/**
 * Decrypts a JWE Compact Serialization string.
 * Currently supports AES-GCM for content encryption ('enc') and
 * AES-KW or RSA-OAEP for key wrapping ('alg'). PBES2 is experimental.
 *
 * @param jwe The JWE Compact Serialization string.
 * @param key The decryption key (CryptoKey or JWK) or a function to retrieve the key.
 * @param options Optional parameters, including whether to return the payload as a string.
 * @returns A Promise resolving to an object containing the decrypted plaintext and the protected header.
 * @throws Error if JWE format is invalid, algorithms are unsupported, key is invalid, or decryption fails.
 */
export async function decrypt(
  jwe: string,
  key:
    | CryptoKey
    | JWK
    | ((header: JWEHeaderParameters) => Promise<CryptoKey | JWK>),
): Promise<{ plaintext: string; protectedHeader: JWEHeaderParameters }>;
export async function decrypt(
  jwe: string,
  key:
    | CryptoKey
    | JWK
    | ((header: JWEHeaderParameters) => Promise<CryptoKey | JWK>),
  options?: { toString?: true | undefined },
): Promise<{ plaintext: string; protectedHeader: JWEHeaderParameters }>;
export async function decrypt(
  jwe: string,
  key:
    | CryptoKey
    | JWK
    | ((header: JWEHeaderParameters) => Promise<CryptoKey | JWK>),
  options: { toString: false },
): Promise<{ plaintext: Uint8Array; protectedHeader: JWEHeaderParameters }>;
export async function decrypt<ToString extends boolean | undefined>(
  jwe: string,
  key:
    | CryptoKey
    | JWK
    | ((header: JWEHeaderParameters) => Promise<CryptoKey | JWK>),
  options?: { toString?: ToString },
): Promise<{
  plaintext: ToString extends false ? Uint8Array : string;
  protectedHeader: JWEHeaderParameters;
}>;
export async function decrypt(
  jwe: string,
  key:
    | CryptoKey
    | JWK
    | ((header: JWEHeaderParameters) => Promise<CryptoKey | JWK>),
  options?: { toString?: boolean | undefined },
): Promise<{
  plaintext: Uint8Array | string;
  protectedHeader: JWEHeaderParameters;
}> {
  // 1. Parse JWE
  const parts = jwe.split(".");
  if (parts.length !== 5) {
    throw new Error(
      "Invalid JWE format: Must contain five parts separated by dots.",
    );
  }
  const [
    encodedProtectedHeader,
    encodedEncryptedKey,
    encodedIv,
    encodedCiphertext,
    encodedTag,
  ] = parts;

  // 2. Decode Header
  let protectedHeader: JWEHeaderParameters;
  try {
    protectedHeader = JSON.parse(base64UrlDecode(encodedProtectedHeader));
  } catch (error_) {
    throw new Error(
      "Invalid JWE: Failed to decode or parse protected header.",
      {
        cause: error_,
      },
    );
  }

  // 3. Validate Algorithms
  if (!protectedHeader.alg || !(protectedHeader.alg in JWE_KEY_WRAPPING)) {
    throw new Error(
      `Unsupported or missing key wrapping algorithm in JWE header: ${protectedHeader.alg}`,
    );
  }
  if (
    !protectedHeader.enc ||
    !(protectedHeader.enc in JWE_CONTENT_ENCRYPTION_ALGORITHMS)
  ) {
    throw new Error(
      `Unsupported or missing content encryption algorithm in JWE header: ${protectedHeader.enc}`,
    );
  }
  // Basic check for GCM support (as it's the only one implemented atm)
  if (
    !JWE_CONTENT_ENCRYPTION_ALGORITHMS[
      protectedHeader.enc as ContentEncryptionAlgorithm
    ]?.type?.startsWith("gcm")
  ) {
    throw new Error(
      `Unsupported content encryption type for '${protectedHeader.enc}'. Only GCM is currently supported.`,
    );
  }

  const alg = protectedHeader.alg as KeyWrappingAlgorithm;
  const enc = protectedHeader.enc as ContentEncryptionAlgorithm; // Assume GCM

  // 4. Retrieve Key
  const retrievedKey: CryptoKey | JWK =
    typeof key === "function" ? await key(protectedHeader) : key;

  // 5. Decode JWE Parts
  const encryptedCek = base64UrlDecode(encodedEncryptedKey, false);
  const iv = base64UrlDecode(encodedIv, false);
  const ciphertext = base64UrlDecode(encodedCiphertext, false);
  const tag = base64UrlDecode(encodedTag, false);
  const aad = textEncoder.encode(encodedProtectedHeader);

  // 6. Decrypt (unwrap) CEK
  const cek = await _unwrapCek(
    encryptedCek,
    retrievedKey,
    alg,
    enc,
    protectedHeader,
  );

  // 7. Decrypt Ciphertext
  const plaintextBytes = await _decryptContent(
    ciphertext,
    cek,
    iv,
    tag,
    enc as AesGcmAlgorithm, // Cast as only GCM supported
    aad,
  );

  // 8. Decode Plaintext
  const plaintext =
    options?.toString === false
      ? plaintextBytes
      : textDecoder.decode(plaintextBytes);

  return { plaintext, protectedHeader };
}

/*
 * --- Internal Helper Functions ---
 */

/** Generates CEK and IV for a given content encryption algorithm. */
async function _generateCekAndIv(enc: ContentEncryptionAlgorithm): Promise<{
  cek: CryptoKey;
  iv: Uint8Array;
}> {
  const encDetails = JWE_CONTENT_ENCRYPTION_ALGORITHMS[enc];
  if (!encDetails) {
    throw new Error(`Unsupported content encryption algorithm: ${enc}`);
  }
  if (encDetails.type !== "gcm") {
    throw new Error(
      `Unsupported content encryption type: ${encDetails.type}. Only GCM is currently supported.`,
    );
  }

  const cek = await generateKey(enc as AesGcmAlgorithm, {
    extractable: true, // CEK needs to be extractable for wrapping
    keyUsage: ["encrypt", "decrypt"],
  });
  const iv = randomBytes(encDetails.ivLength);
  return { cek, iv };
}

/** Wraps the Content Encryption Key (CEK). */
async function _wrapCek(
  cek: CryptoKey,
  key: CryptoKey | JWK,
  alg: KeyWrappingAlgorithm,
  protectedHeader: JWEHeaderParameters, // Useful for algs like PBES2
): Promise<Uint8Array> {
  const wrappingKey = await (async () => {
    if (isJWK(key)) {
      // Ensure JWK alg matches header alg if both exist
      if (key.alg && alg && key.alg !== alg) {
        throw new Error(
          `JWE header algorithm '${alg}' does not match JWK algorithm '${key.alg}'.`,
        );
      }
      return importKey(key, {
        alg: alg as JoseAlgorithm,
        keyUsages: ["wrapKey"],
      });
    } else if (key instanceof CryptoKey) {
      // TODO: Add checks to ensure the CryptoKey's algorithm is compatible with the header's alg

      // Ensure usages include 'wrapKey'
      if (!key.usages.includes("wrapKey")) {
        throw new Error(
          `Provided CryptoKey for wrapping does not have 'wrapKey' usage.`,
        );
      }
      return key;
    } else {
      throw new TypeError(
        "Invalid key type for wrapping. Key must be a CryptoKey or JWK.",
      );
    }
  })();

  const algDetails = JWE_KEY_WRAPPING[alg];
  if (!algDetails) {
    throw new Error(`Unsupported key wrapping algorithm: ${alg}`);
  }

  let wrapAlgorithm: {
    name: string;
    hash?: string; // Optional, for algorithms like RSA-OAEP
    length?: number; // Optional, for AES-KW
  };

  if (alg.startsWith("RSA-OAEP")) {
    wrapAlgorithm = {
      name: algDetails.name, // "RSA-OAEP"
      hash: (algDetails as any).hash, // hash is present for RSA
    };
  } else if (alg.startsWith("A") && alg.endsWith("KW")) {
    wrapAlgorithm = { name: "AES-KW" };
  } else if (alg.startsWith("PBES2")) {
    // TODO: PBES2 requires deriving the key first, which is more complex
    // For now, assume the provided key is the *result* of PBES2 derivation + AES-KW import
    if (!protectedHeader.p2s || !protectedHeader.p2c) {
      throw new Error(
        `PBES2 algorithms require 'p2s' (salt) and 'p2c' (count) in protected header.`,
      );
    }
    // Assuming the user provided a key derived externally and imported as AES-KW.
    wrapAlgorithm = { name: "AES-KW" };
    console.warn(
      "PBES2 wrapping assumes the provided key is already derived and imported as AES-KW.",
    );
  } else {
    throw new Error(`Unsupported key wrapping algorithm type for ${alg}`);
  }

  const encryptedCek = await crypto.subtle.wrapKey(
    "jwk",
    cek,
    wrappingKey,
    wrapAlgorithm,
  );

  return new Uint8Array(encryptedCek);
}

/** Encrypts the plaintext using AES-GCM. */
async function _encryptContent(
  plaintext: Uint8Array,
  cek: CryptoKey,
  iv: Uint8Array,
  enc: AesGcmAlgorithm, // Only GCM supported for now
  aad: Uint8Array,
): Promise<{ ciphertext: Uint8Array; tag: Uint8Array }> {
  const encDetails = JWE_CONTENT_ENCRYPTION_ALGORITHMS[enc];
  if (encDetails.type !== "gcm") {
    throw new Error("Only AES-GCM encryption is currently supported.");
  }

  const algorithm: AesGcmParams = {
    name: "AES-GCM",
    iv: iv,
    additionalData: aad,
    tagLength: encDetails.tagLength * 8, // tagLength in bits
  };

  const encryptedData = await crypto.subtle.encrypt(algorithm, cek, plaintext);

  // GCM output includes ciphertext and tag concatenated
  const ciphertext = new Uint8Array(
    encryptedData,
    0,
    encryptedData.byteLength - encDetails.tagLength,
  );
  const tag = new Uint8Array(
    encryptedData,
    encryptedData.byteLength - encDetails.tagLength,
  );

  return { ciphertext, tag };
}

/** Unwraps the Content Encryption Key (CEK). */
async function _unwrapCek(
  encryptedCek: Uint8Array,
  key: CryptoKey | JWK,
  alg: KeyWrappingAlgorithm,
  enc: ContentEncryptionAlgorithm, // Needed to determine expected CEK properties
  protectedHeader: JWEHeaderParameters, // Useful for algs like PBES2
): Promise<CryptoKey> {
  const unwrappingKey = await (async () => {
    if (isJWK(key)) {
      // Ensure JWK alg matches header alg if both exist
      if (key.alg && alg && key.alg !== alg) {
        throw new Error(
          `JWE header algorithm '${alg}' does not match JWK algorithm '${key.alg}'.`,
        );
      }
      return importKey(key, {
        alg: alg as JoseAlgorithm,
        keyUsages: ["unwrapKey"],
      });
    } else if (key instanceof CryptoKey) {
      // TODO: Add checks to ensure the CryptoKey's algorithm is compatible with the header's alg

      // Ensure usages include 'unwrapKey'
      if (!key.usages.includes("unwrapKey")) {
        throw new Error(
          `Provided CryptoKey for unwrapping does not have 'unwrapKey' usage.`,
        );
      }
      return key;
    } else {
      throw new TypeError(
        "Invalid key type for unwrapping. Key must be a CryptoKey or JWK.",
      );
    }
  })();

  const algDetails = JWE_KEY_WRAPPING[alg];
  if (!algDetails) {
    throw new Error(`Unsupported key wrapping algorithm: ${alg}`);
  }
  const encDetails = JWE_CONTENT_ENCRYPTION_ALGORITHMS[enc];
  if (!encDetails) {
    throw new Error(`Unsupported content encryption algorithm: ${enc}`);
  }
  if (encDetails.type !== "gcm") {
    throw new Error(
      `Unsupported content encryption type: ${encDetails.type}. Only GCM is currently supported.`,
    );
  }

  let unwrapAlgorithm: {
    name: string;
    hash?: string; // Optional, for algorithms like RSA-OAEP
    length?: number; // Optional, for AES-KW
  };
  let unwrappedKeyAlgorithm: string | AesKeyAlgorithm; // Algorithm the *unwrapped* key should have

  if (alg.startsWith("RSA-OAEP")) {
    unwrapAlgorithm = {
      name: algDetails.name, // "RSA-OAEP"
      hash: (algDetails as any).hash, // hash is present for RSA
    };
    unwrappedKeyAlgorithm = "AES-GCM"; // Expecting an AES-GCM CEK
  } else if (alg.startsWith("A") && alg.endsWith("KW")) {
    unwrapAlgorithm = { name: "AES-KW" };
    unwrappedKeyAlgorithm = "AES-GCM"; // Expecting an AES-GCM CEK
  } else if (alg.startsWith("PBES2")) {
    if (!protectedHeader.p2s || !protectedHeader.p2c) {
      throw new Error(
        `PBES2 algorithms require 'p2s' (salt) and 'p2c' (count) in protected header.`,
      );
    }
    // TODO: This part is tricky. The 'unwrappingKey' should ideally be derived here.
    // Assuming the user provided a key derived externally and imported as AES-KW.
    unwrapAlgorithm = { name: "AES-KW" };
    unwrappedKeyAlgorithm = "AES-GCM"; // Expecting an AES-GCM CEK
    console.warn(
      "PBES2 unwrapping assumes the provided key is already derived and imported as AES-KW.",
    );
  } else {
    throw new Error(`Unsupported key wrapping algorithm type for ${alg}`);
  }

  const cek = await crypto.subtle.unwrapKey(
    "jwk",
    encryptedCek,
    unwrappingKey,
    unwrapAlgorithm,
    unwrappedKeyAlgorithm, // Specify the algorithm the unwrapped key is for
    true,
    ["encrypt", "decrypt"],
  );

  return cek;
}

/** Decrypts the ciphertext using AES-GCM. */
async function _decryptContent(
  ciphertext: Uint8Array,
  cek: CryptoKey,
  iv: Uint8Array,
  tag: Uint8Array,
  enc: AesGcmAlgorithm, // Only GCM supported for now
  aad: Uint8Array,
): Promise<Uint8Array> {
  const encDetails = JWE_CONTENT_ENCRYPTION_ALGORITHMS[enc];
  if (encDetails.type !== "gcm") {
    throw new Error("Only AES-GCM decryption is currently supported.");
  }

  const algorithm: AesGcmParams = {
    name: "AES-GCM",
    iv: iv,
    additionalData: aad,
    tagLength: encDetails.tagLength * 8, // tagLength in bits
  };

  // Concatenate ciphertext and tag for input to SubtleCrypto.decrypt
  const encryptedData = concatUint8Arrays(ciphertext, tag);

  try {
    const decryptedData = await crypto.subtle.decrypt(
      algorithm,
      cek,
      encryptedData,
    );
    return new Uint8Array(decryptedData);
  } catch (error_) {
    throw new Error(
      "JWE decryption failed: Authentication tag mismatch or other error.",
      { cause: error_ },
    );
  }
}
