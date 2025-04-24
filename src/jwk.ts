import type { JWK } from "./types";
import { base64UrlEncode, textEncoder, randomBytes } from "./utils";

/**
 * Generates a symmetric JWK (oct).
 *
 * @param length Key length in bits (e.g., 128, 192, 256).
 * @param alg Optional algorithm identifier (e.g., "HS256", "A128KW").
 *
 * @returns Promise resolving to the generated JWK.
 */
export async function generateSymmetricKey(
  length: 128 | 192 | 256,
  alg?: string,
): Promise<JWK> {
  const keyBytes = randomBytes(length / 8);
  const jwk: JWK = {
    kty: "oct",
    k: base64UrlEncode(keyBytes),
    ext: true,
  };
  if (alg) {
    jwk.alg = alg;
  }
  return jwk;
}

/**
 * Exports a symmetric CryptoKey to JWK (oct) format.
 *
 * @param key The CryptoKey to export (must be symmetric and extractable).
 *
 * @returns Promise resolving to the JWK representation.
 */
export async function exportSymmetricKey(key: CryptoKey): Promise<JWK> {
  if (key.type !== "secret" || !key.extractable) {
    throw new Error(
      "Key must be a symmetric (secret) and extractable CryptoKey",
    );
  }

  // Try exporting as JWK first
  try {
    const jwk = await crypto.subtle.exportKey("jwk", key);
    if (jwk.kty === "oct" && jwk.k) {
      return jwk as JWK;
    }
  } catch {
    // Fallback to manual if 'jwk' export is not available
  }

  // Manual construction using 'raw' export
  const rawKey = await crypto.subtle.exportKey("raw", key);
  const jwk: JWK = {
    kty: "oct",
    k: base64UrlEncode(new Uint8Array(rawKey)),
    alg:
      (key.algorithm as any).name === "HMAC"
        ? `HS${(key.algorithm as any).hash.name.split("-")[1]}` // Infer HS alg
        : (key.algorithm as any).name, // Use algorithm name directly (e.g., AES-KW)
    key_ops: key.usages,
    ext: key.extractable,
  };
  return jwk;
}

/**
 * Imports a symmetric key from various formats (JWK, raw bytes, string) into a CryptoKey.
 *
 * @param key The key material (JWK object, Uint8Array, or string).
 * @param algorithm The Web Crypto AlgorithmIdentifier to import the key for (e.g., HmacImportParams, AesKeyAlgorithm).
 * @param extractable Whether the imported key should be extractable.
 * @param keyUsages The allowed key usages for the imported CryptoKey.
 *
 * @returns Promise resolving to the imported CryptoKey.
 * @throws Error if the key format is invalid or unsupported for symmetric import.
 */
export async function importKey(
  key: JWK | string | Uint8Array,
  algorithm: AlgorithmIdentifier | HmacImportParams | AesKeyAlgorithm,
  extractable: boolean,
  keyUsages: KeyUsage[],
): Promise<CryptoKey> {
  if (typeof key === "string") {
    // Raw string secret
    const keyData = textEncoder.encode(key);
    return crypto.subtle.importKey(
      "raw",
      keyData,
      algorithm,
      extractable,
      keyUsages,
    );
  } else if (key instanceof Uint8Array) {
    // Raw byte secret
    const keyData = key;
    return crypto.subtle.importKey(
      "raw",
      keyData,
      algorithm,
      extractable,
      keyUsages,
    );
  } else if (typeof key === "object" && key !== null && key.kty === "oct") {
    // Symmetric JWK
    if (typeof key.k !== "string") {
      throw new TypeError(
        "Symmetric JWK must contain the 'k' parameter as a string",
      );
    }

    // The subtle.importKey API handles the base64url decoding internally for "jwk" format.
    const keyData = key as JsonWebKey; // Cast to Web Crypto's expected JsonWebKey type

    // Ensure required JWK properties for import are present if needed by the algorithm
    // (though subtle.importKey often infers or ignores some like alg, key_ops, ext)
    // TODO: I might add more checks here depending on strictness we want to achieve.

    return crypto.subtle.importKey(
      "jwk",
      keyData,
      algorithm,
      extractable,
      keyUsages,
    );
  } else {
    throw new Error(
      "Invalid key format. Expected symmetric JWK (oct), Uint8Array, or string.",
    );
  }
}
