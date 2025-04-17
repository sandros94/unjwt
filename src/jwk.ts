import { subtle } from "uncrypto";
import type { JWK } from "./types";
import {
  base64UrlEncode,
  base64UrlDecode,
  textEncoder,
  randomBytes,
} from "./utils";

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
    const jwk = await subtle.exportKey("jwk", key);
    if (jwk.kty === "oct" && jwk.k) {
      return jwk as JWK;
    }
  } catch {
    // Fallback to manual if 'jwk' export is not available
  }

  // Manual construction using 'raw' export
  const rawKey = await subtle.exportKey("raw", key);
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
 * Imports a symmetric JWK (oct) to a CryptoKey.
 *
 * @param jwk The JWK object (must be kty: "oct" with "k" property).
 * @param algorithm The Web Crypto AlgorithmIdentifier to import the key for.
 * @param extractable Whether the imported key should be extractable.
 * @param keyUsages The allowed key usages.
 *
 * @returns Promise resolving to the imported CryptoKey.
 */
export async function importSymmetricKey(
  jwk: JWK,
  algorithm: AlgorithmIdentifier | HmacImportParams | AesKeyAlgorithm,
  extractable: boolean,
  keyUsages: KeyUsage[],
): Promise<CryptoKey> {
  if (jwk.kty !== "oct" || typeof jwk.k !== "string") {
    throw new Error("JWK must be of type 'oct' and contain the 'k' parameter");
  }
  const keyData = base64UrlDecode(jwk.k);
  return subtle.importKey("raw", keyData, algorithm, extractable, keyUsages);
}

/**
 * Imports a raw symmetric key (e.g., from a password or stored secret).
 *
 * @param secret The raw key material.
 * @param algorithm The Web Crypto AlgorithmIdentifier to import the key for.
 * @param extractable Whether the imported key should be extractable.
 * @param keyUsages The allowed key usages.
 *
 * @returns Promise resolving to the imported CryptoKey.
 */
export async function importRawSymmetricKey(
  secret: string | Uint8Array,
  algorithm: AlgorithmIdentifier | HmacImportParams | AesKeyAlgorithm,
  extractable: boolean,
  keyUsages: KeyUsage[],
): Promise<CryptoKey> {
  const keyData =
    typeof secret === "string" ? textEncoder.encode(secret) : secret;
  return subtle.importKey("raw", keyData, algorithm, extractable, keyUsages);
}
