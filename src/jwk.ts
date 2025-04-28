import type { JWK } from "./types";
import { base64UrlEncode, textEncoder, randomBytes } from "./utils";

/**
 * Generates a new cryptographic key as a JWK object.
 * Currently supports symmetric keys ('oct'). Future versions will support asymmetric keys.
 *
 * @param type The type of key to generate. Currently only 'oct' (symmetric) is supported.
 *             For 'oct': requires `length` option.
 *             Future types like 'RSA' or 'EC' will require different options.
 * @param options Generation options specific to the key type.
 * @param options.length For 'oct' keys: Key length in bits (e.g., 128, 192, 256, 512).
 * @param options.alg Optional JWA algorithm identifier (e.g., "HS256", "A128KW") to include in the JWK.
 *
 * @returns Promise resolving to the generated key as a JWK object.
 * @throws Error if the key type or options are invalid/unsupported.
 */
export async function generateKey(
  type: Readonly<"oct">,
  length: Readonly<128 | 192 | 256 | 512>,
  jwk?: Readonly<Omit<JWK, "kty" | "k">>,
): Promise<JWK>;
// TODO: Add overloads for asymmetric types ("RSA" | "EC")
export async function generateKey(
  type: Readonly<string>,
  length: Readonly<128 | 192 | 256 | 512>,
  options?: Readonly<Omit<JWK, "kty" | "k">>,
): Promise<JWK> {
  switch (type) {
    case "oct": {
      if (
        !length ||
        typeof length !== "number" ||
        ![128, 192, 256, 512].includes(length)
      ) {
        throw new Error(
          "Invalid options for 'oct' key generation. 'length' (128, 192, 256, or 512) is required.",
        );
      }
      const keyBytes = randomBytes(length / 8);
      const jwk: JWK = {
        ext: true, // Default extractable
        ...options, // TODO: do we want to allow this level of control?
        kty: "oct",
        k: base64UrlEncode(keyBytes),
      };
      return jwk;
    }
    // Add cases for 'RSA', 'EC'
    default: {
      throw new Error(`Unsupported key type for generation: ${type}`);
    }
  }
}

/**
 * Exports a CryptoKey to its JWK representation.
 * Supports symmetric ('oct') keys. Future versions will support asymmetric keys.
 *
 * @param key The CryptoKey to export. Must be extractable.
 *
 * @returns Promise resolving to the JWK representation.
 * @throws Error if the key is not extractable or its type is unsupported for export.
 */
export async function exportKey(key: Readonly<CryptoKey>): Promise<JWK> {
  if (!key.extractable) {
    throw new Error("Key must be extractable to export to JWK format.");
  }

  if (key.type === "secret") {
    try {
      // Prefer standard 'jwk' export if available
      const jwk = await crypto.subtle.exportKey("jwk", key);

      if (jwk.kty === "oct" && typeof jwk.k === "string") {
        const finalJwk: JWK = {
          ...jwk,
          kty: "oct",
          key_ops: jwk.key_ops || key.usages,
          ext: jwk.ext ?? key.extractable,
        };

        // Infer 'alg' if missing
        if (!finalJwk.alg && (key.algorithm as any).name === "HMAC") {
          finalJwk.alg = `HS${(key.algorithm as HmacKeyAlgorithm).hash.name.split("-")[1]}`;
        } else if (!finalJwk.alg) {
          finalJwk.alg = (key.algorithm as any).name; // Fallback to algorithm name
        }
        return finalJwk;
      }
    } catch {
      // Ignore error and fall through to manual 'raw' export if 'jwk' format failed
    }

    // Manual construction using 'raw' export (fallback)
    const rawKey = await crypto.subtle.exportKey("raw", key);
    const jwk: JWK = {
      kty: "oct",
      k: base64UrlEncode(new Uint8Array(rawKey)),
      // Infer JWA algorithm name
      alg:
        (key.algorithm as any).name === "HMAC"
          ? `HS${(key.algorithm as HmacKeyAlgorithm).hash.name.split("-")[1]}`
          : (key.algorithm as any).name, // Use algorithm name directly (e.g., AES-KW)
      key_ops: key.usages,
      ext: key.extractable,
    };
    return jwk;
  } else if (key.type === "public" || key.type === "private") {
    // TODO: Implement asymmetric key export (RSA, EC)
    // This will likely involve exporting as 'jwk' directly,
    // as 'raw'/'pkcs8'/'spki' don't map directly to all JWK fields.
    try {
      const jwk = await crypto.subtle.exportKey("jwk", key);
      // TODO: Validate the structure based on expected kty (RSA/EC)
      // and return the JWK object (potentially casting/adjusting fields).
      // For private keys, this will contain private parameters (d, p, q, etc.).
      // For public keys, it will contain only public parameters (n, e for RSA; x, y for EC).
      return jwk as JWK; // Placeholder cast
    } catch (error) {
      throw new Error(`Failed to export asymmetric key to JWK: ${error}`);
    }
  } else {
    throw new Error(`Unsupported CryptoKey type for export: ${key.type}`);
  }
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
