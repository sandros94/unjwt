/* eslint-disable unicorn/filename-case */

/**
 * This is a fork of Jose library's utility functions.
 * @source https://github.com/panva/jose/tree/69b7960c67e05be55fa2ec31c74b987696c20c60/src/lib/encrypt_key_management.ts
 * @license MIT https://github.com/panva/jose/blob/69b7960c67e05be55fa2ec31c74b987696c20c60/LICENSE.md
 */

import type {
  JWEKeyManagementHeaderParameters,
  JWEHeaderParameters,
  JWK,
  JWK_EC,
  JWK_EC_Public,
} from "../types";
import {
  base64UrlEncode,
  base64UrlDecode,
  isJWK,
  isAsymmetricJWK,
  assertCryptoKey,
  isCryptoKey,
} from "../utils";
import { bitLengthCEK, generateCEK } from "./cek-iv";
import { jwkTokey } from "./jwk_to_key";
import { keyToJWK } from "./key_to_jwk";
import { encryptRSAES } from "./rsaes";
import { encryptIV } from "./aesgcmkw";
import * as ecdhes from "./ecdhes";
import { wrap } from "./pbes2kw";
import { sanitizeObject } from "../utils";

const PUBLIC_EPK_FIELDS = new Set([
  "kty",
  "crv",
  "x",
  "y",
  "kid",
  "use",
  "key_ops",
  "alg",
  "x5c",
  "x5t",
  "x5t#S256",
  "x5u",
]);

function toPublicEpkJwk(jwk: JWK_EC): JWK_EC_Public {
  const filtered: Record<string, unknown> = {};
  for (const [key, value] of Object.entries(jwk)) {
    if (value !== undefined && PUBLIC_EPK_FIELDS.has(key)) {
      filtered[key] = value;
    }
  }

  const { kty, crv, x, y } = filtered as {
    kty?: unknown;
    crv?: unknown;
    x?: unknown;
    y?: unknown;
  };

  if (typeof kty !== "string") {
    throw new TypeError(
      'ECDH-ES ephemeral key JWK must include the "kty" parameter.',
    );
  }

  if (typeof crv !== "string") {
    throw new TypeError(
      'ECDH-ES ephemeral key JWK must include the "crv" parameter.',
    );
  }

  if (typeof x !== "string") {
    throw new TypeError(
      'ECDH-ES ephemeral key JWK must include the "x" coordinate.',
    );
  }

  if (kty === "EC" && typeof y !== "string") {
    throw new TypeError(
      'ECDH-ES EC ephemeral key JWK must include both "x" and "y" coordinates.',
    );
  }

  const publicJwk: Record<string, unknown> = {
    ...filtered,
    kty,
    crv,
    x,
  };

  if (typeof y === "string") {
    publicJwk.y = y;
  } else {
    delete publicJwk.y;
  }

  return sanitizeObject(publicJwk) as unknown as JWK_EC_Public;
}

async function ensurePrivateKey(
  alg: string,
  value: CryptoKey | JWK_EC,
): Promise<CryptoKey> {
  const normalized = await normalizeKey(value, alg);
  if (!(normalized instanceof CryptoKey)) {
    throw new TypeError(
      "ECDH-ES ephemeral private key must be a CryptoKey or convertible JWK.",
    );
  }
  if (normalized.type !== "private") {
    throw new TypeError(
      'ECDH-ES ephemeral private key must have type "private".',
    );
  }
  return normalized;
}

async function exportPublicJwkFrom(
  alg: string,
  value: CryptoKey | JWK_EC,
): Promise<JWK_EC_Public> {
  if (isCryptoKey(value)) {
    try {
      return toPublicEpkJwk(await keyToJWK(value));
    } catch (error_) {
      throw new TypeError(
        "ECDH-ES ephemeral CryptoKey must be extractable to export as JWK.",
        { cause: error_ instanceof Error ? error_ : undefined },
      );
    }
  }
  if (isJWK(value) && isAsymmetricJWK(value) && value.kty === "EC") {
    return toPublicEpkJwk(value);
  }
  const normalized = await normalizeKey(value, alg);
  if (!(normalized instanceof CryptoKey)) {
    throw new TypeError(
      "ECDH-ES ephemeral public key must be a CryptoKey or convertible JWK.",
    );
  }
  return exportPublicJwkFrom(alg, normalized);
}

export async function encryptKey(
  alg: string,
  enc: string,
  key: CryptoKey | Uint8Array<ArrayBuffer>,
  providedCek?: Uint8Array<ArrayBuffer>,
  providedParameters: JWEKeyManagementHeaderParameters = {},
): Promise<{
  cek: CryptoKey | Uint8Array<ArrayBuffer>;
  encryptedKey?: Uint8Array<ArrayBuffer>;
  parameters?: JWEHeaderParameters;
}> {
  let encryptedKey: Uint8Array<ArrayBuffer> | undefined;
  let parameters: JWEHeaderParameters = {};
  let cek: CryptoKey | Uint8Array<ArrayBuffer>;

  switch (alg) {
    case "dir": {
      // Direct Encryption
      cek = key;
      break;
    }
    case "ECDH-ES":
    case "ECDH-ES+A128KW":
    case "ECDH-ES+A192KW":
    case "ECDH-ES+A256KW": {
      assertCryptoKey(key);
      // Direct Key Agreement
      if (!ecdhes.allowed(key)) {
        throw new Error(
          "ECDH with the provided key is not allowed or not supported by your javascript runtime",
        );
      }
      const { apu, apv, epk: providedEpk, epkPrivateKey } = providedParameters;

      if (providedEpk && !epkPrivateKey) {
        throw new TypeError(
          "ECDH-ES custom ephemeral key material must include the matching private key.",
        );
      }

      let ephemeralPrivateKey: CryptoKey;
      let epkHeader: JWK_EC_Public;

      if (epkPrivateKey) {
        ephemeralPrivateKey = await ensurePrivateKey(alg, epkPrivateKey);
        const publicSource = providedEpk ?? epkPrivateKey;
        epkHeader = await exportPublicJwkFrom(alg, publicSource);
      } else {
        if (providedEpk) {
          throw new TypeError(
            "ECDH-ES custom ephemeral public key requires a matching private key.",
          );
        }
        const generated = await crypto.subtle.generateKey(
          key.algorithm as EcKeyAlgorithm,
          true,
          ["deriveBits"],
        );
        ephemeralPrivateKey = generated.privateKey;
        epkHeader = await exportPublicJwkFrom(alg, generated.publicKey);
      }

      const sharedSecret = await ecdhes.deriveECDHESKey(
        key,
        ephemeralPrivateKey,
        alg === "ECDH-ES" ? enc : alg,
        alg === "ECDH-ES"
          ? bitLengthCEK(enc)
          : Number.parseInt(alg.slice(-5, -2), 10),
        apu,
        apv,
      );
      parameters = { epk: epkHeader };
      if (apu) parameters.apu = base64UrlEncode(apu);
      if (apv) parameters.apv = base64UrlEncode(apv);

      if (alg === "ECDH-ES") {
        cek = sharedSecret;
        break;
      }

      // Key Agreement with Key Wrapping
      cek = providedCek || generateCEK(enc);
      const kwAlg = alg.slice(-6);
      encryptedKey = (await wrap(kwAlg, sharedSecret, cek)).encryptedKey;
      break;
    }
    case "RSA-OAEP":
    case "RSA-OAEP-256":
    case "RSA-OAEP-384":
    case "RSA-OAEP-512": {
      // Key Encryption (RSA)
      cek = providedCek || generateCEK(enc);
      assertCryptoKey(key);
      encryptedKey = await encryptRSAES(alg, key, cek);
      break;
    }
    case "PBES2-HS256+A128KW":
    case "PBES2-HS384+A192KW":
    case "PBES2-HS512+A256KW": {
      // Key Encryption (PBES2)
      cek = providedCek || generateCEK(enc);
      const { p2c, p2s } = providedParameters;
      ({ encryptedKey, ...parameters } = await wrap(alg, key, cek, p2c, p2s));
      break;
    }
    case "A128KW":
    case "A192KW":
    case "A256KW": {
      // Key Wrapping (AES KW)
      cek = providedCek || generateCEK(enc);
      encryptedKey = (await wrap(alg, key, cek)).encryptedKey;
      break;
    }
    case "A128GCMKW":
    case "A192GCMKW":
    case "A256GCMKW": {
      // Key Wrapping (AES GCM KW)
      cek = providedCek || generateCEK(enc);
      const { iv } = providedParameters;
      ({ encryptedKey, ...parameters } = await encryptIV(alg, key, cek, iv));
      break;
    }
    default: {
      throw new Error(
        'Invalid or unsupported "alg" (JWE Algorithm) header value',
      );
    }
  }

  return { cek, encryptedKey, parameters };
}

export async function normalizeKey(
  key: CryptoKey | JWK | Uint8Array<ArrayBuffer>,
  alg: string,
): Promise<CryptoKey | Uint8Array<ArrayBuffer>> {
  if (key instanceof Uint8Array) {
    return key;
  }

  if (isCryptoKey(key)) {
    return key;
  }

  if (isJWK(key)) {
    const safeJwk = sanitizeObject(key as Record<string, any>) as JWK;
    if ("k" in safeJwk && safeJwk.k) {
      return base64UrlDecode(safeJwk.k as string, false);
    }
    return jwkTokey({ ...safeJwk, alg });
  }

  throw new Error("unreachable");
}
