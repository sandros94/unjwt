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
} from "../types";
import {
  base64UrlEncode,
  base64UrlDecode,
  isJWK,
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
  let parameters: JWEHeaderParameters & { epk?: JWK } = {};
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
      const { apu, apv } = providedParameters;
      const ephemeralKey: CryptoKey = providedParameters.epk
        ? ((await normalizeKey(providedParameters.epk, alg)) as CryptoKey)
        : (
            await crypto.subtle.generateKey(
              key.algorithm as EcKeyAlgorithm,
              true,
              ["deriveBits"],
            )
          ).privateKey;
      const { x, y, crv, kty } = (await keyToJWK(ephemeralKey!)) as JWK_EC;
      const sharedSecret = await ecdhes.deriveECDHESKey(
        key,
        ephemeralKey,
        alg === "ECDH-ES" ? enc : alg,
        alg === "ECDH-ES"
          ? bitLengthCEK(enc)
          : Number.parseInt(alg.slice(-5, -2), 10),
        apu,
        apv,
      );
      parameters = { epk: { x, y, crv, kty } };
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
