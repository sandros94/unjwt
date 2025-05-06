/* eslint-disable unicorn/filename-case */

/**
 * This is a fork of Jose library's utility functions.
 * @source https://github.com/panva/jose/tree/69b7960c67e05be55fa2ec31c74b987696c20c60/src/lib/jwt_to_key.ts
 * @license MIT https://github.com/panva/jose/blob/69b7960c67e05be55fa2ec31c74b987696c20c60/LICENSE.md
 */

import type { JWK, JWK_RSA_Private, JWK_EC_Public } from "../types";

function subtleMapping(jwk: JWK): {
  algorithm: RsaHashedImportParams | EcKeyAlgorithm | Algorithm;
  keyUsages: KeyUsage[];
} {
  let algorithm: RsaHashedImportParams | EcKeyAlgorithm | Algorithm;
  let keyUsages: KeyUsage[];

  switch (jwk.kty) {
    case "RSA": {
      switch (jwk.alg) {
        case "PS256":
        case "PS384":
        case "PS512": {
          algorithm = { name: "RSA-PSS", hash: `SHA-${jwk.alg.slice(-3)}` };
          keyUsages = (jwk as JWK_RSA_Private).d ? ["sign"] : ["verify"];
          break;
        }
        case "RS256":
        case "RS384":
        case "RS512": {
          algorithm = {
            name: "RSASSA-PKCS1-v1_5",
            hash: `SHA-${jwk.alg.slice(-3)}`,
          };
          keyUsages = (jwk as JWK_RSA_Private).d ? ["sign"] : ["verify"];
          break;
        }
        case "RSA-OAEP":
        case "RSA-OAEP-256":
        case "RSA-OAEP-384":
        case "RSA-OAEP-512": {
          algorithm = {
            name: "RSA-OAEP",
            hash: `SHA-${Number.parseInt(jwk.alg.slice(-3), 10) || 1}`,
          };
          keyUsages = (jwk as JWK_RSA_Private).d
            ? ["decrypt", "unwrapKey"]
            : ["encrypt", "wrapKey"];
          break;
        }
        default: {
          throw new Error(
            'Invalid or unsupported JWK "alg" (Algorithm) Parameter value',
          );
        }
      }
      break;
    }
    case "EC": {
      switch (jwk.alg) {
        case "ES256": {
          algorithm = { name: "ECDSA", namedCurve: "P-256" };
          keyUsages = (jwk as JWK_RSA_Private).d ? ["sign"] : ["verify"];
          break;
        }
        case "ES384": {
          algorithm = { name: "ECDSA", namedCurve: "P-384" };
          keyUsages = (jwk as JWK_RSA_Private).d ? ["sign"] : ["verify"];
          break;
        }
        case "ES512": {
          algorithm = { name: "ECDSA", namedCurve: "P-521" };
          keyUsages = (jwk as JWK_RSA_Private).d ? ["sign"] : ["verify"];
          break;
        }
        case "ECDH-ES":
        case "ECDH-ES+A128KW":
        case "ECDH-ES+A192KW":
        case "ECDH-ES+A256KW": {
          algorithm = { name: "ECDH", namedCurve: (jwk as JWK_EC_Public).crv! };
          keyUsages = (jwk as JWK_RSA_Private).d ? ["deriveBits"] : [];
          break;
        }
        default: {
          throw new Error(
            'Invalid or unsupported JWK "alg" (Algorithm) Parameter value',
          );
        }
      }
      break;
    }
    case "OKP": {
      switch (jwk.alg) {
        case "Ed25519": // Fall through
        case "EdDSA": {
          algorithm = { name: "Ed25519" };
          keyUsages = (jwk as JWK_RSA_Private).d ? ["sign"] : ["verify"];
          break;
        }
        case "ECDH-ES":
        case "ECDH-ES+A128KW":
        case "ECDH-ES+A192KW":
        case "ECDH-ES+A256KW": {
          algorithm = { name: (jwk as JWK_EC_Public).crv! };
          keyUsages = (jwk as JWK_RSA_Private).d ? ["deriveBits"] : [];
          break;
        }
        default: {
          throw new Error(
            'Invalid or unsupported JWK "alg" (Algorithm) Parameter value',
          );
        }
      }
      break;
    }
    default: {
      throw new Error(
        'Invalid or unsupported JWK "kty" (Key Type) Parameter value',
      );
    }
  }

  return { algorithm, keyUsages };
}

export async function jwkTokey(jwk: JWK): Promise<CryptoKey> {
  if (!jwk.alg) {
    throw new TypeError(
      '"alg" argument is required when "jwk.alg" is not present',
    );
  }

  const { algorithm, keyUsages } = subtleMapping(jwk);

  const keyData: JWK = { ...jwk };
  delete keyData.alg;
  delete keyData.use;

  return crypto.subtle.importKey(
    "jwk",
    keyData,
    algorithm,
    jwk.ext ?? ((jwk as JWK_RSA_Private).d ? false : true),
    (jwk.key_ops as KeyUsage[]) ?? keyUsages,
  );
}
