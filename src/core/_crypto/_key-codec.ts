import { base64UrlStringify } from "../utils/base64";

import type { JWK, JWK_RSA_Private, JWK_EC_Private, JWK_OKP_Private } from "../types";
import { isCryptoKey } from "../utils";
import { JWTError } from "../error";

export async function jwkTokey(jwk: JWK): Promise<CryptoKey> {
  if (!jwk.alg) {
    throw new TypeError('"alg" argument is required when "jwk.alg" is not present');
  }

  const { algorithm, keyUsages } = subtleMapping(jwk);

  return crypto.subtle.importKey(
    "jwk",
    jwk,
    algorithm,
    jwk.ext ?? ((jwk as JWK_RSA_Private).d ? false : true),
    (jwk.key_ops as KeyUsage[]) ?? keyUsages,
  );
}

export async function keyToJWK<T extends JWK>(
  key: Uint8Array<ArrayBuffer> | CryptoKey,
): Promise<T> {
  if (key instanceof Uint8Array) {
    return {
      kty: "oct",
      k: base64UrlStringify(key),
    } as T;
  }
  if (!isCryptoKey(key)) {
    throw new TypeError("Key must be one of type: CryptoKey or Uint8Array");
  }
  if (!key.extractable) {
    throw new TypeError("non-extractable CryptoKey cannot be exported as a JWK");
  }
  const jwk = await crypto.subtle.exportKey("jwk", key);

  return jwk as T;
}

// --- Internal helpers ---

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
          throw new Error('Invalid or unsupported JWK "alg" (Algorithm) Parameter value');
        }
      }
      break;
    }
    case "EC": {
      switch (jwk.alg) {
        case "ES256": {
          algorithm = { name: "ECDSA", namedCurve: "P-256" };
          keyUsages = (jwk as JWK_EC_Private).d ? ["sign"] : ["verify"];
          break;
        }
        case "ES384": {
          algorithm = { name: "ECDSA", namedCurve: "P-384" };
          keyUsages = (jwk as JWK_EC_Private).d ? ["sign"] : ["verify"];
          break;
        }
        case "ES512": {
          algorithm = { name: "ECDSA", namedCurve: "P-521" };
          keyUsages = (jwk as JWK_EC_Private).d ? ["sign"] : ["verify"];
          break;
        }
        case "ECDH-ES":
        case "ECDH-ES+A128KW":
        case "ECDH-ES+A192KW":
        case "ECDH-ES+A256KW": {
          algorithm = {
            name: "ECDH",
            namedCurve: requireCurve(jwk, ["P-256", "P-384", "P-521"]),
          };
          keyUsages = (jwk as JWK_EC_Private).d ? ["deriveBits"] : [];
          break;
        }
        default: {
          throw new Error('Invalid or unsupported JWK "alg" (Algorithm) Parameter value');
        }
      }
      break;
    }
    case "OKP": {
      switch (jwk.alg) {
        case "Ed25519":
        case "EdDSA": {
          algorithm = { name: requireCurve(jwk, ["Ed25519", "Ed448"]) };
          keyUsages = (jwk as JWK_OKP_Private).d ? ["sign"] : ["verify"];
          break;
        }
        case "ECDH-ES":
        case "ECDH-ES+A128KW":
        case "ECDH-ES+A192KW":
        case "ECDH-ES+A256KW": {
          algorithm = { name: requireCurve(jwk, ["X25519", "X448"]) };
          keyUsages = (jwk as JWK_OKP_Private).d ? ["deriveBits"] : [];
          break;
        }
        default: {
          throw new Error('Invalid or unsupported JWK "alg" (Algorithm) Parameter value');
        }
      }
      break;
    }
    default: {
      throw new Error('Invalid or unsupported JWK "kty" (Key Type) Parameter value');
    }
  }

  return { algorithm, keyUsages };
}

/**
 * Returns the JWK's `crv` once it is known to be one of `allowed`.
 *
 * The curve drives the WebCrypto algorithm name, so an unknown value must never
 * reach `crypto.subtle` — nor may a curve be assumed from `alg` alone, which
 * would import an `Ed448` key as `Ed25519`.
 */
function requireCurve(jwk: JWK, allowed: readonly string[]): string {
  const crv = (jwk as JWK_EC_Private | JWK_OKP_Private).crv as string | undefined;
  if (crv === undefined || !allowed.includes(crv)) {
    throw new JWTError(
      `Invalid or unsupported JWK "crv" (Curve) Parameter value: ${String(crv)}. Expected one of: ${allowed.join(", ")}.`,
      "ERR_JWK_INVALID",
    );
  }
  return crv;
}
