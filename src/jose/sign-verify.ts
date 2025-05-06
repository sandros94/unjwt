/**
 * This is a fork of Jose library's utility functions.
 * @source https://github.com/panva/jose/tree/69b7960c67e05be55fa2ec31c74b987696c20c60/src/lib/sign.ts
 * @source https://github.com/panva/jose/tree/69b7960c67e05be55fa2ec31c74b987696c20c60/src/lib/verify.ts
 * @license MIT https://github.com/panva/jose/blob/69b7960c67e05be55fa2ec31c74b987696c20c60/LICENSE.md
 */

export async function sign(
  alg: string,
  key: CryptoKey | Uint8Array,
  data: Uint8Array,
) {
  const cryptoKey = await getSignVerifyKey(alg, key, "sign");
  checkKeyLength(alg, cryptoKey);
  const signature = await crypto.subtle.sign(
    subtleAlgorithm(alg, cryptoKey.algorithm),
    cryptoKey,
    data,
  );
  return new Uint8Array(signature);
}

export async function verify(
  alg: string,
  key: CryptoKey | Uint8Array,
  signature: Uint8Array,
  data: Uint8Array,
) {
  const cryptoKey = await getSignVerifyKey(alg, key, "verify");
  checkKeyLength(alg, cryptoKey);
  const algorithm = subtleAlgorithm(alg, cryptoKey.algorithm);
  try {
    return await crypto.subtle.verify(algorithm, cryptoKey, signature, data);
  } catch {
    return false;
  }
}

export function checkKeyLength(alg: string, key: CryptoKey) {
  if (alg.startsWith("RS") || alg.startsWith("PS")) {
    const { modulusLength } = key.algorithm as RsaKeyAlgorithm;
    if (typeof modulusLength !== "number" || modulusLength < 2048) {
      throw new TypeError(
        `${alg} requires key modulusLength to be 2048 bits or larger`,
      );
    }
  }
}

import { checkSigCryptoKey } from "./crypto_key.js";

export async function getSignVerifyKey(
  alg: string,
  key: CryptoKey | Uint8Array,
  usage: KeyUsage,
) {
  if (key instanceof Uint8Array) {
    if (!alg.startsWith("HS")) {
      throw new TypeError(
        `Key must be ${key} of type: CryptoKey or JSON Web Key`,
      );
    }
    return crypto.subtle.importKey(
      "raw",
      key,
      { hash: `SHA-${alg.slice(-3)}`, name: "HMAC" },
      false,
      [usage],
    );
  }

  checkSigCryptoKey(key, alg, usage);
  return key;
}

export function subtleAlgorithm(
  alg: string,
  algorithm: KeyAlgorithm | EcKeyAlgorithm,
) {
  const hash = `SHA-${alg.slice(-3)}`;
  switch (alg) {
    case "HS256":
    case "HS384":
    case "HS512": {
      return { hash, name: "HMAC" };
    }
    case "PS256":
    case "PS384":
    case "PS512": {
      return {
        hash,
        name: "RSA-PSS",
        saltLength: Number.parseInt(alg.slice(-3), 10) >> 3,
      };
    }
    case "RS256":
    case "RS384":
    case "RS512": {
      return { hash, name: "RSASSA-PKCS1-v1_5" };
    }
    case "ES256":
    case "ES384":
    case "ES512": {
      return {
        hash,
        name: "ECDSA",
        namedCurve: (algorithm as EcKeyAlgorithm).namedCurve,
      };
    }
    case "Ed25519": // Fall through
    case "EdDSA": {
      return { name: "Ed25519" };
    }
    default: {
      throw new Error(
        `alg ${alg} is not supported either by JOSE or your javascript runtime`,
      );
    }
  }
}
