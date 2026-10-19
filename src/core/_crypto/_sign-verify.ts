import { JWTError } from "../error";
import type { JWK_HMAC, JWK_RSA_PSS, JWK_RSA_SIGN, JWSAlgorithm } from "../types";
import {
  ECDSA_CURVES,
  checkKeyUsage,
  hashBitsOf,
  isAlgorithm,
  jwsHashOf,
  namedCurveOf,
  shaBitsOf,
  unusableKey,
} from "./_key-algorithm";

const HASHED_SIGNATURE_ALGORITHMS: Readonly<
  Record<JWK_HMAC | JWK_RSA_SIGN | JWK_RSA_PSS, "HMAC" | "RSASSA-PKCS1-v1_5" | "RSA-PSS">
> = /* @__PURE__ */ Object.freeze({
  HS256: "HMAC",
  HS384: "HMAC",
  HS512: "HMAC",
  RS256: "RSASSA-PKCS1-v1_5",
  RS384: "RSASSA-PKCS1-v1_5",
  RS512: "RSASSA-PKCS1-v1_5",
  PS256: "RSA-PSS",
  PS384: "RSA-PSS",
  PS512: "RSA-PSS",
});

export async function sign(
  alg: JWSAlgorithm,
  key: CryptoKey,
  data: Uint8Array<ArrayBuffer>,
): Promise<Uint8Array<ArrayBuffer>> {
  checkSigCryptoKey(key, alg, "sign");
  const signature = await crypto.subtle.sign(subtleAlgorithm(alg, key.algorithm), key, data);
  return new Uint8Array(signature);
}

export async function verify(
  alg: JWSAlgorithm,
  key: CryptoKey,
  signature: Uint8Array<ArrayBuffer>,
  data: Uint8Array<ArrayBuffer>,
): Promise<boolean> {
  checkSigCryptoKey(key, alg, "verify");
  try {
    return await crypto.subtle.verify(subtleAlgorithm(alg, key.algorithm), key, signature, data);
  } catch {
    return false;
  }
}

export function checkSigCryptoKey(key: CryptoKey, alg: JWSAlgorithm, usage: KeyUsage): void {
  switch (alg) {
    case "HS256":
    case "HS384":
    case "HS512":
    case "RS256":
    case "RS384":
    case "RS512":
    case "PS256":
    case "PS384":
    case "PS512": {
      const name = HASHED_SIGNATURE_ALGORITHMS[alg];
      if (!isAlgorithm(key.algorithm, name)) throw unusableKey(name);
      const expected = shaBitsOf(jwsHashOf(alg));
      if (hashBitsOf(key.algorithm.hash) !== expected)
        throw unusableKey(`SHA-${expected}`, "algorithm.hash");
      break;
    }
    case "Ed25519":
    case "EdDSA": {
      if (!isAlgorithm(key.algorithm, "Ed25519")) throw unusableKey("Ed25519");
      break;
    }
    case "ES256":
    case "ES384":
    case "ES512": {
      if (!isAlgorithm(key.algorithm, "ECDSA")) throw unusableKey("ECDSA");
      const expected = ECDSA_CURVES[alg];
      const actual = key.algorithm.namedCurve;
      if (actual !== expected) throw unusableKey(expected, "algorithm.namedCurve");
      break;
    }
  }

  checkKeyUsage(key, usage);
}

export function subtleAlgorithm(
  alg: JWSAlgorithm,
  algorithm: KeyAlgorithm,
):
  | { hash: string; name: string; saltLength?: undefined; namedCurve?: undefined }
  | { hash: string; name: string; saltLength: number; namedCurve?: undefined }
  | { hash: string; name: string; namedCurve: string | undefined; saltLength?: undefined }
  | { name: string; hash?: undefined; saltLength?: undefined; namedCurve?: undefined } {
  switch (alg) {
    case "HS256":
    case "HS384":
    case "HS512": {
      return { hash: jwsHashOf(alg), name: "HMAC" };
    }
    case "PS256":
    case "PS384":
    case "PS512": {
      const hash = jwsHashOf(alg);
      return { hash, name: "RSA-PSS", saltLength: shaBitsOf(hash) >> 3 };
    }
    case "RS256":
    case "RS384":
    case "RS512": {
      return { hash: jwsHashOf(alg), name: "RSASSA-PKCS1-v1_5" };
    }
    case "ES256":
    case "ES384":
    case "ES512": {
      return { hash: jwsHashOf(alg), name: "ECDSA", namedCurve: namedCurveOf(algorithm) };
    }
    case "Ed25519":
    case "EdDSA": {
      return { name: "Ed25519" };
    }
    default: {
      return unsupportedSignatureAlgorithm(alg);
    }
  }
}

/** Reached only by a caller outside the type system; `never` keeps the switch above exhaustive. */
function unsupportedSignatureAlgorithm(alg: never): never {
  throw new JWTError(
    `alg ${String(alg)} is not supported either by JOSE or your javascript runtime`,
    "ERR_JWS_ALG_NOT_ALLOWED",
  );
}
