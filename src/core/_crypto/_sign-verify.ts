import { JWTError } from "../error";
import {
  ECDSA_CURVES,
  checkKeyUsage,
  hashBitsOf,
  isAlgorithm,
  jwsHashOf,
  namedCurveOf,
  unusableKey,
} from "./_key-algorithm";

const HASHED_SIGNATURE_ALGORITHMS: Record<string, "HMAC" | "RSASSA-PKCS1-v1_5" | "RSA-PSS"> = {
  HS: "HMAC",
  RS: "RSASSA-PKCS1-v1_5",
  PS: "RSA-PSS",
};

export async function sign(
  alg: string,
  key: CryptoKey,
  data: Uint8Array<ArrayBuffer>,
): Promise<Uint8Array<ArrayBuffer>> {
  checkSigCryptoKey(key, alg, "sign");
  const signature = await crypto.subtle.sign(subtleAlgorithm(alg, key.algorithm), key, data);
  return new Uint8Array(signature);
}

export async function verify(
  alg: string,
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

export function checkSigCryptoKey(key: CryptoKey, alg: string, usage: KeyUsage): void {
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
      const name = HASHED_SIGNATURE_ALGORITHMS[alg.slice(0, 2)];
      if (!isAlgorithm(key.algorithm, name)) throw unusableKey(name);
      const expected = Number.parseInt(alg.slice(2), 10);
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
    default: {
      throw new JWTError("CryptoKey does not support this operation", "ERR_JWK_INVALID");
    }
  }

  checkKeyUsage(key, usage);
}

export function subtleAlgorithm(
  alg: string,
  algorithm: KeyAlgorithm,
):
  | { hash: string; name: string; saltLength?: undefined; namedCurve?: undefined }
  | { hash: string; name: string; saltLength: number; namedCurve?: undefined }
  | { hash: string; name: string; namedCurve: string | undefined; saltLength?: undefined }
  | { name: string; hash?: undefined; saltLength?: undefined; namedCurve?: undefined } {
  const hash = jwsHashOf(alg);
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
        namedCurve: namedCurveOf(algorithm),
      };
    }
    case "Ed25519":
    case "EdDSA": {
      return { name: "Ed25519" };
    }
    default: {
      throw new JWTError(
        `alg ${alg} is not supported either by JOSE or your javascript runtime`,
        "ERR_JWS_ALG_NOT_ALLOWED",
      );
    }
  }
}
