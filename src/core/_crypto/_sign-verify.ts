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
    case "HS512": {
      if (!isAlgorithm<HmacKeyAlgorithm>(key.algorithm, "HMAC")) throw unusable("HMAC");
      const expected = Number.parseInt(alg.slice(2), 10);
      const actual = getHashLength(key.algorithm.hash);
      if (actual !== expected) throw unusable(`SHA-${expected}`, "algorithm.hash");
      break;
    }
    case "RS256":
    case "RS384":
    case "RS512": {
      if (!isAlgorithm<RsaHashedKeyAlgorithm>(key.algorithm, "RSASSA-PKCS1-v1_5"))
        throw unusable("RSASSA-PKCS1-v1_5");
      const expected = Number.parseInt(alg.slice(2), 10);
      const actual = getHashLength(key.algorithm.hash);
      if (actual !== expected) throw unusable(`SHA-${expected}`, "algorithm.hash");
      break;
    }
    case "PS256":
    case "PS384":
    case "PS512": {
      if (!isAlgorithm<RsaHashedKeyAlgorithm>(key.algorithm, "RSA-PSS")) throw unusable("RSA-PSS");
      const expected = Number.parseInt(alg.slice(2), 10);
      const actual = getHashLength(key.algorithm.hash);
      if (actual !== expected) throw unusable(`SHA-${expected}`, "algorithm.hash");
      break;
    }
    case "Ed25519":
    case "EdDSA": {
      if (!isAlgorithm(key.algorithm, "Ed25519")) throw unusable("Ed25519");
      break;
    }
    case "ES256":
    case "ES384":
    case "ES512": {
      if (!isAlgorithm<EcKeyAlgorithm>(key.algorithm, "ECDSA")) throw unusable("ECDSA");
      const expected = getNamedCurve(alg);
      const actual = key.algorithm.namedCurve;
      if (actual !== expected) throw unusable(expected, "algorithm.namedCurve");
      break;
    }
    default: {
      throw new TypeError("CryptoKey does not support this operation");
    }
  }

  checkUsage(key, usage);
}

export function subtleAlgorithm(
  alg: string,
  algorithm: KeyAlgorithm | EcKeyAlgorithm,
):
  | { hash: string; name: string; saltLength?: undefined; namedCurve?: undefined }
  | { hash: string; name: string; saltLength: number; namedCurve?: undefined }
  | { hash: string; name: string; namedCurve: string; saltLength?: undefined }
  | { name: string; hash?: undefined; saltLength?: undefined; namedCurve?: undefined } {
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
    case "Ed25519":
    case "EdDSA": {
      return { name: "Ed25519" };
    }
    default: {
      throw new Error(`alg ${alg} is not supported either by JOSE or your javascript runtime`);
    }
  }
}

// --- Internal helpers ---

function unusable(name: string | number, prop = "algorithm.name") {
  return new TypeError(`CryptoKey does not support this operation, its ${prop} must be ${name}`);
}

function isAlgorithm<T extends KeyAlgorithm>(
  algorithm: KeyAlgorithm,
  name: string,
): algorithm is T {
  return algorithm.name === name;
}

function getHashLength(hash: KeyAlgorithm) {
  return Number.parseInt(hash.name.slice(4), 10);
}

function getNamedCurve(alg: string) {
  switch (alg) {
    case "ES256":
      return "P-256";
    case "ES384":
      return "P-384";
    case "ES512":
      return "P-521";
    default:
      throw new Error("unreachable");
  }
}

function checkUsage(key: CryptoKey, usage?: KeyUsage): void {
  if (usage && !key.usages.includes(usage)) {
    throw new TypeError(
      `CryptoKey does not support this operation, its usages must include ${usage}.`,
    );
  }
}
