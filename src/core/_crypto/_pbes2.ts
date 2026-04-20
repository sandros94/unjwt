import { concatUint8Arrays, textEncoder, base64UrlEncode } from "../utils";
import { JWTError } from "../error";
import { aesKwWrap, aesKwUnwrap } from "./_aes";

export const DEFAULT_PBES2_MIN_ITERATIONS = 1000;
export const DEFAULT_PBES2_MAX_ITERATIONS = 1_000_000;

export async function pbes2Wrap(
  alg: string,
  key: CryptoKey | Uint8Array<ArrayBuffer>,
  cek: Uint8Array<ArrayBuffer>,
  p2c: number,
  p2s: Uint8Array<ArrayBuffer>,
): Promise<{ encryptedKey: Uint8Array<ArrayBuffer>; p2c: number; p2s: string }> {
  const derived = await deriveKey(p2s, alg, p2c, key);
  const encryptedKey = await aesKwWrap(alg.slice(-6), derived, cek);
  return { encryptedKey, p2c, p2s: base64UrlEncode(p2s) };
}

export async function pbes2Unwrap(
  alg: string,
  key: CryptoKey | Uint8Array<ArrayBuffer>,
  encryptedKey: Uint8Array<ArrayBuffer>,
  p2c: number,
  p2s: Uint8Array<ArrayBuffer>,
  minIterations: number = DEFAULT_PBES2_MIN_ITERATIONS,
  maxIterations: number = DEFAULT_PBES2_MAX_ITERATIONS,
): Promise<Uint8Array<ArrayBuffer>> {
  if (p2c < minIterations) {
    throw new JWTError(
      `PBES2 "p2c" below the minimum of ${minIterations} iterations (got ${p2c}).`,
      "ERR_JWE_INVALID",
    );
  }
  if (p2c > maxIterations) {
    throw new JWTError(
      `PBES2 "p2c" above the maximum of ${maxIterations} iterations (got ${p2c}).`,
      "ERR_JWE_INVALID",
    );
  }
  const derived = await deriveKey(p2s, alg, p2c, key);
  return aesKwUnwrap(alg.slice(-6), derived, encryptedKey);
}

export async function deriveKey(
  p2s: Uint8Array<ArrayBuffer>,
  alg: string,
  p2c: number,
  key: CryptoKey | Uint8Array<ArrayBuffer>,
): Promise<Uint8Array<ArrayBuffer>> {
  if (!(p2s instanceof Uint8Array) || p2s.length < 8) {
    throw new Error("PBES2 Salt Input must be 8 or more octets");
  }
  if (p2c === undefined || p2c < 1) {
    throw new Error("PBES2 Iteration Count Parameter must be a positive integer");
  }

  const salt = concatUint8Arrays(textEncoder.encode(alg), new Uint8Array([0]), p2s);
  const keylen = Number.parseInt(alg.slice(13, 16), 10);
  const subtleAlg = {
    hash: `SHA-${alg.slice(8, 11)}`,
    iterations: p2c,
    name: "PBKDF2",
    salt,
  };

  const cryptoKey = await getPBKDF2CryptoKey(key, alg);

  return new Uint8Array(await crypto.subtle.deriveBits(subtleAlg, cryptoKey, keylen));
}

export function checkPBES2CryptoKey(key: CryptoKey, alg: string, usage?: KeyUsage): void {
  if (!isAlgorithm(key.algorithm, "PBKDF2")) {
    throw unusable("PBKDF2");
  }
  checkUsage(key, usage);
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

function checkUsage(key: CryptoKey, usage?: KeyUsage): void {
  if (usage && !key.usages.includes(usage)) {
    throw new TypeError(
      `CryptoKey does not support this operation, its usages must include ${usage}.`,
    );
  }
}

async function getPBKDF2CryptoKey(
  key: CryptoKey | Uint8Array<ArrayBuffer>,
  alg: string,
  options: { usage?: KeyUsage; extractable?: boolean } = {},
): Promise<CryptoKey> {
  const { extractable = false, usage = "deriveBits" } = options;
  if (key instanceof Uint8Array) {
    return crypto.subtle.importKey("raw", key, "PBKDF2", extractable, [usage]);
  }
  checkPBES2CryptoKey(key, alg, usage);
  return key;
}
