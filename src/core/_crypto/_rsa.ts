import { JWTError } from "../error";
import {
  checkKeyUsage,
  hashBitsOf,
  isAlgorithm,
  modulusLengthOf,
  unusableKey,
} from "./_key-algorithm";

export async function encryptRSAES(
  alg: string,
  key: CryptoKey,
  cek: Uint8Array<ArrayBuffer>,
): Promise<Uint8Array<ArrayBuffer>> {
  checkRSACryptoKey(key, alg, "encrypt");
  checkRSAModulusLength(alg, key);

  return new Uint8Array(await crypto.subtle.encrypt("RSA-OAEP", key, cek));
}

export async function decryptRSAES(
  alg: string,
  key: CryptoKey,
  encryptedKey: Uint8Array<ArrayBuffer>,
): Promise<Uint8Array<ArrayBuffer>> {
  checkRSACryptoKey(key, alg, "decrypt");
  checkRSAModulusLength(alg, key);

  return new Uint8Array(await crypto.subtle.decrypt("RSA-OAEP", key, encryptedKey));
}

export function checkRSACryptoKey(key: CryptoKey, alg: string, usage?: KeyUsage): void {
  if (!isAlgorithm(key.algorithm, "RSA-OAEP")) {
    throw unusableKey("RSA-OAEP");
  }
  const expected = Number.parseInt(alg.slice(9), 10) || 1;
  const actual = hashBitsOf(key.algorithm.hash);
  if (actual !== expected) throw unusableKey(`SHA-${expected}`, "algorithm.hash");
  checkKeyUsage(key, usage);
}

export function checkRSAModulusLength(alg: string, key: CryptoKey): void {
  if (alg.startsWith("RS") || alg.startsWith("PS") || alg.startsWith("RSA")) {
    const modulusLength = modulusLengthOf(key.algorithm);
    if (typeof modulusLength !== "number" || modulusLength < 2048) {
      throw new JWTError(
        `${alg} requires key modulusLength to be 2048 bits or larger`,
        "ERR_JWK_INVALID",
      );
    }
  }
}
