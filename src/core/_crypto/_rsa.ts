import { JWTError } from "../../error.ts";
import type { JWK_RSA_ENC, JWK_RSA_PSS, JWK_RSA_SIGN } from "../types/index.ts";
import {
  checkKeyUsage,
  hashBitsOf,
  isAlgorithm,
  modulusLengthOf,
  rsaOaepHashOf,
  shaBitsOf,
  unusableKey,
} from "./_key-algorithm.ts";

export async function encryptRSAES(
  alg: JWK_RSA_ENC,
  key: CryptoKey,
  cek: Uint8Array<ArrayBuffer>,
): Promise<Uint8Array<ArrayBuffer>> {
  checkRSACryptoKey(key, alg, "encrypt");
  checkRSAModulusLength(alg, key);

  return new Uint8Array(await crypto.subtle.encrypt("RSA-OAEP", key, cek));
}

export async function decryptRSAES(
  alg: JWK_RSA_ENC,
  key: CryptoKey,
  encryptedKey: Uint8Array<ArrayBuffer>,
): Promise<Uint8Array<ArrayBuffer>> {
  checkRSACryptoKey(key, alg, "decrypt");
  checkRSAModulusLength(alg, key);

  return new Uint8Array(await crypto.subtle.decrypt("RSA-OAEP", key, encryptedKey));
}

export function checkRSACryptoKey(key: CryptoKey, alg: JWK_RSA_ENC, usage?: KeyUsage): void {
  if (!isAlgorithm(key.algorithm, "RSA-OAEP")) {
    throw unusableKey("RSA-OAEP");
  }
  const expected = shaBitsOf(rsaOaepHashOf(alg));
  const actual = hashBitsOf(key.algorithm.hash);
  if (actual !== expected) throw unusableKey(`SHA-${expected}`, "algorithm.hash");
  checkKeyUsage(key, usage);
}

export function checkRSAModulusLength(
  alg: JWK_RSA_SIGN | JWK_RSA_PSS | JWK_RSA_ENC,
  key: CryptoKey,
): void {
  const modulusLength = modulusLengthOf(key.algorithm);
  if (typeof modulusLength !== "number" || modulusLength < 2048) {
    throw new JWTError(
      `${alg} requires key modulusLength to be 2048 bits or larger`,
      "ERR_JWK_INVALID",
    );
  }
}
