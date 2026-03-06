import { checkEncCryptoKey } from "./crypto_key";
import { checkKeyLength } from "./sign-verify";

export async function encryptRSAES(
  alg: string,
  key: CryptoKey,
  cek: Uint8Array<ArrayBuffer>,
): Promise<Uint8Array<ArrayBuffer>> {
  checkEncCryptoKey(key, alg, "encrypt");
  checkKeyLength(alg, key);

  return new Uint8Array(await crypto.subtle.encrypt("RSA-OAEP", key, cek));
}

export async function decryptRSAES(
  alg: string,
  key: CryptoKey,
  encryptedKey: Uint8Array<ArrayBuffer>,
): Promise<Uint8Array<ArrayBuffer>> {
  checkEncCryptoKey(key, alg, "decrypt");
  checkKeyLength(alg, key);

  return new Uint8Array(await crypto.subtle.decrypt("RSA-OAEP", key, encryptedKey));
}
