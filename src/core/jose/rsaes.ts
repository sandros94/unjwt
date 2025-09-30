import { checkEncCryptoKey } from "./crypto_key";
import { checkKeyLength } from "./sign-verify";

const subtleAlgorithm = (alg: string) => {
  switch (alg) {
    case "RSA-OAEP":
    case "RSA-OAEP-256":
    case "RSA-OAEP-384":
    case "RSA-OAEP-512": {
      return "RSA-OAEP";
    }
    default: {
      throw new Error(
        `alg ${alg} is not supported either by JOSE or your javascript runtime`,
      );
    }
  }
};

export async function encryptRSAES(
  alg: string,
  key: CryptoKey,
  cek: Uint8Array<ArrayBuffer>,
) {
  checkEncCryptoKey(key, alg, "encrypt");
  checkKeyLength(alg, key);

  return new Uint8Array(
    await crypto.subtle.encrypt(subtleAlgorithm(alg), key, cek),
  );
}

export async function decryptRSAES(
  alg: string,
  key: CryptoKey,
  encryptedKey: Uint8Array<ArrayBuffer>,
) {
  checkEncCryptoKey(key, alg, "decrypt");
  checkKeyLength(alg, key);

  return new Uint8Array(
    await crypto.subtle.decrypt(subtleAlgorithm(alg), key, encryptedKey),
  );
}
