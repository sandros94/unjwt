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
  if (!isAlgorithm<RsaHashedKeyAlgorithm>(key.algorithm, "RSA-OAEP")) {
    throw unusable("RSA-OAEP");
  }
  const expected = Number.parseInt(alg.slice(9), 10) || 1;
  const actual = getHashLength(key.algorithm.hash);
  if (actual !== expected) throw unusable(`SHA-${expected}`, "algorithm.hash");
  checkUsage(key, usage);
}

export function checkRSAModulusLength(alg: string, key: CryptoKey): void {
  if (alg.startsWith("RS") || alg.startsWith("PS") || alg.startsWith("RSA")) {
    const { modulusLength } = key.algorithm as RsaKeyAlgorithm;
    if (typeof modulusLength !== "number" || modulusLength < 2048) {
      throw new TypeError(`${alg} requires key modulusLength to be 2048 bits or larger`);
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

function checkUsage(key: CryptoKey, usage?: KeyUsage): void {
  if (usage && !key.usages.includes(usage)) {
    throw new TypeError(
      `CryptoKey does not support this operation, its usages must include ${usage}.`,
    );
  }
}
