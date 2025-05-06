/**
 * This is a fork of Jose library's utility functions.
 * @source https://github.com/panva/jose/tree/69b7960c67e05be55fa2ec31c74b987696c20c60/src/lib/pbes2kw.ts
 * @license MIT https://github.com/panva/jose/blob/69b7960c67e05be55fa2ec31c74b987696c20c60/LICENSE.md
 */

import { concatUint8Arrays, textEncoder, base64UrlEncode } from "../utils";

import { checkEncCryptoKey } from "./crypto_key";

export async function wrap(
  alg: string,
  key: CryptoKey | Uint8Array,
  cek: Uint8Array,
  p2c?: number,
  p2s?: Uint8Array,
) {
  if (p2c && p2s) {
    const derived = await deriveKey(p2s, alg, p2c, key);

    const encryptedKey = await _wrap(alg.slice(-6), derived, cek);

    return { encryptedKey, p2c, p2s: base64UrlEncode(p2s) };
  } else {
    const encryptedKey = await _wrap(alg, key, cek);

    return { encryptedKey };
  }
}

export async function unwrap(
  alg: string,
  key: CryptoKey | Uint8Array,
  encryptedKey: Uint8Array,
  p2c?: number,
  p2s?: Uint8Array,
) {
  if (p2c && p2s) {
    const derived = await deriveKey(p2s, alg, p2c, key);

    return _unwrap(alg.slice(-6), derived, encryptedKey);
  } else {
    return _unwrap(alg, key, encryptedKey);
  }
}

function getCryptoKey(
  key: CryptoKey | Uint8Array,
  alg: string,
  options: {
    usage?: KeyUsage;
    extractable?: boolean;
    importAlg?: "AES-KW" | "PBKDF2";
  } = {},
) {
  const {
    importAlg = "PBKDF2",
    extractable = false,
    usage = "deriveBits",
  } = options;

  if (key instanceof Uint8Array) {
    return crypto.subtle.importKey("raw", key, importAlg, extractable, [usage]);
  }

  checkEncCryptoKey(key, alg, usage);
  return key;
}

export async function deriveKey(
  p2s: Uint8Array,
  alg: string,
  p2c: number,
  key: CryptoKey | Uint8Array,
): Promise<Uint8Array> {
  if (!(p2s instanceof Uint8Array) || p2s.length < 8) {
    throw new Error("PBES2 Salt Input must be 8 or more octets");
  }
  if (p2c === undefined || p2c < 1) {
    throw new Error(
      "PBES2 Iteration Count Parameter must be a positive integer",
    );
  }

  const salt = concatUint8Arrays(
    textEncoder.encode(alg),
    new Uint8Array([0]),
    p2s,
  );
  const keylen = Number.parseInt(alg.slice(13, 16), 10);
  const subtleAlg = {
    hash: `SHA-${alg.slice(8, 11)}`,
    iterations: p2c,
    name: "PBKDF2",
    salt,
  };

  const cryptoKey = await getCryptoKey(key, alg);

  return new Uint8Array(
    await crypto.subtle.deriveBits(subtleAlg, cryptoKey, keylen),
  );
}

/**
 * Fork from: https://github.com/panva/jose/tree/69b7960c67e05be55fa2ec31c74b987696c20c60/src/lib/aeskw.ts
 */

function checkKeySize(key: CryptoKey, alg: string) {
  if (
    (key.algorithm as AesKeyAlgorithm).length !==
    Number.parseInt(alg.slice(1, 4), 10)
  ) {
    throw new TypeError(`Invalid key size for alg: ${alg}`);
  }
}

async function _wrap(
  alg: string,
  key: CryptoKey | Uint8Array,
  cek: Uint8Array,
) {
  const cryptoKey = await getCryptoKey(key, alg, {
    importAlg: "AES-KW",
    extractable: true,
    usage: "wrapKey",
  });

  checkKeySize(cryptoKey, alg);

  // algorithm used is irrelevant
  const cryptoKeyCek = await crypto.subtle.importKey(
    "raw",
    cek,
    { hash: "SHA-256", name: "HMAC" },
    true,
    ["sign"],
  );

  return new Uint8Array(
    await crypto.subtle.wrapKey("raw", cryptoKeyCek, cryptoKey, "AES-KW"),
  );
}

async function _unwrap(
  alg: string,
  key: CryptoKey | Uint8Array,
  encryptedKey: Uint8Array,
) {
  const cryptoKey = await getCryptoKey(key, alg, {
    importAlg: "AES-KW",
    extractable: true,
    usage: "unwrapKey",
  });

  checkKeySize(cryptoKey, alg);

  // algorithm used is irrelevant
  const cryptoKeyCek = await crypto.subtle.unwrapKey(
    "raw",
    encryptedKey,
    cryptoKey,
    "AES-KW",
    { hash: "SHA-256", name: "HMAC" },
    true,
    ["sign"],
  );

  return new Uint8Array(await crypto.subtle.exportKey("raw", cryptoKeyCek));
}
