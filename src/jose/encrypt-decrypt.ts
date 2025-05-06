/**
 * This is a fork of Jose library's utility functions.
 * @source https://github.com/panva/jose/tree/69b7960c67e05be55fa2ec31c74b987696c20c60/src/lib/encrypt.ts
 * @source https://github.com/panva/jose/tree/69b7960c67e05be55fa2ec31c74b987696c20c60/src/lib/decrypt.ts
 * @license MIT https://github.com/panva/jose/blob/69b7960c67e05be55fa2ec31c74b987696c20c60/LICENSE.md
 */

import { concatUint8Arrays } from "../utils";

import { uint64be } from "./buffer_utils";
import { checkIvLength, checkCEKLength, generateIV } from "./cek-iv";
import { checkEncCryptoKey } from "./crypto_key";

async function cbcEncrypt(
  enc: string,
  plaintext: Uint8Array,
  cek: Uint8Array | CryptoKey,
  iv: Uint8Array,
  aad: Uint8Array,
) {
  if (!(cek instanceof Uint8Array)) {
    throw new TypeError(`Key must be ${cek} of type: Uint8Array`);
  }
  const keySize = Number.parseInt(enc.slice(1, 4), 10);
  const encKey = await crypto.subtle.importKey(
    "raw",
    cek.subarray(keySize >> 3),
    "AES-CBC",
    false,
    ["encrypt"],
  );
  const macKey = await crypto.subtle.importKey(
    "raw",
    cek.subarray(0, keySize >> 3),
    {
      hash: `SHA-${keySize << 1}`,
      name: "HMAC",
    },
    false,
    ["sign"],
  );

  const ciphertext = new Uint8Array(
    await crypto.subtle.encrypt(
      {
        iv,
        name: "AES-CBC",
      },
      encKey,
      plaintext,
    ),
  );

  const macData = concatUint8Arrays(
    aad,
    iv,
    ciphertext,
    uint64be(aad.length << 3),
  );
  const tag = new Uint8Array(
    (await crypto.subtle.sign("HMAC", macKey, macData)).slice(0, keySize >> 3),
  );

  return { ciphertext, tag, iv };
}

async function gcmEncrypt(
  enc: string,
  plaintext: Uint8Array,
  cek: Uint8Array | CryptoKey,
  iv: Uint8Array,
  aad: Uint8Array,
) {
  let encKey: CryptoKey;
  if (cek instanceof Uint8Array) {
    encKey = await crypto.subtle.importKey("raw", cek, "AES-GCM", false, [
      "encrypt",
    ]);
  } else {
    checkEncCryptoKey(cek, enc, "encrypt");
    encKey = cek;
  }

  const encrypted = new Uint8Array(
    await crypto.subtle.encrypt(
      {
        additionalData: aad,
        iv,
        name: "AES-GCM",
        tagLength: 128,
      },
      encKey,
      plaintext,
    ),
  );

  const tag = encrypted.slice(-16);
  const ciphertext = encrypted.slice(0, -16);

  return { ciphertext, tag, iv };
}

export async function encrypt(
  enc: string,
  plaintext: Uint8Array,
  cek: unknown,
  iv: Uint8Array | undefined,
  aad: Uint8Array,
): Promise<{
  ciphertext: Uint8Array;
  tag: Uint8Array | undefined;
  iv: Uint8Array | undefined;
}> {
  if (!isCryptoKey(cek) && !(cek instanceof Uint8Array)) {
    throw new TypeError(
      `Key must be ${cek} one of type: CryptoKey, Uint8Array, or JSON Web Key`,
    );
  }

  if (iv) {
    checkIvLength(enc, iv);
  } else {
    iv = generateIV(enc);
  }

  switch (enc) {
    case "A128CBC-HS256":
    case "A192CBC-HS384":
    case "A256CBC-HS512": {
      if (cek instanceof Uint8Array) {
        checkCEKLength(cek, Number.parseInt(enc.slice(-3), 10));
      }
      return cbcEncrypt(enc, plaintext, cek, iv, aad);
    }
    case "A128GCM":
    case "A192GCM":
    case "A256GCM": {
      if (cek instanceof Uint8Array) {
        checkCEKLength(cek, Number.parseInt(enc.slice(1, 4), 10));
      }
      return gcmEncrypt(enc, plaintext, cek, iv, aad);
    }
    default: {
      throw new Error("Unsupported JWE Content Encryption Algorithm");
    }
  }
}

/**
 * Decrypt fork
 */

async function timingSafeEqual(a: Uint8Array, b: Uint8Array): Promise<boolean> {
  if (!(a instanceof Uint8Array)) {
    throw new TypeError("First argument must be a buffer");
  }
  if (!(b instanceof Uint8Array)) {
    throw new TypeError("Second argument must be a buffer");
  }

  const algorithm = { name: "HMAC", hash: "SHA-256" };
  const key = (await crypto.subtle.generateKey(algorithm, false, [
    "sign",
  ])) as CryptoKey;

  const aHmac = new Uint8Array(await crypto.subtle.sign(algorithm, key, a));
  const bHmac = new Uint8Array(await crypto.subtle.sign(algorithm, key, b));

  let out = 0;
  let i = -1;
  while (++i < 32) {
    out |= aHmac[i]! ^ bHmac[i]!;
  }

  return out === 0;
}

async function cbcDecrypt(
  enc: string,
  cek: Uint8Array | CryptoKey,
  ciphertext: Uint8Array,
  iv: Uint8Array,
  tag: Uint8Array,
  aad: Uint8Array,
) {
  if (!(cek instanceof Uint8Array)) {
    throw new TypeError(`Key must be ${cek} of type: Uint8Array`);
  }
  const keySize = Number.parseInt(enc.slice(1, 4), 10);
  const encKey = await crypto.subtle.importKey(
    "raw",
    cek.subarray(keySize >> 3),
    "AES-CBC",
    false,
    ["decrypt"],
  );
  const macKey = await crypto.subtle.importKey(
    "raw",
    cek.subarray(0, keySize >> 3),
    {
      hash: `SHA-${keySize << 1}`,
      name: "HMAC",
    },
    false,
    ["sign"],
  );

  const macData = concatUint8Arrays(
    aad,
    iv,
    ciphertext,
    uint64be(aad.length << 3),
  );
  const expectedTag = new Uint8Array(
    (await crypto.subtle.sign("HMAC", macKey, macData)).slice(0, keySize >> 3),
  );

  let macCheckPassed!: boolean;
  try {
    macCheckPassed = await timingSafeEqual(tag, expectedTag);
  } catch {
    //
  }
  if (!macCheckPassed) {
    throw new Error("JWE Decryption Failed");
  }

  let plaintext!: Uint8Array;
  try {
    plaintext = new Uint8Array(
      await crypto.subtle.decrypt({ iv, name: "AES-CBC" }, encKey, ciphertext),
    );
  } catch {
    //
  }
  if (!plaintext) {
    throw new Error("JWE Decryption Failed");
  }

  return plaintext;
}

async function gcmDecrypt(
  enc: string,
  cek: Uint8Array | CryptoKey,
  ciphertext: Uint8Array,
  iv: Uint8Array,
  tag: Uint8Array,
  aad: Uint8Array,
) {
  let encKey: CryptoKey;
  if (cek instanceof Uint8Array) {
    encKey = await crypto.subtle.importKey("raw", cek, "AES-GCM", false, [
      "decrypt",
    ]);
  } else {
    checkEncCryptoKey(cek, enc, "decrypt");
    encKey = cek;
  }

  try {
    return new Uint8Array(
      await crypto.subtle.decrypt(
        {
          additionalData: aad,
          iv,
          name: "AES-GCM",
          tagLength: 128,
        },
        encKey,
        concatUint8Arrays(ciphertext, tag),
      ),
    );
  } catch {
    throw new Error("JWE Decryption Failed");
  }
}

export async function decrypt(
  enc: string,
  cek: unknown,
  ciphertext: Uint8Array,
  iv: Uint8Array | undefined,
  tag: Uint8Array | undefined,
  aad: Uint8Array,
): Promise<Uint8Array> {
  if (!isCryptoKey(cek) && !(cek instanceof Uint8Array)) {
    throw new TypeError(
      `Key must be ${cek} one of type: CryptoKey, Uint8Array, or JSON Web Key`,
    );
  }

  if (!iv) {
    throw new Error("JWE Initialization Vector missing");
  }
  if (!tag) {
    throw new Error("JWE Authentication Tag missing");
  }

  checkIvLength(enc, iv);

  switch (enc) {
    case "A128CBC-HS256":
    case "A192CBC-HS384":
    case "A256CBC-HS512": {
      if (cek instanceof Uint8Array)
        checkCEKLength(cek, Number.parseInt(enc.slice(-3), 10));
      return cbcDecrypt(enc, cek, ciphertext, iv, tag, aad);
    }
    case "A128GCM":
    case "A192GCM":
    case "A256GCM": {
      if (cek instanceof Uint8Array)
        checkCEKLength(cek, Number.parseInt(enc.slice(1, 4), 10));
      return gcmDecrypt(enc, cek, ciphertext, iv, tag, aad);
    }
    default: {
      throw new Error("Unsupported JWE Content Encryption Algorithm");
    }
  }
}

/**
 * Fork from https://github.com/panva/jose/tree/69b7960c67e05be55fa2ec31c74b987696c20c60/src/lib/is_key_like.ts
 */

export function assertCryptoKey(key: unknown): asserts key is CryptoKey {
  if (!isCryptoKey(key)) {
    throw new Error("CryptoKey instance expected");
  }
}

export function isCryptoKey(key: unknown): key is CryptoKey {
  // @ts-expect-error
  return key?.[Symbol.toStringTag] === "CryptoKey";
}
