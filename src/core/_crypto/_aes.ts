import { base64UrlStringify } from "../utils/base64.ts";

import { concatUint8Arrays, uint32be } from "../utils/array.ts";
import { isCryptoKey } from "../utils/guards.ts";
import { JWTError } from "../error.ts";
import { quoteTokenValue } from "../utils/_text.ts";
import type {
  ContentEncryptionAlgorithm,
  JWK_AES_CBC_HMAC,
  JWK_AES_GCM,
  JWK_AES_GCM_KW,
  JWK_AES_KW,
  JWKAlgorithm,
} from "../types/index.ts";
import {
  aesBitsOf,
  checkKeyUsage,
  isAlgorithm,
  jwsHashOf,
  lengthOf,
  shaBitsOf,
  unusableKey,
} from "./_key-algorithm.ts";

/** Algorithms with an IV and a tag: the content encryption ones and AES-GCM key wrapping. */
type AuthenticatedAlgorithm = ContentEncryptionAlgorithm | JWK_AES_GCM_KW;

const IV_BIT_LENGTHS: Readonly<Record<AuthenticatedAlgorithm, 96 | 128>> =
  /* @__PURE__ */ Object.freeze({
    "A128GCM": 96,
    "A128GCMKW": 96,
    "A192GCM": 96,
    "A192GCMKW": 96,
    "A256GCM": 96,
    "A256GCMKW": 96,
    "A128CBC-HS256": 128,
    "A192CBC-HS384": 128,
    "A256CBC-HS512": 128,
  });

const CEK_BIT_LENGTHS: Readonly<Record<ContentEncryptionAlgorithm, 128 | 192 | 256 | 384 | 512>> =
  /* @__PURE__ */ Object.freeze({
    "A128GCM": 128,
    "A192GCM": 192,
    "A256GCM": 256,
    "A128CBC-HS256": 256,
    "A192CBC-HS384": 384,
    "A256CBC-HS512": 512,
  });

export function bitLengthIV(alg: AuthenticatedAlgorithm): number {
  return IV_BIT_LENGTHS[alg];
}

export function generateIV(alg: AuthenticatedAlgorithm): Uint8Array<ArrayBuffer> {
  return crypto.getRandomValues(new Uint8Array(bitLengthIV(alg) >> 3));
}

export function checkIvLength(enc: AuthenticatedAlgorithm, iv: Uint8Array<ArrayBuffer>): void {
  if (iv.length << 3 !== bitLengthIV(enc)) {
    throw new JWTError("Invalid Initialization Vector length", "ERR_JWE_INVALID");
  }
}

// RFC 7518 §5.2.2.1 / §5.3: GCM tags are 128 bits; CBC-HMAC tags are half the CEK size.
const TAG_BIT_LENGTHS: Readonly<Record<AuthenticatedAlgorithm, 128 | 192 | 256>> =
  /* @__PURE__ */ Object.freeze({
    "A128GCM": 128,
    "A128GCMKW": 128,
    "A192GCM": 128,
    "A192GCMKW": 128,
    "A256GCM": 128,
    "A256GCMKW": 128,
    "A128CBC-HS256": 128,
    "A192CBC-HS384": 192,
    "A256CBC-HS512": 256,
  });

export function bitLengthTag(alg: AuthenticatedAlgorithm): number {
  return TAG_BIT_LENGTHS[alg];
}

export function checkTagLength(enc: AuthenticatedAlgorithm, tag: Uint8Array<ArrayBuffer>): void {
  if (tag.length << 3 !== bitLengthTag(enc)) {
    throw new JWTError("Invalid Authentication Tag length", "ERR_JWE_INVALID");
  }
}

export function bitLengthCEK(enc: ContentEncryptionAlgorithm): number {
  return CEK_BIT_LENGTHS[enc];
}

export function generateCEK(alg: ContentEncryptionAlgorithm): Uint8Array<ArrayBuffer> {
  return crypto.getRandomValues(new Uint8Array(bitLengthCEK(alg) >> 3));
}

export function checkCEKLength(cek: Uint8Array<ArrayBuffer>, expected: number): void {
  const actual = cek.byteLength << 3;
  if (actual !== expected) {
    throw new JWTError(
      `Invalid Content Encryption Key length, expected ${expected} bits (got ${actual})`,
      "ERR_INVALID_OPTION",
    );
  }
}

// RFC 7518 §3.2: HMAC keys are at least the hash size; AES keys have an exact size.
export function assertOctKeyLength(bytes: Uint8Array, alg: JWKAlgorithm | undefined): void {
  if (!alg) return;
  if (alg === "HS256" || alg === "HS384" || alg === "HS512") {
    const minBytes = shaBitsOf(jwsHashOf(alg)) >> 3;
    if (bytes.length < minBytes) {
      throw new JWTError(
        `${alg} requires a key of at least ${minBytes} bytes (got ${bytes.length})`,
        "ERR_JWK_INVALID",
      );
    }
    return;
  }
  const exactBits = isKeyWrapAlgorithm(alg)
    ? aesBitsOf(alg)
    : isContentEncryption(alg)
      ? CEK_BIT_LENGTHS[alg]
      : undefined;
  if (exactBits !== undefined && bytes.length << 3 !== exactBits) {
    throw new JWTError(
      `${alg} requires a key of exactly ${exactBits >> 3} bytes (got ${bytes.length})`,
      "ERR_JWK_INVALID",
    );
  }
}

export function checkAESCryptoKey(
  key: CryptoKey,
  alg: JWK_AES_KW | JWK_AES_GCM,
  usage?: KeyUsage,
): void {
  const name = alg.endsWith("KW") ? "AES-KW" : "AES-GCM";
  if (!isAlgorithm(key.algorithm, name)) throw unusableKey(name);
  const expected = aesBitsOf(alg);
  if (key.algorithm.length !== expected) throw unusableKey(expected, "algorithm.length");
  checkKeyUsage(key, usage);
}

export async function aesKwWrap(
  alg: JWK_AES_KW,
  key: CryptoKey | Uint8Array<ArrayBuffer>,
  cek: Uint8Array<ArrayBuffer>,
): Promise<Uint8Array<ArrayBuffer>> {
  const cryptoKey = await getAESKWCryptoKey(key, alg, { usage: "wrapKey" });
  checkAESKWKeySize(cryptoKey, alg);

  const cryptoKeyCek = await crypto.subtle.importKey(
    "raw",
    cek,
    { hash: "SHA-256", name: "HMAC" },
    true,
    ["sign"],
  );

  return new Uint8Array(await crypto.subtle.wrapKey("raw", cryptoKeyCek, cryptoKey, "AES-KW"));
}

export async function aesKwUnwrap(
  alg: JWK_AES_KW,
  key: CryptoKey | Uint8Array<ArrayBuffer>,
  encryptedKey: Uint8Array<ArrayBuffer>,
): Promise<Uint8Array<ArrayBuffer>> {
  const cryptoKey = await getAESKWCryptoKey(key, alg, { usage: "unwrapKey" });
  checkAESKWKeySize(cryptoKey, alg);

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

export async function gcmkwEncrypt(
  alg: JWK_AES_GCM_KW,
  key: CryptoKey | Uint8Array<ArrayBuffer>,
  plaintext: Uint8Array<ArrayBuffer>,
  iv?: Uint8Array<ArrayBuffer>,
): Promise<{ encryptedKey: Uint8Array<ArrayBuffer>; iv: string; tag: string }> {
  const wrapped = await encrypt(gcmOf(alg), plaintext, key, iv, new Uint8Array(0));

  return {
    encryptedKey: wrapped.ciphertext,
    iv: base64UrlStringify(wrapped.iv),
    tag: base64UrlStringify(wrapped.tag),
  };
}

export async function gcmkwDecrypt(
  alg: JWK_AES_GCM_KW,
  key: CryptoKey | Uint8Array<ArrayBuffer>,
  ciphertext: Uint8Array<ArrayBuffer>,
  iv: Uint8Array<ArrayBuffer>,
  tag: Uint8Array<ArrayBuffer>,
): Promise<Uint8Array<ArrayBuffer>> {
  return decrypt(gcmOf(alg), key, ciphertext, iv, tag, new Uint8Array(0));
}

export async function encrypt(
  enc: ContentEncryptionAlgorithm,
  plaintext: Uint8Array<ArrayBuffer>,
  cek: Uint8Array<ArrayBuffer> | CryptoKey,
  iv: Uint8Array<ArrayBuffer> | undefined,
  aad: Uint8Array<ArrayBuffer>,
): Promise<{
  ciphertext: Uint8Array<ArrayBuffer>;
  tag: Uint8Array<ArrayBuffer>;
  iv: Uint8Array<ArrayBuffer>;
}> {
  if (!isCryptoKey(cek) && !(cek instanceof Uint8Array)) {
    throw new JWTError("Key must be one of type: CryptoKey or Uint8Array", "ERR_JWK_INVALID");
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
      if (cek instanceof Uint8Array) checkCEKLength(cek, bitLengthCEK(enc));
      return cbcEncrypt(enc, plaintext, cek, iv, aad);
    }
    case "A128GCM":
    case "A192GCM":
    case "A256GCM": {
      if (cek instanceof Uint8Array) checkCEKLength(cek, bitLengthCEK(enc));
      return gcmEncrypt(enc, plaintext, cek, iv, aad);
    }
    default: {
      return unsupportedContentEncryption(enc);
    }
  }
}

export async function decrypt(
  enc: ContentEncryptionAlgorithm,
  cek: Uint8Array<ArrayBuffer> | CryptoKey,
  ciphertext: Uint8Array<ArrayBuffer>,
  iv: Uint8Array<ArrayBuffer> | undefined,
  tag: Uint8Array<ArrayBuffer> | undefined,
  aad: Uint8Array<ArrayBuffer>,
): Promise<Uint8Array<ArrayBuffer>> {
  if (!isCryptoKey(cek) && !(cek instanceof Uint8Array)) {
    throw new JWTError("Key must be one of type: CryptoKey or Uint8Array", "ERR_JWK_INVALID");
  }

  if (!iv) {
    throw new JWTError("JWE Initialization Vector missing", "ERR_JWE_INVALID");
  }
  if (!tag) {
    throw new JWTError("JWE Authentication Tag missing", "ERR_JWE_INVALID");
  }

  checkIvLength(enc, iv);
  checkTagLength(enc, tag);

  switch (enc) {
    case "A128CBC-HS256":
    case "A192CBC-HS384":
    case "A256CBC-HS512": {
      if (cek instanceof Uint8Array) checkCEKLength(cek, bitLengthCEK(enc));
      return cbcDecrypt(enc, cek, ciphertext, iv, tag, aad);
    }
    case "A128GCM":
    case "A192GCM":
    case "A256GCM": {
      if (cek instanceof Uint8Array) checkCEKLength(cek, bitLengthCEK(enc));
      return gcmDecrypt(enc, cek, ciphertext, iv, tag, aad);
    }
    default: {
      return unsupportedContentEncryption(enc);
    }
  }
}

async function getAESKWCryptoKey(
  key: CryptoKey | Uint8Array<ArrayBuffer>,
  alg: JWK_AES_KW,
  options: { usage?: KeyUsage; extractable?: boolean } = {},
): Promise<CryptoKey> {
  const { extractable = true, usage } = options;
  if (key instanceof Uint8Array) {
    return crypto.subtle.importKey("raw", key, "AES-KW", extractable, [usage ?? "wrapKey"]);
  }
  checkAESCryptoKey(key, alg, usage);
  return key;
}

function checkAESKWKeySize(key: CryptoKey, alg: JWK_AES_KW): void {
  if (lengthOf(key.algorithm) !== aesBitsOf(alg)) {
    throw new JWTError(`Invalid key size for alg: ${alg}`, "ERR_JWK_INVALID");
  }
}

async function importCBCKeys(enc: JWK_AES_CBC_HMAC, cek: Uint8Array<ArrayBuffer>, usage: KeyUsage) {
  const keySize = aesBitsOf(enc);
  const [encKey, macKey] = await Promise.all([
    crypto.subtle.importKey("raw", cek.subarray(keySize >> 3), "AES-CBC", false, [usage]),
    crypto.subtle.importKey(
      "raw",
      cek.subarray(0, keySize >> 3),
      { hash: `SHA-${keySize << 1}`, name: "HMAC" },
      false,
      ["sign"],
    ),
  ]);
  return { encKey, macKey, keySize };
}

function cbcMacData(
  aad: Uint8Array<ArrayBuffer>,
  iv: Uint8Array<ArrayBuffer>,
  ciphertext: Uint8Array<ArrayBuffer>,
): Uint8Array<ArrayBuffer> {
  return concatUint8Arrays(aad, iv, ciphertext, uint64be(aad.length << 3));
}

async function cbcEncrypt(
  enc: JWK_AES_CBC_HMAC,
  plaintext: Uint8Array<ArrayBuffer>,
  cek: Uint8Array<ArrayBuffer> | CryptoKey,
  iv: Uint8Array<ArrayBuffer>,
  aad: Uint8Array<ArrayBuffer>,
) {
  if (!(cek instanceof Uint8Array)) {
    throw new JWTError("CBC key must be of type Uint8Array", "ERR_JWK_INVALID");
  }
  const { encKey, macKey, keySize } = await importCBCKeys(enc, cek, "encrypt");

  const ciphertext = new Uint8Array(
    await crypto.subtle.encrypt({ iv, name: "AES-CBC" }, encKey, plaintext),
  );

  const macData = cbcMacData(aad, iv, ciphertext);
  const tag = new Uint8Array(
    (await crypto.subtle.sign("HMAC", macKey, macData)).slice(0, keySize >> 3),
  );

  return { ciphertext, tag, iv };
}

async function gcmEncrypt(
  enc: JWK_AES_GCM,
  plaintext: Uint8Array<ArrayBuffer>,
  cek: Uint8Array<ArrayBuffer> | CryptoKey,
  iv: Uint8Array<ArrayBuffer>,
  aad: Uint8Array<ArrayBuffer>,
) {
  let encKey: CryptoKey;
  if (cek instanceof Uint8Array) {
    encKey = await crypto.subtle.importKey("raw", cek, "AES-GCM", false, ["encrypt"]);
  } else {
    checkAESCryptoKey(cek, enc, "encrypt");
    encKey = cek;
  }

  const encrypted = new Uint8Array(
    await crypto.subtle.encrypt(
      { additionalData: aad, iv, name: "AES-GCM", tagLength: 128 },
      encKey,
      plaintext,
    ),
  );

  const tag = encrypted.subarray(-16);
  const ciphertext = encrypted.subarray(0, -16);

  return { ciphertext, tag, iv };
}

async function cbcDecrypt(
  enc: JWK_AES_CBC_HMAC,
  cek: Uint8Array<ArrayBuffer> | CryptoKey,
  ciphertext: Uint8Array<ArrayBuffer>,
  iv: Uint8Array<ArrayBuffer>,
  tag: Uint8Array<ArrayBuffer>,
  aad: Uint8Array<ArrayBuffer>,
) {
  if (!(cek instanceof Uint8Array)) {
    throw new JWTError("CBC key must be of type Uint8Array", "ERR_JWK_INVALID");
  }
  const { encKey, macKey, keySize } = await importCBCKeys(enc, cek, "decrypt");

  const macData = cbcMacData(aad, iv, ciphertext);
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
    throw new JWTError("JWE Decryption Failed", "ERR_JWE_DECRYPTION_FAILED");
  }

  let plaintext!: Uint8Array<ArrayBuffer>;
  try {
    plaintext = new Uint8Array(
      await crypto.subtle.decrypt({ iv, name: "AES-CBC" }, encKey, ciphertext),
    );
  } catch {
    //
  }
  if (!plaintext) {
    throw new JWTError("JWE Decryption Failed", "ERR_JWE_DECRYPTION_FAILED");
  }

  return plaintext;
}

async function gcmDecrypt(
  enc: JWK_AES_GCM,
  cek: Uint8Array<ArrayBuffer> | CryptoKey,
  ciphertext: Uint8Array<ArrayBuffer>,
  iv: Uint8Array<ArrayBuffer>,
  tag: Uint8Array<ArrayBuffer>,
  aad: Uint8Array<ArrayBuffer>,
) {
  let encKey: CryptoKey;
  if (cek instanceof Uint8Array) {
    encKey = await crypto.subtle.importKey("raw", cek, "AES-GCM", false, ["decrypt"]);
  } else {
    checkAESCryptoKey(cek, enc, "decrypt");
    encKey = cek;
  }

  try {
    return new Uint8Array(
      await crypto.subtle.decrypt(
        { additionalData: aad, iv, name: "AES-GCM", tagLength: 128 },
        encKey,
        concatUint8Arrays(ciphertext, tag),
      ),
    );
  } catch {
    throw new JWTError("JWE Decryption Failed", "ERR_JWE_DECRYPTION_FAILED");
  }
}

let _timingSafeKey: Promise<CryptoKey> | undefined;
function getTimingSafeKey(): Promise<CryptoKey> {
  if (!_timingSafeKey) {
    _timingSafeKey = crypto.subtle.generateKey({ name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  }
  return _timingSafeKey;
}

async function timingSafeEqual(
  a: Uint8Array<ArrayBuffer>,
  b: Uint8Array<ArrayBuffer>,
): Promise<boolean> {
  if (!(a instanceof Uint8Array)) {
    throw new JWTError("First argument must be a buffer", "ERR_INVALID_OPTION");
  }
  if (!(b instanceof Uint8Array)) {
    throw new JWTError("Second argument must be a buffer", "ERR_INVALID_OPTION");
  }

  const algorithm = { name: "HMAC", hash: "SHA-256" };
  const key = await getTimingSafeKey();

  const aHmac = new Uint8Array(await crypto.subtle.sign(algorithm, key, a));
  const bHmac = new Uint8Array(await crypto.subtle.sign(algorithm, key, b));

  let out = 0;
  let i = -1;
  while (++i < 32) {
    out |= aHmac[i] ^ bHmac[i];
  }

  return out === 0;
}

function uint64be(value: number): Uint8Array<ArrayBuffer> {
  return concatUint8Arrays(uint32be(Math.floor(value / 2 ** 32)), uint32be(value % 2 ** 32));
}

/** The content encryption algorithm an `A*GCMKW` wraps with: the name without its `KW`. */
function gcmOf(alg: JWK_AES_GCM_KW): JWK_AES_GCM {
  // oxlint-disable-next-line typescript/no-unsafe-type-assertion -- every `JWK_AES_GCM_KW` is a `JWK_AES_GCM` plus `KW`; `slice` cannot carry it
  return alg.slice(0, 7) as JWK_AES_GCM;
}

/** Of the closed `JWKAlgorithm` union, only `A*KW` and `A*GCMKW` start with `A` and end with `KW`. */
function isKeyWrapAlgorithm(alg: JWKAlgorithm): alg is JWK_AES_KW | JWK_AES_GCM_KW {
  return alg.startsWith("A") && alg.endsWith("KW");
}

function isContentEncryption(alg: string): alg is ContentEncryptionAlgorithm {
  return Object.hasOwn(CEK_BIT_LENGTHS, alg);
}

/** Reached only by a caller outside the type system; `never` keeps the switches above exhaustive. */
function unsupportedContentEncryption(enc: never): never {
  throw new JWTError(
    `Unsupported JWE Content Encryption Algorithm: ${quoteTokenValue(String(enc))}`,
    "ERR_JWE_INVALID",
  );
}
