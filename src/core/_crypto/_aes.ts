import { base64UrlStringify } from "../utils/base64";

import { concatUint8Arrays } from "../utils/array";
import { isCryptoKey } from "../utils/guards";
import { JWTError } from "../error";
import { lengthOf } from "./_key-algorithm";

// --- CEK / IV generation ---

const IV_BIT_LENGTHS: Record<string, number> = {
  "A128GCM": 96,
  "A128GCMKW": 96,
  "A192GCM": 96,
  "A192GCMKW": 96,
  "A256GCM": 96,
  "A256GCMKW": 96,
  "A128CBC-HS256": 128,
  "A192CBC-HS384": 128,
  "A256CBC-HS512": 128,
};

const CEK_BIT_LENGTHS: Record<string, number> = {
  "A128GCM": 128,
  "A192GCM": 192,
  "A256GCM": 256,
  "A128CBC-HS256": 256,
  "A192CBC-HS384": 384,
  "A256CBC-HS512": 512,
};

export function bitLengthIV(alg: string): number {
  const length = IV_BIT_LENGTHS[alg];
  if (length === undefined) {
    throw new JWTError(`Unsupported JWE Algorithm: ${alg}`, "ERR_JWE_INVALID");
  }
  return length;
}

export function generateIV(alg: string): Uint8Array<ArrayBuffer> {
  return crypto.getRandomValues(new Uint8Array(bitLengthIV(alg) >> 3));
}

export function checkIvLength(enc: string, iv: Uint8Array<ArrayBuffer>): void {
  if (iv.length << 3 !== bitLengthIV(enc)) {
    throw new JWTError("Invalid Initialization Vector length", "ERR_JWE_INVALID");
  }
}

// RFC 7518 §5.2.2.1 / §5.3: AES-GCM always authenticates with a 128-bit tag;
// AES-CBC-HMAC truncates the HMAC to half the digest, i.e. half the CEK size.
const TAG_BIT_LENGTHS: Record<string, number> = {
  "A128GCM": 128,
  "A128GCMKW": 128,
  "A192GCM": 128,
  "A192GCMKW": 128,
  "A256GCM": 128,
  "A256GCMKW": 128,
  "A128CBC-HS256": 128,
  "A192CBC-HS384": 192,
  "A256CBC-HS512": 256,
};

export function bitLengthTag(alg: string): number {
  const length = TAG_BIT_LENGTHS[alg];
  if (length === undefined) {
    throw new JWTError(`Unsupported JWE Algorithm: ${alg}`, "ERR_JWE_INVALID");
  }
  return length;
}

export function checkTagLength(enc: string, tag: Uint8Array<ArrayBuffer>): void {
  if (tag.length << 3 !== bitLengthTag(enc)) {
    throw new JWTError("Invalid Authentication Tag length", "ERR_JWE_INVALID");
  }
}

export function bitLengthCEK(alg: string): number {
  const length = CEK_BIT_LENGTHS[alg];
  if (length === undefined) {
    throw new JWTError(`Unsupported JWE Algorithm: ${alg}`, "ERR_JWE_INVALID");
  }
  return length;
}

export function generateCEK(alg: string): Uint8Array<ArrayBuffer> {
  return crypto.getRandomValues(new Uint8Array(bitLengthCEK(alg) >> 3));
}

export function checkCEKLength(cek: Uint8Array<ArrayBuffer>, expected: number): void {
  const actual = cek.byteLength << 3;
  if (actual !== expected) {
    throw new JWTError(
      `Invalid Content Encryption Key length. Expected ${expected} bits, got ${actual} bits`,
      "ERR_INVALID_OPTION",
    );
  }
}

// RFC 7518 §3.2: HMAC keys must be at least the hash output size; AES-based
// algorithms require an exact key size. Algorithms whose key size cannot be
// known from `alg` alone (e.g. "dir", absent alg) are skipped.
export function assertOctKeyLength(bytes: Uint8Array, alg: string | undefined): void {
  if (!alg) return;
  if (alg === "HS256" || alg === "HS384" || alg === "HS512") {
    const minBytes = Number.parseInt(alg.slice(2), 10) >> 3;
    if (bytes.length < minBytes) {
      throw new JWTError(
        `${alg} requires a key of at least ${minBytes} bytes (got ${bytes.length})`,
        "ERR_JWK_INVALID",
      );
    }
    return;
  }
  const exactBits = /^A(128|192|256)(GCM)?KW$/.test(alg)
    ? Number.parseInt(alg.slice(1, 4), 10)
    : CEK_BIT_LENGTHS[alg];
  if (exactBits !== undefined && bytes.length << 3 !== exactBits) {
    throw new JWTError(
      `${alg} requires a key of exactly ${exactBits >> 3} bytes (got ${bytes.length})`,
      "ERR_JWK_INVALID",
    );
  }
}

// --- AES CryptoKey validation ---

export function checkAESCryptoKey(key: CryptoKey, alg: string, usage?: KeyUsage): void {
  switch (alg) {
    case "A128GCM":
    case "A192GCM":
    case "A256GCM": {
      if (!isAlgorithm<AesKeyAlgorithm>(key.algorithm, "AES-GCM")) throw unusable("AES-GCM");
      const expected = Number.parseInt(alg.slice(1, 4), 10);
      const actual = key.algorithm.length;
      if (actual !== expected) throw unusable(expected, "algorithm.length");
      break;
    }
    case "A128KW":
    case "A192KW":
    case "A256KW": {
      if (!isAlgorithm<AesKeyAlgorithm>(key.algorithm, "AES-KW")) throw unusable("AES-KW");
      const expected = Number.parseInt(alg.slice(1, 4), 10);
      const actual = key.algorithm.length;
      if (actual !== expected) throw unusable(expected, "algorithm.length");
      break;
    }
    default: {
      throw new JWTError("CryptoKey does not support this operation", "ERR_JWK_INVALID");
    }
  }
  checkUsage(key, usage);
}

// --- AES-KW key wrap / unwrap ---

export async function aesKwWrap(
  alg: string,
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
  alg: string,
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

// --- AES-GCM key wrap (AES-GCMKW) ---

export async function gcmkwEncrypt(
  alg: string,
  key: CryptoKey | Uint8Array<ArrayBuffer>,
  plaintext: Uint8Array<ArrayBuffer>,
  iv?: Uint8Array<ArrayBuffer>,
): Promise<{ encryptedKey: Uint8Array<ArrayBuffer>; iv: string; tag: string }> {
  const jweAlgorithm = alg.slice(0, 7);
  const wrapped = await encrypt(jweAlgorithm, plaintext, key, iv, new Uint8Array(0));

  return {
    encryptedKey: wrapped.ciphertext,
    iv: base64UrlStringify(wrapped.iv),
    tag: base64UrlStringify(wrapped.tag),
  };
}

export async function gcmkwDecrypt(
  alg: string,
  key: CryptoKey | Uint8Array<ArrayBuffer>,
  ciphertext: Uint8Array<ArrayBuffer>,
  iv: Uint8Array<ArrayBuffer>,
  tag: Uint8Array<ArrayBuffer>,
): Promise<Uint8Array<ArrayBuffer>> {
  const jweAlgorithm = alg.slice(0, 7);
  return decrypt(jweAlgorithm, key, ciphertext, iv, tag, new Uint8Array(0));
}

// --- AES-GCM / AES-CBC content encryption / decryption ---

export async function encrypt(
  enc: string,
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
      throw new JWTError("Unsupported JWE Content Encryption Algorithm", "ERR_JWE_INVALID");
    }
  }
}

export async function decrypt(
  enc: string,
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
      if (cek instanceof Uint8Array) checkCEKLength(cek, Number.parseInt(enc.slice(-3), 10));
      return cbcDecrypt(enc, cek, ciphertext, iv, tag, aad);
    }
    case "A128GCM":
    case "A192GCM":
    case "A256GCM": {
      if (cek instanceof Uint8Array) checkCEKLength(cek, Number.parseInt(enc.slice(1, 4), 10));
      return gcmDecrypt(enc, cek, ciphertext, iv, tag, aad);
    }
    default: {
      throw new JWTError("Unsupported JWE Content Encryption Algorithm", "ERR_JWE_INVALID");
    }
  }
}

// --- Internal helpers ---

function unusable(name: string | number, prop = "algorithm.name") {
  return new JWTError(
    `CryptoKey does not support this operation, its ${prop} must be ${name}`,
    "ERR_JWK_INVALID",
  );
}

function isAlgorithm<T extends KeyAlgorithm>(
  algorithm: KeyAlgorithm,
  name: string,
): algorithm is T {
  return algorithm.name === name;
}

function checkUsage(key: CryptoKey, usage?: KeyUsage): void {
  if (usage && !key.usages.includes(usage)) {
    throw new JWTError(
      `CryptoKey does not support this operation, its usages must include ${usage}.`,
      "ERR_JWK_INVALID",
    );
  }
}

async function getAESKWCryptoKey(
  key: CryptoKey | Uint8Array<ArrayBuffer>,
  alg: string,
  options: { usage?: KeyUsage; extractable?: boolean } = {},
): Promise<CryptoKey> {
  const { extractable = true, usage } = options;
  if (key instanceof Uint8Array) {
    return crypto.subtle.importKey("raw", key, "AES-KW", extractable, [usage ?? "wrapKey"]);
  }
  checkAESCryptoKey(key, alg, usage);
  return key;
}

function checkAESKWKeySize(key: CryptoKey, alg: string): void {
  if (lengthOf(key.algorithm) !== Number.parseInt(alg.slice(1, 4), 10)) {
    throw new JWTError(`Invalid key size for alg: ${alg}`, "ERR_JWK_INVALID");
  }
}

async function importCBCKeys(enc: string, cek: Uint8Array<ArrayBuffer>, usage: KeyUsage) {
  const keySize = Number.parseInt(enc.slice(1, 4), 10);
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
  enc: string,
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
  enc: string,
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
  enc: string,
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
  enc: string,
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

function writeUInt32BE(buf: Uint8Array<ArrayBuffer>, value: number, offset?: number): void {
  if (value < 0 || value >= 2 ** 32) {
    throw new JWTError(
      `value must be >= 0 and <= ${2 ** 32 - 1}. Received ${value}`,
      "ERR_INVALID_OPTION",
    );
  }
  buf.set([value >>> 24, value >>> 16, value >>> 8, value & 0xff], offset);
}

function uint64be(value: number): Uint8Array<ArrayBuffer> {
  const high = Math.floor(value / 2 ** 32);
  const low = value % 2 ** 32;
  const buf = new Uint8Array(8);
  writeUInt32BE(buf, high, 0);
  writeUInt32BE(buf, low, 4);
  return buf;
}
