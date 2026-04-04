import { concatUint8Arrays, isCryptoKey, base64UrlEncode } from "../utils";

// --- CEK / IV generation ---

const IV_BIT_LENGTHS: Record<string, number> = {
  A128GCM: 96,
  A128GCMKW: 96,
  A192GCM: 96,
  A192GCMKW: 96,
  A256GCM: 96,
  A256GCMKW: 96,
  "A128CBC-HS256": 128,
  "A192CBC-HS384": 128,
  "A256CBC-HS512": 128,
};

const CEK_BIT_LENGTHS: Record<string, number> = {
  A128GCM: 128,
  A192GCM: 192,
  A256GCM: 256,
  "A128CBC-HS256": 256,
  "A192CBC-HS384": 384,
  "A256CBC-HS512": 512,
};

export function bitLengthIV(alg: string): number {
  const length = IV_BIT_LENGTHS[alg];
  if (length === undefined) {
    throw new Error(`Unsupported JWE Algorithm: ${alg}`);
  }
  return length;
}

export function generateIV(alg: string): Uint8Array<ArrayBuffer> {
  return crypto.getRandomValues(new Uint8Array(bitLengthIV(alg) >> 3));
}

export function checkIvLength(enc: string, iv: Uint8Array<ArrayBuffer>): void {
  if (iv.length << 3 !== bitLengthIV(enc)) {
    throw new Error("Invalid Initialization Vector length");
  }
}

export function bitLengthCEK(alg: string): number {
  const length = CEK_BIT_LENGTHS[alg];
  if (length === undefined) {
    throw new Error(`Unsupported JWE Algorithm: ${alg}`);
  }
  return length;
}

export function generateCEK(alg: string): Uint8Array<ArrayBuffer> {
  return crypto.getRandomValues(new Uint8Array(bitLengthCEK(alg) >> 3));
}

export function checkCEKLength(cek: Uint8Array<ArrayBuffer>, expected: number): void {
  const actual = cek.byteLength << 3;
  if (actual !== expected) {
    throw new Error(
      `Invalid Content Encryption Key length. Expected ${expected} bits, got ${actual} bits`,
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
      throw new TypeError("CryptoKey does not support this operation");
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
    iv: base64UrlEncode(wrapped.iv!),
    tag: base64UrlEncode(wrapped.tag!),
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
  tag: Uint8Array<ArrayBuffer> | undefined;
  iv: Uint8Array<ArrayBuffer> | undefined;
}> {
  if (!isCryptoKey(cek) && !(cek instanceof Uint8Array)) {
    throw new TypeError("Key must be one of type: CryptoKey or Uint8Array");
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

export async function decrypt(
  enc: string,
  cek: Uint8Array<ArrayBuffer> | CryptoKey,
  ciphertext: Uint8Array<ArrayBuffer>,
  iv: Uint8Array<ArrayBuffer> | undefined,
  tag: Uint8Array<ArrayBuffer> | undefined,
  aad: Uint8Array<ArrayBuffer>,
): Promise<Uint8Array<ArrayBuffer>> {
  if (!isCryptoKey(cek) && !(cek instanceof Uint8Array)) {
    throw new TypeError("Key must be one of type: CryptoKey or Uint8Array");
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
      throw new Error("Unsupported JWE Content Encryption Algorithm");
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

function checkUsage(key: CryptoKey, usage?: KeyUsage): void {
  if (usage && !key.usages.includes(usage)) {
    throw new TypeError(
      `CryptoKey does not support this operation, its usages must include ${usage}.`,
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
  if ((key.algorithm as AesKeyAlgorithm).length !== Number.parseInt(alg.slice(1, 4), 10)) {
    throw new TypeError(`Invalid key size for alg: ${alg}`);
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
    throw new TypeError("CBC key must be of type Uint8Array");
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
    throw new TypeError("CBC key must be of type Uint8Array");
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
    throw new Error("JWE Decryption Failed");
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
    throw new Error("JWE Decryption Failed");
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
    throw new Error("JWE Decryption Failed");
  }
}

let _timingSafeKey: Promise<CryptoKey> | undefined;
function getTimingSafeKey(): Promise<CryptoKey> {
  if (!_timingSafeKey) {
    _timingSafeKey = crypto.subtle.generateKey({ name: "HMAC", hash: "SHA-256" }, false, [
      "sign",
    ]) as Promise<CryptoKey>;
  }
  return _timingSafeKey;
}

async function timingSafeEqual(
  a: Uint8Array<ArrayBuffer>,
  b: Uint8Array<ArrayBuffer>,
): Promise<boolean> {
  if (!(a instanceof Uint8Array)) {
    throw new TypeError("First argument must be a buffer");
  }
  if (!(b instanceof Uint8Array)) {
    throw new TypeError("Second argument must be a buffer");
  }

  const algorithm = { name: "HMAC", hash: "SHA-256" };
  const key = await getTimingSafeKey();

  const aHmac = new Uint8Array(await crypto.subtle.sign(algorithm, key, a));
  const bHmac = new Uint8Array(await crypto.subtle.sign(algorithm, key, b));

  let out = 0;
  let i = -1;
  while (++i < 32) {
    out |= aHmac[i]! ^ bHmac[i]!;
  }

  return out === 0;
}

function writeUInt32BE(buf: Uint8Array<ArrayBuffer>, value: number, offset?: number): void {
  if (value < 0 || value >= 2 ** 32) {
    throw new RangeError(`value must be >= 0 and <= ${2 ** 32 - 1}. Received ${value}`);
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
