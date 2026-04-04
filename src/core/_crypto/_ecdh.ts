import { textEncoder, concatUint8Arrays } from "../utils";

export async function deriveECDHESKey(
  publicKey: CryptoKey,
  privateKey: CryptoKey,
  algorithm: string,
  keyLength: number,
  apu: Uint8Array<ArrayBuffer> = new Uint8Array(0),
  apv: Uint8Array<ArrayBuffer> = new Uint8Array(0),
): Promise<Uint8Array<ArrayBuffer>> {
  checkECDHCryptoKey(publicKey, "ECDH");
  checkECDHCryptoKey(privateKey, "ECDH", "deriveBits");

  const value = concatUint8Arrays(
    lengthAndInput(textEncoder.encode(algorithm)),
    lengthAndInput(apu),
    lengthAndInput(apv),
    uint32be(keyLength),
  );

  const length: number =
    publicKey.algorithm.name === "X25519"
      ? 256
      : Math.ceil(
          Number.parseInt((publicKey.algorithm as EcKeyAlgorithm).namedCurve.slice(-3), 10) / 8,
        ) << 3;

  const sharedSecret = new Uint8Array(
    await crypto.subtle.deriveBits(
      {
        name: publicKey.algorithm.name,
        public: publicKey,
      },
      privateKey,
      length,
    ),
  );

  return concatKdf(sharedSecret, keyLength, value);
}

export function isECDHKeyAllowed(key: CryptoKey): boolean {
  switch ((key.algorithm as EcKeyAlgorithm).namedCurve) {
    case "P-256":
    case "P-384":
    case "P-521": {
      return true;
    }
    default: {
      return key.algorithm.name === "X25519";
    }
  }
}

export function checkECDHCryptoKey(key: CryptoKey, alg: string, usage?: KeyUsage): void {
  switch (key.algorithm.name) {
    case "ECDH":
    case "X25519": {
      break;
    }
    default: {
      throw unusable("ECDH or X25519");
    }
  }
  checkUsage(key, usage);
}

// --- Internal helpers ---

function unusable(name: string | number, prop = "algorithm.name") {
  return new TypeError(`CryptoKey does not support this operation, its ${prop} must be ${name}`);
}

function checkUsage(key: CryptoKey, usage?: KeyUsage): void {
  if (usage && !key.usages.includes(usage)) {
    throw new TypeError(
      `CryptoKey does not support this operation, its usages must include ${usage}.`,
    );
  }
}

async function concatKdf(
  secret: Uint8Array<ArrayBuffer>,
  bits: number,
  value: Uint8Array<ArrayBuffer>,
): Promise<Uint8Array<ArrayBuffer>> {
  const iterations = Math.ceil((bits >> 3) / 32);
  const res = new Uint8Array(iterations * 32);
  for (let iter = 0; iter < iterations; iter++) {
    const buf = new Uint8Array(4 + secret.length + value.length);
    buf.set(uint32be(iter + 1));
    buf.set(secret, 4);
    buf.set(value, 4 + secret.length);
    res.set(await digest("sha256", buf), iter * 32);
  }
  return res.slice(0, bits >> 3);
}

function lengthAndInput(input: Uint8Array<ArrayBuffer>): Uint8Array<ArrayBuffer> {
  return concatUint8Arrays(uint32be(input.length), input);
}

async function digest(
  algorithm: "sha256" | "sha384" | "sha512",
  data: Uint8Array<ArrayBuffer>,
): Promise<Uint8Array<ArrayBuffer>> {
  return new Uint8Array(await crypto.subtle.digest(`SHA-${algorithm.slice(-3)}`, data));
}

function writeUInt32BE(buf: Uint8Array<ArrayBuffer>, value: number, offset?: number): void {
  if (value < 0 || value >= 2 ** 32) {
    throw new RangeError(`value must be >= 0 and <= ${2 ** 32 - 1}. Received ${value}`);
  }
  buf.set([value >>> 24, value >>> 16, value >>> 8, value & 0xff], offset);
}

function uint32be(value: number): Uint8Array<ArrayBuffer> {
  const buf = new Uint8Array(4);
  writeUInt32BE(buf, value, 0);
  return buf;
}
