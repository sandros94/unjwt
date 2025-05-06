import { textEncoder, concatUint8Arrays } from "../utils";
import { uint32be } from "./buffer_utils.js";
import { checkEncCryptoKey } from "./crypto_key";

function lengthAndInput(input: Uint8Array) {
  return concatUint8Arrays(uint32be(input.length), input);
}

async function concatKdf(secret: Uint8Array, bits: number, value: Uint8Array) {
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

export async function deriveECDHESKey(
  publicKey: CryptoKey,
  privateKey: CryptoKey,
  algorithm: string,
  keyLength: number,
  apu: Uint8Array = new Uint8Array(0),
  apv: Uint8Array = new Uint8Array(0),
) {
  checkEncCryptoKey(publicKey, "ECDH");
  checkEncCryptoKey(privateKey, "ECDH", "deriveBits");

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
          Number.parseInt(
            (publicKey.algorithm as EcKeyAlgorithm).namedCurve.slice(-3),
            10,
          ) / 8,
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

export function allowed(key: CryptoKey) {
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

export async function digest(
  algorithm: "sha256" | "sha384" | "sha512",
  data: Uint8Array,
): Promise<Uint8Array> {
  const subtleDigest = `SHA-${algorithm.slice(-3)}`;
  return new Uint8Array(await crypto.subtle.digest(subtleDigest, data));
}
