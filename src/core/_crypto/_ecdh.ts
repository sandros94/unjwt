import { textEncoder } from "unsecure/utils";

import { concatUint8Arrays, uint32be } from "../../utils/array.ts";
import { JWTError } from "../../error.ts";
import type { ContentEncryptionAlgorithm, JWK_ECDH_ES } from "../types/index.ts";
import {
  aesBitsOf,
  checkKeyUsage,
  innerKeyWrapAlg,
  namedCurveOf,
  unusableKey,
} from "./_key-algorithm.ts";
import { bitLengthCEK } from "./_aes.ts";

/** RFC 7518 §4.6.2 — the AlgorithmID of the Concat KDF: `enc` for direct agreement, `alg` with key wrapping, or whatever a caller of `deriveSharedSecret` names. */
export type ConcatKdfAlgorithm = ContentEncryptionAlgorithm | JWK_ECDH_ES;

export async function deriveECDHESKey(
  publicKey: CryptoKey,
  privateKey: CryptoKey,
  algorithm: ConcatKdfAlgorithm,
  keyLength: number,
  apu: Uint8Array<ArrayBuffer> = new Uint8Array(0),
  apv: Uint8Array<ArrayBuffer> = new Uint8Array(0),
): Promise<Uint8Array<ArrayBuffer>> {
  checkECDHCryptoKey(publicKey);
  checkECDHCryptoKey(privateKey, "deriveBits");

  const value = concatUint8Arrays(
    lengthAndInput(textEncoder.encode(algorithm)),
    lengthAndInput(apu),
    lengthAndInput(apv),
    uint32be(keyLength),
  );

  const length: number =
    publicKey.algorithm.name === "X25519"
      ? 256
      : Math.ceil(Number.parseInt((namedCurveOf(publicKey.algorithm) ?? "").slice(-3), 10) / 8) <<
        3;

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

/** RFC 7518 §4.6.2 — the Concat KDF output length: the CEK size, or the AES-KW key size. */
export function ecdhDerivedBits(
  alg: JWK_ECDH_ES,
  enc: ContentEncryptionAlgorithm | undefined,
): number {
  if (alg !== "ECDH-ES") return aesBitsOf(innerKeyWrapAlg(alg));
  if (enc) return bitLengthCEK(enc);
  throw new JWTError('ECDH-ES requires "enc" to derive the key.', "ERR_JWE_INVALID");
}

/** A fresh extractable key pair on the curve of an ECDH-ES recipient key. */
export function generateEphemeralKeyPair(recipientKey: CryptoKey): Promise<CryptoKeyPair> {
  // oxlint-disable-next-line typescript/no-unsafe-type-assertion -- an ECDH-ES recipient key is ECDH or X25519
  return crypto.subtle.generateKey(recipientKey.algorithm as EcKeyAlgorithm, true, ["deriveBits"]);
}

/** RFC 7518 §4.6 / RFC 8037 §3.2 — ECDH-ES runs on P-256, P-384, P-521 or X25519. */
export function assertECDHKeyAllowed(key: CryptoKey): void {
  switch (namedCurveOf(key.algorithm) ?? key.algorithm.name) {
    case "P-256":
    case "P-384":
    case "P-521":
    case "X25519": {
      return;
    }
    default: {
      throw new JWTError(
        "ECDH with the provided key is not allowed or not supported",
        "ERR_JWK_INVALID",
      );
    }
  }
}

export function checkECDHCryptoKey(key: CryptoKey, usage?: KeyUsage): void {
  switch (key.algorithm.name) {
    case "ECDH":
    case "X25519": {
      break;
    }
    default: {
      throw unusableKey("ECDH or X25519");
    }
  }
  checkKeyUsage(key, usage);
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
