import { MAX_PARTY_INFO_BYTES } from "../../_internal/limits.ts";
import { asDecryptionError } from "../../_internal/errors.ts";
import { decodeSegment } from "../../_internal/headers.ts";
import type {
  JWK_ECDH_ES,
  JWK_RSA_ENC,
  JWK_AES_GCM_KW,
  KeyManagementAlgorithm,
  ContentEncryptionAlgorithm,
} from "../../types/index.ts";
import { isCryptoKey } from "../../../utils/guards.ts";
import { JWTError } from "../../../error.ts";
import { aesBitsOf } from "../../_crypto/_key-algorithm.ts";

export function inferAesImportAlgorithm(
  enc: ContentEncryptionAlgorithm | undefined,
  cekLengthBytes: number,
): AesKeyAlgorithm | undefined {
  const bitLength = cekLengthBytes << 3;

  if (enc) {
    if (enc.includes("GCM")) {
      return {
        name: "AES-GCM",
        length: aesBitsOf(enc),
      } satisfies AesKeyAlgorithm;
    }

    if (enc.includes("CBC-HS")) {
      return undefined;
    }
  }

  if (bitLength === 128 || bitLength === 192 || bitLength === 256) {
    return { name: "AES-GCM", length: bitLength } satisfies AesKeyAlgorithm;
  }

  return undefined;
}

/** RFC 3394 §2: AES Key Wrap needs a CEK of two or more whole 64-bit blocks. */
export function assertWrappableCEK(
  cek: Uint8Array<ArrayBuffer>,
  alg: KeyManagementAlgorithm,
): void {
  if (cek.length >= 16 && cek.length % 8 === 0) return;
  throw new JWTError(
    `${alg} wraps a key of 16 or more bytes in whole 8-byte blocks (got ${cek.length}).`,
    "ERR_INVALID_OPTION",
  );
}

/** RFC 7516 §11.5: every unwrap failure is the same `ERR_JWE_DECRYPTION_FAILED`. */
export async function unwrapping<T>(operation: Promise<T>): Promise<T> {
  try {
    return await operation;
  } catch (error) {
    throw asDecryptionError(error);
  }
}

export function assertKeyBytesArg(value: unknown, name: string): void {
  if (value instanceof Uint8Array || isCryptoKey(value)) return;
  throw new JWTError(`"${name}" must be a Uint8Array or a CryptoKey.`, "ERR_INVALID_OPTION");
}

/** RFC 7518 §4.6.1.2: a token's `apu` or `apv` above `MAX_PARTY_INFO_BYTES` is `ERR_JWE_INVALID`. */
export function assertPartyInfoLength(name: "apu" | "apv", bytes: Uint8Array<ArrayBuffer>): void {
  if (bytes.length > MAX_PARTY_INFO_BYTES) {
    throw new JWTError(
      `Invalid JWE: "${name}" must not exceed ${MAX_PARTY_INFO_BYTES} bytes (got ${bytes.length}).`,
      "ERR_JWE_INVALID",
    );
  }
}

export function assertKeyWrapSegmentLength(
  name: "iv" | "tag",
  bytes: Uint8Array<ArrayBuffer>,
  expected: number,
  alg: JWK_AES_GCM_KW,
): void {
  if (bytes.length !== expected) {
    throw new JWTError(
      `Invalid JWE: "${name}" must be ${expected} bytes for ${alg} (got ${bytes.length}).`,
      "ERR_JWE_INVALID",
    );
  }
}

/** RSA-OAEP and ECDH-ES need an asymmetric `CryptoKey`. Raw bytes are `ERR_JWK_INVALID`. */
export function assertCryptoKeyFor(
  alg: JWK_RSA_ENC | JWK_ECDH_ES,
  key: CryptoKey | Uint8Array<ArrayBuffer>,
  role: "wrapping" | "unwrapping",
): asserts key is CryptoKey {
  if (isCryptoKey(key)) return;
  throw new JWTError(`${alg} requires the ${role} key to be a CryptoKey`, "ERR_JWK_INVALID");
}

/** Returns an `unwrapKey` header parameter as bytes, from its base64url header value or as given. */
export function segmentBytes(
  value: string | Uint8Array<ArrayBuffer>,
  name: "p2s" | "iv" | "tag" | "apu" | "apv",
): Uint8Array<ArrayBuffer> {
  return typeof value === "string"
    ? decodeSegment(value, { family: "JWE", what: `"${name}"` })
    : value;
}
