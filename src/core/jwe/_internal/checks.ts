import type { ContentEncryptionAlgorithm, KeyManagementAlgorithm } from "../../types/index.ts";
import { JWTError } from "../../../error.ts";
import { bitLengthCEK, bitLengthIV, bitLengthTag } from "../../_crypto/index.ts";
import { JWE_DIRECT_ALGS } from "./algorithms.ts";

/** RFC 7518 §5: the CEK size is fixed by `enc`. */
export function assertProducerCEK(
  cek: Uint8Array<ArrayBuffer> | undefined,
  enc: ContentEncryptionAlgorithm,
): void {
  if (cek === undefined) return;
  const expected = bitLengthCEK(enc) >> 3;
  if (!(cek instanceof Uint8Array) || cek.length !== expected) {
    throw new JWTError(`"cek" must be ${expected} bytes for ${enc}.`, "ERR_INVALID_OPTION");
  }
}

/** RFC 7518 §5.2 / §5.3: the content IV length is fixed by `enc`. */
export function assertProducerIV(
  iv: Uint8Array<ArrayBuffer> | undefined,
  enc: ContentEncryptionAlgorithm,
): void {
  if (iv === undefined) return;
  const expected = bitLengthIV(enc) >> 3;
  if (!(iv instanceof Uint8Array) || iv.length !== expected) {
    throw new JWTError(
      `"contentEncryptionIV" must be ${expected} bytes for ${enc}.`,
      "ERR_INVALID_OPTION",
    );
  }
}

/** RFC 7516 §5.2 step 6: direct key agreement has an empty encrypted key. */
export function checkJWEDirectEncryptedKey(
  alg: KeyManagementAlgorithm,
  encryptedKey: string | undefined,
): JWTError | undefined {
  if (!JWE_DIRECT_ALGS.has(alg) || !encryptedKey) return undefined;
  return new JWTError(`Invalid JWE: Encrypted key must be empty for ${alg}.`, "ERR_JWE_INVALID");
}

/** RFC 7518 §5.2 / §5.3: the IV and authentication tag sizes are fixed by `enc`. */
export function checkJWEContentSegments(
  enc: ContentEncryptionAlgorithm,
  iv: Uint8Array<ArrayBuffer>,
  tag: Uint8Array<ArrayBuffer>,
): JWTError | undefined {
  const ivBytes = bitLengthIV(enc) >> 3;
  if (iv.length !== ivBytes) {
    return new JWTError(
      `Invalid JWE: Initialization vector must be ${ivBytes} bytes for ${enc} (got ${iv.length}).`,
      "ERR_JWE_INVALID",
    );
  }
  const tagBytes = bitLengthTag(enc) >> 3;
  if (tag.length !== tagBytes) {
    return new JWTError(
      `Invalid JWE: Authentication tag must be ${tagBytes} bytes for ${enc} (got ${tag.length}).`,
      "ERR_JWE_INVALID",
    );
  }
  return undefined;
}

/** RFC 7516 §4.1.3: compression is not supported. */
export function checkJWEZip(header: object | undefined): JWTError | undefined {
  if (!header || !Object.hasOwn(header, "zip")) return undefined;
  return new JWTError("Invalid JWE: compression is not supported.", "ERR_JWE_INVALID");
}

export function assertNoZipOption(header: object | undefined, tier: string): void {
  if (!header || !Object.hasOwn(header, "zip")) return;
  throw new JWTError(
    `JWE compression ("zip") in the ${tier} header is not supported.`,
    "ERR_INVALID_OPTION",
  );
}

/** RFC 7516 §4.1.13: `crit` must be integrity protected. */
export function checkJWEUnprotectedCrit(header: object | undefined): JWTError | undefined {
  if (!header || !Object.hasOwn(header, "crit")) return undefined;
  return new JWTError('Invalid JWE: "crit" must be integrity protected.', "ERR_JWE_INVALID");
}
