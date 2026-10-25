import { textEncoder } from "unsecure/utils";
import { base64UrlStringify } from "../../utils/base64.ts";

import { concatUint8Arrays } from "../../utils/array.ts";
import { JWTError } from "../../error.ts";
import type { JWK_PBES2 } from "../types/index.ts";
import {
  aesBitsOf,
  checkKeyUsage,
  innerKeyWrapAlg,
  isAlgorithm,
  pbes2HashOf,
  unusableKey,
} from "./_key-algorithm.ts";
import { aesKwWrap, aesKwUnwrap } from "./_aes.ts";

/** RFC 7518 §4.8.1.2 — the floor every PBES2 `p2c` is held to. */
export const DEFAULT_PBES2_MIN_ITERATIONS = 1000;

/** The PBKDF2 work a PBES2 token is minted with when the caller names none. */
export const DEFAULT_PBES2_ITERATIONS = 600_000;

/** The `p2c` ceiling one unwrap accepts by default: the cost a producer mints with. */
export const DEFAULT_PBES2_MAX_ITERATIONS: number = DEFAULT_PBES2_ITERATIONS;

/** RFC 7518 §4.8.1 — mint-side `p2s`/`p2c` stay within the unwrap bounds; else `ERR_INVALID_OPTION`. */
export function assertPBES2Params(params: {
  p2s: Uint8Array<ArrayBuffer> | undefined;
  p2c: number | undefined;
}): void {
  const { p2s, p2c } = params;
  if (p2s !== undefined) assertPBES2Salt(p2s, '"p2s"');
  if (p2c === undefined) return;
  assertPBES2Count(p2c, '"p2c"');
  if (p2c > DEFAULT_PBES2_MAX_ITERATIONS) {
    throw new JWTError(
      `"p2c" must be between ${DEFAULT_PBES2_MIN_ITERATIONS} and ${DEFAULT_PBES2_MAX_ITERATIONS} iterations (got ${p2c}).`,
      "ERR_INVALID_OPTION",
    );
  }
}

/** RFC 7518 §4.8.1.1 — a PBES2 salt input is at least 8 octets. */
export function assertPBES2Salt(salt: unknown, name: string): void {
  if (salt instanceof Uint8Array && salt.length >= 8) return;
  throw new JWTError(`${name} must be 8 or more octets.`, "ERR_INVALID_OPTION");
}

/** RFC 7518 §4.8.1.2 — a PBES2 iteration count is an integer of at least 1000. */
export function assertPBES2Count(count: unknown, name: string): asserts count is number {
  if (typeof count !== "number" || !Number.isInteger(count) || count < 1) {
    throw new JWTError(`${name} must be a positive integer.`, "ERR_INVALID_OPTION");
  }
  if (count < DEFAULT_PBES2_MIN_ITERATIONS) {
    throw new JWTError(
      `${name} must be at least ${DEFAULT_PBES2_MIN_ITERATIONS} iterations (got ${count}).`,
      "ERR_INVALID_OPTION",
    );
  }
}

export async function pbes2Wrap(
  alg: JWK_PBES2,
  key: CryptoKey | Uint8Array<ArrayBuffer>,
  cek: Uint8Array<ArrayBuffer>,
  p2c: number,
  p2s: Uint8Array<ArrayBuffer>,
): Promise<{ encryptedKey: Uint8Array<ArrayBuffer>; p2c: number; p2s: string }> {
  const derived = await deriveKey(p2s, alg, p2c, key);
  const encryptedKey = await aesKwWrap(innerKeyWrapAlg(alg), derived, cek);
  return { encryptedKey, p2c, p2s: base64UrlStringify(p2s) };
}

/** The `p2c` bounds one PBES2 unwrap accepts, defaulting to the `DEFAULT_PBES2_*` limits. */
export function assertPBES2Iterations(
  p2c: number,
  bounds: { minIterations?: number; maxIterations?: number },
): void {
  const {
    minIterations = DEFAULT_PBES2_MIN_ITERATIONS,
    maxIterations = DEFAULT_PBES2_MAX_ITERATIONS,
  } = bounds;
  if (p2c < minIterations) {
    throw new JWTError(
      `PBES2 "p2c" below the minimum of ${minIterations} iterations (got ${p2c}).`,
      "ERR_JWE_INVALID",
    );
  }
  if (p2c > maxIterations) {
    throw new JWTError(
      `PBES2 "p2c" above the maximum of ${maxIterations} iterations (got ${p2c}).`,
      "ERR_JWE_INVALID",
    );
  }
}

export async function pbes2Unwrap(
  alg: JWK_PBES2,
  key: CryptoKey | Uint8Array<ArrayBuffer>,
  encryptedKey: Uint8Array<ArrayBuffer>,
  p2c: number,
  p2s: Uint8Array<ArrayBuffer>,
  minIterations?: number,
  maxIterations?: number,
): Promise<Uint8Array<ArrayBuffer>> {
  assertPBES2Iterations(p2c, { minIterations, maxIterations });
  const derived = await deriveKey(p2s, alg, p2c, key);
  return aesKwUnwrap(innerKeyWrapAlg(alg), derived, encryptedKey);
}

export async function deriveKey(
  p2s: Uint8Array<ArrayBuffer>,
  alg: JWK_PBES2,
  p2c: number,
  key: CryptoKey | Uint8Array<ArrayBuffer>,
): Promise<Uint8Array<ArrayBuffer>> {
  assertPBES2Salt(p2s, '"p2s"');
  if (p2c === undefined || p2c < 1) {
    throw new JWTError(
      "PBES2 Iteration Count Parameter must be a positive integer",
      "ERR_INVALID_OPTION",
    );
  }

  const salt = concatUint8Arrays(textEncoder.encode(alg), new Uint8Array([0]), p2s);
  const keylen = aesBitsOf(innerKeyWrapAlg(alg));
  const subtleAlg = {
    hash: pbes2HashOf(alg),
    iterations: p2c,
    name: "PBKDF2",
    salt,
  };

  const cryptoKey = await getPBKDF2CryptoKey(key, alg);

  return new Uint8Array(await crypto.subtle.deriveBits(subtleAlg, cryptoKey, keylen));
}

export function checkPBES2CryptoKey(key: CryptoKey, alg: JWK_PBES2, usage?: KeyUsage): void {
  if (!isAlgorithm(key.algorithm, "PBKDF2")) {
    throw unusableKey("PBKDF2");
  }
  checkKeyUsage(key, usage);
}

async function getPBKDF2CryptoKey(
  key: CryptoKey | Uint8Array<ArrayBuffer>,
  alg: JWK_PBES2,
  options: { usage?: KeyUsage; extractable?: boolean } = {},
): Promise<CryptoKey> {
  const { extractable = false, usage = "deriveBits" } = options;
  if (key instanceof Uint8Array) {
    return crypto.subtle.importKey("raw", key, "PBKDF2", extractable, [usage]);
  }
  checkPBES2CryptoKey(key, alg, usage);
  return key;
}
