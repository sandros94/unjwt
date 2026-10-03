import { textEncoder } from "unsecure/utils";
import { base64UrlStringify } from "../utils/base64";

import { concatUint8Arrays } from "../utils";
import { JWTError } from "../error";
import { aesKwWrap, aesKwUnwrap } from "./_aes";

/** RFC 7518 §4.8.1.2 — the floor every PBES2 `p2c` is held to. */
export const DEFAULT_PBES2_MIN_ITERATIONS = 1000;

/** The PBKDF2 work a PBES2 token is minted with when the caller names none. */
export const DEFAULT_PBES2_ITERATIONS = 600_000;

/**
 * The ceiling one unwrap accepts unless the caller raises `maxIterations`: the
 * cost a producer mints by default, and no more, so a token cannot claim more
 * work than the library itself would spend writing one.
 */
export const DEFAULT_PBES2_MAX_ITERATIONS: number = DEFAULT_PBES2_ITERATIONS;

/**
 * RFC 7518 §4.8.1 — the PBES2 parameters a token is minted with. `p2s` is at
 * least 8 octets and `p2c` a positive integer inside the bounds the unwrap side
 * enforces, so the library never mints a token it would itself refuse to open.
 * A value outside them is caller input, not key material: `ERR_INVALID_OPTION`.
 */
export function assertPBES2Params(params: {
  p2s: Uint8Array<ArrayBuffer> | undefined;
  p2c: number | undefined;
}): void {
  const { p2s, p2c } = params;
  if (p2s !== undefined && (!(p2s instanceof Uint8Array) || p2s.length < 8)) {
    throw new JWTError(`"p2s" must be 8 or more octets (RFC 7518 §4.8.1.1).`, "ERR_INVALID_OPTION");
  }
  if (p2c === undefined) return;
  if (typeof p2c !== "number" || !Number.isInteger(p2c) || p2c < 1) {
    throw new JWTError('"p2c" must be a positive integer.', "ERR_INVALID_OPTION");
  }
  if (p2c < DEFAULT_PBES2_MIN_ITERATIONS || p2c > DEFAULT_PBES2_MAX_ITERATIONS) {
    throw new JWTError(
      `"p2c" must be between ${DEFAULT_PBES2_MIN_ITERATIONS} and ${DEFAULT_PBES2_MAX_ITERATIONS} iterations (got ${p2c}).`,
      "ERR_INVALID_OPTION",
    );
  }
}

export async function pbes2Wrap(
  alg: string,
  key: CryptoKey | Uint8Array<ArrayBuffer>,
  cek: Uint8Array<ArrayBuffer>,
  p2c: number,
  p2s: Uint8Array<ArrayBuffer>,
): Promise<{ encryptedKey: Uint8Array<ArrayBuffer>; p2c: number; p2s: string }> {
  const derived = await deriveKey(p2s, alg, p2c, key);
  const encryptedKey = await aesKwWrap(alg.slice(-6), derived, cek);
  return { encryptedKey, p2c, p2s: base64UrlStringify(p2s) };
}

/**
 * The `p2c` bounds one PBES2 unwrap accepts: `minIterations` (default 1000,
 * RFC 7518 §4.8.1.2) to `maxIterations` (default {@link DEFAULT_PBES2_MAX_ITERATIONS}).
 */
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
  alg: string,
  key: CryptoKey | Uint8Array<ArrayBuffer>,
  encryptedKey: Uint8Array<ArrayBuffer>,
  p2c: number,
  p2s: Uint8Array<ArrayBuffer>,
  minIterations?: number,
  maxIterations?: number,
): Promise<Uint8Array<ArrayBuffer>> {
  assertPBES2Iterations(p2c, { minIterations, maxIterations });
  const derived = await deriveKey(p2s, alg, p2c, key);
  return aesKwUnwrap(alg.slice(-6), derived, encryptedKey);
}

export async function deriveKey(
  p2s: Uint8Array<ArrayBuffer>,
  alg: string,
  p2c: number,
  key: CryptoKey | Uint8Array<ArrayBuffer>,
): Promise<Uint8Array<ArrayBuffer>> {
  if (!(p2s instanceof Uint8Array) || p2s.length < 8) {
    throw new JWTError("PBES2 Salt Input must be 8 or more octets", "ERR_INVALID_OPTION");
  }
  if (p2c === undefined || p2c < 1) {
    throw new JWTError(
      "PBES2 Iteration Count Parameter must be a positive integer",
      "ERR_INVALID_OPTION",
    );
  }

  const salt = concatUint8Arrays(textEncoder.encode(alg), new Uint8Array([0]), p2s);
  const keylen = Number.parseInt(alg.slice(13, 16), 10);
  const subtleAlg = {
    hash: `SHA-${alg.slice(8, 11)}`,
    iterations: p2c,
    name: "PBKDF2",
    salt,
  };

  const cryptoKey = await getPBKDF2CryptoKey(key, alg);

  return new Uint8Array(await crypto.subtle.deriveBits(subtleAlg, cryptoKey, keylen));
}

export function checkPBES2CryptoKey(key: CryptoKey, alg: string, usage?: KeyUsage): void {
  if (!isAlgorithm(key.algorithm, "PBKDF2")) {
    throw unusable("PBKDF2");
  }
  checkUsage(key, usage);
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

async function getPBKDF2CryptoKey(
  key: CryptoKey | Uint8Array<ArrayBuffer>,
  alg: string,
  options: { usage?: KeyUsage; extractable?: boolean } = {},
): Promise<CryptoKey> {
  const { extractable = false, usage = "deriveBits" } = options;
  if (key instanceof Uint8Array) {
    return crypto.subtle.importKey("raw", key, "PBKDF2", extractable, [usage]);
  }
  checkPBES2CryptoKey(key, alg, usage);
  return key;
}
