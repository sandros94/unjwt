import { textEncoder } from "unsecure/utils";
import type {
  JWK_oct,
  JWKMetadata,
  DeriveKeyOptions,
  DeriveKeyReturn,
  JWK_PBES2,
  DeriveJWKOptions,
  DeriveJWKReturn,
} from "../types/index.ts";
import { assertPlainObject } from "../../utils/guards.ts";
import { PBES2_ALGORITHMS } from "../../utils/algorithms.ts";
import { JWTError } from "../../error.ts";
import { keyToJWK, assertPBES2Salt, assertPBES2Count, deriveKeyPBES2 } from "../_crypto/index.ts";
import { innerKeyWrapAlg } from "../_crypto/_key-algorithm.ts";
import {
  assertNoReservedJWKParams,
  assertKidOption,
  withGeneratedKid,
  requestedKeyOps,
  withKeyOps,
} from "./_internal/members.ts";

/**
 * Derives an AES-KW key from a password with PBKDF2 per PBES2 (RFC 7518 §4.8).
 *
 * @param options
 *   - `alg` — a PBES2 algorithm; any other throws `ERR_JWK_UNSUPPORTED`.
 *   - `salt` — PBKDF2 salt (`p2s`), at least 8 octets (RFC 7518 §4.8.1.1).
 *   - `iterations` — PBKDF2 count (`p2c`), an integer of at least 1000 (RFC 7518 §4.8.1.2);
 *     anything else throws `ERR_INVALID_OPTION`.
 *   - `keyUsage?` — defaults to `["wrapKey", "unwrapKey"]`.
 *   - `extractable?` — defaults to `false`; ignored when `toJWK` is set.
 *   - `toJWK?` — return a `JWK_oct` carrying the inner AES-KW `alg` instead of a `CryptoKey`.
 */
export async function deriveKeyFromPassword<TOptions extends DeriveKeyOptions>(
  password: string | Uint8Array<ArrayBuffer>,
  options: TOptions,
): Promise<DeriveKeyReturn<TOptions, TOptions["alg"]>>;
export async function deriveKeyFromPassword(
  password: string | Uint8Array<ArrayBuffer>,
  options: DeriveKeyOptions,
): Promise<CryptoKey | JWK_oct> {
  assertPlainObject(options, "options");
  if (typeof password !== "string" && !(password instanceof Uint8Array)) {
    throw new JWTError('"password" must be a string or a Uint8Array.', "ERR_INVALID_OPTION");
  }
  const { alg, salt, iterations, extractable, keyUsage } = options;
  assertPBES2Algorithm(alg);
  const exportToJWK = options.toJWK !== undefined && options.toJWK;

  const saltBytes = typeof salt === "string" ? textEncoder.encode(salt) : salt;
  assertPBES2Salt(saltBytes, '"salt"');
  assertPBES2Count(iterations, '"iterations"');

  const passwordBytes = typeof password === "string" ? textEncoder.encode(password) : password;

  const derivedBytes = await deriveKeyPBES2(saltBytes, alg, iterations, passwordBytes);

  const wrappingAlg = innerKeyWrapAlg(alg);
  const defaultUsages: KeyUsage[] = ["wrapKey", "unwrapKey"];
  const finalUsages = keyUsage ?? defaultUsages;
  const finalExtractable = exportToJWK ? true : extractable === true;

  const derivedKey = await crypto.subtle.importKey(
    "raw",
    derivedBytes,
    { name: "AES-KW" },
    finalExtractable,
    finalUsages,
  );

  if (exportToJWK) {
    const jwk = await keyToJWK<JWK_oct>(derivedKey);
    return withKeyOps(
      { ...jwk, alg: wrappingAlg, kty: "oct" },
      requestedKeyOps(options, derivedKey),
    );
  }

  return derivedKey;
}

/**
 * Derives a `JWK_oct` from a password per PBES2 (RFC 7518 §4.8); its `alg` is the inner AES-KW
 * variant and its `kid` the caller's, none with `kid: false`, or else its RFC 7638 thumbprint.
 *
 * @param options
 *   - `alg` (PBES2 only, else `ERR_JWK_UNSUPPORTED`), `salt` (at least 8 octets), `iterations`
 *     (integer of at least 1000, else `ERR_INVALID_OPTION`), `keyUsage?` (default
 *     `["wrapKey", "unwrapKey"]`).
 *   - `kid?` — a string set verbatim or `false` for no `kid`, either skipping the thumbprint
 *     digest; anything else throws `ERR_INVALID_OPTION`.
 *   - JWK metadata (`use`, `x5c`, `x5t`, `x5t#S256`, `x5u`) is merged onto the result;
 *     `alg`, `kty`, `key_ops`, `ext` and key-material members are reserved (`ERR_INVALID_OPTION`).
 */
export async function deriveJWKFromPassword<
  TAlg extends JWK_PBES2,
  Kid extends string | false = string,
>(
  password: string | Uint8Array<ArrayBuffer>,
  options: DeriveJWKOptions<TAlg, Kid> & Omit<JWKMetadata, "kid">,
): Promise<DeriveJWKReturn<TAlg, Kid>>;
export async function deriveJWKFromPassword(
  password: string | Uint8Array<ArrayBuffer>,
  options: DeriveJWKOptions & Omit<JWKMetadata, "kid">,
): Promise<JWK_oct> {
  assertPlainObject(options, "options");
  const {
    alg,
    salt,
    iterations,
    keyUsage,
    kid: kidOption,
    extractable: _extractable,
    toJWK: _toJWK,
    ...jwkParams
  } = options as DeriveKeyOptions & Omit<JWKMetadata, "kid"> & { kid?: string | false };
  assertNoReservedJWKParams(jwkParams);
  const kid = assertKidOption(kidOption);
  const result = await deriveKeyFromPassword(password, {
    alg,
    salt,
    iterations,
    keyUsage,
    toJWK: true,
  });
  return { ...jwkParams, ...(await withGeneratedKid(kid, result)) };
}

function assertPBES2Algorithm(alg: unknown): void {
  const pbes2: readonly string[] = PBES2_ALGORITHMS;
  if (typeof alg === "string" && pbes2.includes(alg)) return;
  throw new JWTError(
    `Password derivation is defined for ${PBES2_ALGORITHMS.join(", ")}, not ${String(alg)}.`,
    "ERR_JWK_UNSUPPORTED",
  );
}
