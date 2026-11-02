import { copyJsonObject } from "../_internal/errors.ts";
import type {
  JWK,
  JWK_Public,
  JWK_Asymmetric,
  ToPublicJWKReturn,
  JWKMetadata,
} from "../types/index.ts";
import { isAsymmetricJWK, isCryptoKey, isJWK, isPublicJWK } from "../../utils/guards.ts";
import { JWTError } from "../../error.ts";
import { keyToJWK } from "../_crypto/index.ts";
import { assertNoReservedJWKParams } from "./_internal/members.ts";

/**
 * Exports an extractable `CryptoKey` as a JWK and copies the `jwkParams` metadata onto it.
 * The JWK has no `ext` or `key_ops` member.
 *
 * The `alg` is the one Web Crypto exports: an AES-GCM key exports as `A128GCM`, even one meant
 * for `A128GCMKW`. Use `generateJWK` for a key wrapping JWK.
 *
 * @throws `ERR_INVALID_OPTION` if `key` is not a `CryptoKey`, or `jwkParams` holds a non-JSON value
 *   or sets `alg`, `kty`, `key_ops`, `ext` or a key material member.
 * @throws `ERR_JWK_INVALID` if the key is not extractable.
 */
export async function exportJWK<T extends JWK = JWK>(
  key: CryptoKey,
  jwkParams?: JWKMetadata,
): Promise<T> {
  if (!isCryptoKey(key)) {
    throw new JWTError("exportJWK expects a CryptoKey.", "ERR_INVALID_OPTION");
  }
  if (!key.extractable) {
    throw new JWTError(
      "A non-extractable CryptoKey cannot be exported as a JWK.",
      "ERR_JWK_INVALID",
    );
  }
  const exportedJwk = await keyToJWK<T>(key);
  if (jwkParams) {
    const extraParams = copyJsonObject(jwkParams, {
      code: "ERR_INVALID_OPTION",
      message: "JWK parameters must hold only JSON values.",
    });
    assertNoReservedJWKParams(extraParams);
    return { ...exportedJwk, ...extraParams };
  }
  return exportedJwk;
}

/**
 * Returns the public half of an asymmetric JWK.
 *
 * @param jwk An asymmetric JWK (EC, OKP, RSA), private or public.
 * @throws `ERR_JWK_INVALID` if `jwk` is not an asymmetric JWK, holds a non-JSON value, or lacks the public members of its key type.
 * @returns A copy without the private members. `key_ops` keeps the public operations only (`sign` becomes `verify`).
 */
export function toPublicJWK<T extends JWK_Asymmetric>(jwk: T): ToPublicJWKReturn<T>;
export function toPublicJWK(jwk: JWK_Asymmetric): JWK_Public {
  if (!isAsymmetricJWK(jwk)) {
    throw new JWTError(
      isJWK(jwk) ? "An oct JWK has no public half." : "toPublicJWK expects an asymmetric JWK.",
      "ERR_JWK_INVALID",
    );
  }
  const copy: Record<string, unknown> = copyJsonObject(
    { ...jwk },
    { code: "ERR_JWK_INVALID", message: "A JWK must hold only JSON values." },
  );
  const {
    d: _d,
    p: _p,
    q: _q,
    dp: _dp,
    dq: _dq,
    qi: _qi,
    oth: _oth,
    k: _k,
    key_ops,
    ...publicMembers
  } = copy;
  const publicKey =
    key_ops === undefined ? publicMembers : { ...publicMembers, key_ops: publicKeyOps(key_ops) };
  if (!isPublicJWK(publicKey)) {
    throw new JWTError(
      `${jwk.kty} JWK lacks the public members of its key type.`,
      "ERR_JWK_INVALID",
    );
  }
  return publicKey;
}

const PUBLIC_KEY_OPS = new Map<string, KeyUsage>([
  ["sign", "verify"],
  ["verify", "verify"],
  ["decrypt", "encrypt"],
  ["encrypt", "encrypt"],
  ["unwrapKey", "wrapKey"],
  ["wrapKey", "wrapKey"],
]);

/** The public operations of a private half's `key_ops`. ECDH's `deriveBits` and `deriveKey` have no public counterpart. */
function publicKeyOps(keyOps: unknown): KeyUsage[] {
  if (!Array.isArray(keyOps)) return [];
  const ops: KeyUsage[] = [];
  for (const op of keyOps) {
    const publicOp = typeof op === "string" ? PUBLIC_KEY_OPS.get(op) : undefined;
    if (publicOp !== undefined && !ops.includes(publicOp)) ops.push(publicOp);
  }
  return ops;
}
