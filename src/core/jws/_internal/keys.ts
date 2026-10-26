import type { JWSAlgorithm, JWKAlgorithm, JWK_RSA_SIGN, JWK_RSA_PSS } from "../../types/index.ts";
import { JWTError } from "../../../error.ts";
import { jwsHashOf, modulusLengthOf } from "../../_crypto/_key-algorithm.ts";
import { assertOctKeyLength } from "../../_crypto/index.ts";
import { stringKeyError } from "../../_internal/keys.ts";
import { asJWTError } from "../../_internal/errors.ts";

/** Bytes become an HMAC key, for `HS*` only. RSA needs `modulusLength ≥ 2048` (RFC 7518 §3.3 / §3.5). */
export async function resolveSigningKey(
  alg: JWSAlgorithm,
  key: CryptoKey | Uint8Array<ArrayBuffer>,
  usage: "sign" | "verify",
): Promise<CryptoKey> {
  if (key instanceof Uint8Array) {
    if (alg !== "HS256" && alg !== "HS384" && alg !== "HS512") {
      throw new JWTError(`${alg} needs an asymmetric key, not raw bytes.`, "ERR_JWK_INVALID");
    }
    assertOctKeyLength(key, alg);
    return crypto.subtle.importKey("raw", key, { name: "HMAC", hash: jwsHashOf(alg) }, false, [
      usage,
    ]);
  }
  if (RSA_SIGNATURE_ALGORITHMS.has(alg)) {
    const modulusLength = modulusLengthOf(key.algorithm);
    if (typeof modulusLength !== "number" || modulusLength < 2048) {
      throw new JWTError(
        `${alg} requires a key modulusLength of at least 2048 bits`,
        "ERR_JWK_INVALID",
      );
    }
  }
  return key;
}

export function assertNotStringKey<K>(key: K): asserts key is Exclude<K, string> {
  if (typeof key === "string") throw stringKeyError();
}

export function asKeyUsageError(error: unknown, alg: JWKAlgorithm): JWTError {
  return asJWTError(error, { code: "ERR_JWK_INVALID", message: `Key is not usable for ${alg}.` });
}

/** RFC 7518 §3.3 / §3.5: the signature algorithms bound to an RSA modulus. */
const RSA_SIGNATURE_ALGORITHMS: ReadonlySet<string> = /* @__PURE__ */ new Set<
  JWK_RSA_SIGN | JWK_RSA_PSS
>(["RS256", "RS384", "RS512", "PS256", "PS384", "PS512"]);
