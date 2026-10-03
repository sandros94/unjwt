import { base64UrlStringify } from "../utils/base64";

import type { JWK } from "../types";
import { isCryptoKey } from "../utils/guards";
import { JWTError } from "../error";

/**
 * Import a JWK as a `CryptoKey` for the algorithm its `alg` names.
 *
 * The operation decides which usages the key needs; a JWK's `key_ops` can only
 * narrow that set (RFC 7517 §4.3), never widen it, and a `key_ops` permitting
 * none of them is a key the caller cannot use for this operation. `ext` works
 * the same way: private key material is non-extractable unless the caller asks
 * otherwise, and `ext: false` lowers extractability but never raises it.
 *
 * Key material WebCrypto itself refuses fails as `ERR_JWK_INVALID`, carrying the
 * originating `DOMException` as its `cause`.
 */
export async function jwkTokey(
  jwk: JWK,
  options: { extractable?: boolean } = {},
): Promise<CryptoKey> {
  if (!jwk.alg) {
    throw new JWTError(
      '"alg" argument is required when "jwk.alg" is not present',
      "ERR_JWK_INVALID",
    );
  }

  const { algorithm, keyUsages } = subtleMapping(jwk);

  const isPrivate = "d" in jwk && jwk.d !== undefined;
  const extractable = jwk.ext === false ? false : (options.extractable ?? !isPrivate);

  try {
    return await crypto.subtle.importKey(
      "jwk",
      jwk,
      algorithm,
      extractable,
      permittedUsages(jwk, keyUsages),
    );
  } catch (error) {
    // WebCrypto reports a JWK it cannot import — a curve that contradicts the
    // `alg`, a truncated coordinate, an `e` it refuses — as a `DOMException`.
    if (error instanceof JWTError) throw error;
    throw new JWTError(`Key is not usable for ${jwk.alg}.`, "ERR_JWK_INVALID", error);
  }
}

export async function keyToJWK<T extends JWK>(
  key: Uint8Array<ArrayBuffer> | CryptoKey,
): Promise<T> {
  let jwk: JsonWebKey;
  if (key instanceof Uint8Array) {
    jwk = { kty: "oct", k: base64UrlStringify(key) };
  } else {
    if (!isCryptoKey(key)) {
      throw new JWTError("Key must be one of type: CryptoKey or Uint8Array", "ERR_JWK_INVALID");
    }
    if (!key.extractable) {
      throw new JWTError(
        "non-extractable CryptoKey cannot be exported as a JWK",
        "ERR_JWK_INVALID",
      );
    }
    jwk = await crypto.subtle.exportKey("jwk", key);
  }

  // oxlint-disable-next-line typescript/no-unsafe-type-assertion -- WebCrypto exports a complete JWK of the key's own kty, and the caller names the kty it passed in
  return jwk as T;
}

// --- Internal helpers ---

/**
 * Intersect a JWK's `key_ops` with the usages the operation needs. An operation
 * that needs none (a public ECDH key derives nothing itself) takes the JWK's
 * declaration as-is.
 */
function permittedUsages(jwk: JWK, keyUsages: KeyUsage[]): KeyUsage[] {
  const keyOps = jwk.key_ops;
  if (!keyOps || keyUsages.length === 0) return keyUsages;
  const permitted = keyUsages.filter((usage) => keyOps.includes(usage));
  if (permitted.length === 0) {
    throw new JWTError(`JWK "key_ops" does not permit ${keyUsages.join(", ")}.`, "ERR_JWK_INVALID");
  }
  return permitted;
}

function subtleMapping(jwk: JWK): {
  algorithm: RsaHashedImportParams | EcKeyAlgorithm | Algorithm;
  keyUsages: KeyUsage[];
} {
  let algorithm: RsaHashedImportParams | EcKeyAlgorithm | Algorithm;
  let keyUsages: KeyUsage[];

  switch (jwk.kty) {
    case "RSA": {
      switch (jwk.alg) {
        case "PS256":
        case "PS384":
        case "PS512": {
          algorithm = { name: "RSA-PSS", hash: `SHA-${jwk.alg.slice(-3)}` };
          keyUsages = hasPrivateMember(jwk) ? ["sign"] : ["verify"];
          break;
        }
        case "RS256":
        case "RS384":
        case "RS512": {
          algorithm = {
            name: "RSASSA-PKCS1-v1_5",
            hash: `SHA-${jwk.alg.slice(-3)}`,
          };
          keyUsages = hasPrivateMember(jwk) ? ["sign"] : ["verify"];
          break;
        }
        case "RSA-OAEP":
        case "RSA-OAEP-256":
        case "RSA-OAEP-384":
        case "RSA-OAEP-512": {
          algorithm = {
            name: "RSA-OAEP",
            hash: `SHA-${Number.parseInt(jwk.alg.slice(-3), 10) || 1}`,
          };
          keyUsages = hasPrivateMember(jwk) ? ["decrypt", "unwrapKey"] : ["encrypt", "wrapKey"];
          break;
        }
        default: {
          throw new JWTError(
            `Invalid or unsupported JWK "alg" (Algorithm) Parameter value: ${String(jwk.alg)}.`,
            "ERR_JWK_INVALID",
          );
        }
      }
      break;
    }
    case "EC": {
      switch (jwk.alg) {
        case "ES256": {
          algorithm = { name: "ECDSA", namedCurve: "P-256" };
          keyUsages = hasPrivateMember(jwk) ? ["sign"] : ["verify"];
          break;
        }
        case "ES384": {
          algorithm = { name: "ECDSA", namedCurve: "P-384" };
          keyUsages = hasPrivateMember(jwk) ? ["sign"] : ["verify"];
          break;
        }
        case "ES512": {
          algorithm = { name: "ECDSA", namedCurve: "P-521" };
          keyUsages = hasPrivateMember(jwk) ? ["sign"] : ["verify"];
          break;
        }
        case "ECDH-ES":
        case "ECDH-ES+A128KW":
        case "ECDH-ES+A192KW":
        case "ECDH-ES+A256KW": {
          algorithm = {
            name: "ECDH",
            namedCurve: requireCurve(jwk, ["P-256", "P-384", "P-521"]),
          };
          keyUsages = hasPrivateMember(jwk) ? ["deriveBits"] : [];
          break;
        }
        default: {
          throw new JWTError(
            `Invalid or unsupported JWK "alg" (Algorithm) Parameter value: ${String(jwk.alg)}.`,
            "ERR_JWK_INVALID",
          );
        }
      }
      break;
    }
    case "OKP": {
      switch (jwk.alg) {
        case "Ed25519":
        case "EdDSA": {
          algorithm = { name: requireCurve(jwk, ["Ed25519"]) };
          keyUsages = hasPrivateMember(jwk) ? ["sign"] : ["verify"];
          break;
        }
        case "ECDH-ES":
        case "ECDH-ES+A128KW":
        case "ECDH-ES+A192KW":
        case "ECDH-ES+A256KW": {
          algorithm = { name: requireCurve(jwk, ["X25519"]) };
          keyUsages = hasPrivateMember(jwk) ? ["deriveBits"] : [];
          break;
        }
        default: {
          throw new JWTError(
            `Invalid or unsupported JWK "alg" (Algorithm) Parameter value: ${String(jwk.alg)}.`,
            "ERR_JWK_INVALID",
          );
        }
      }
      break;
    }
    default: {
      throw new JWTError(
        `Invalid or unsupported JWK "kty" (Key Type) Parameter value: ${String((jwk as { kty?: unknown }).kty)}.`,
        "ERR_JWK_INVALID",
      );
    }
  }

  return { algorithm, keyUsages };
}

/**
 * Returns the JWK's `crv` once it is known to be one of `allowed`.
 *
 * The curve drives the WebCrypto algorithm name, so an unknown value must never
 * reach `crypto.subtle` — nor may a curve be assumed from `alg` alone, which
 * would import a key on another curve as `Ed25519`.
 */
function requireCurve(jwk: JWK, allowed: readonly string[]): string {
  const crv: unknown = "crv" in jwk ? jwk.crv : undefined;
  if (typeof crv !== "string" || !allowed.includes(crv)) {
    throw new JWTError(
      `Invalid or unsupported JWK "crv" (Curve) Parameter value: ${String(crv)}. Expected one of: ${allowed.join(", ")}.`,
      "ERR_JWK_INVALID",
    );
  }
  return crv;
}

/** Whether the JWK carries a non-empty private `d` member. */
function hasPrivateMember(jwk: JWK): boolean {
  return "d" in jwk && Boolean(jwk.d);
}
