import { base64UrlStringify } from "../utils/base64.ts";

import type { JWK, JWKAlgorithm } from "../types/index.ts";
import { isCryptoKey } from "../utils/guards.ts";
import { JWTError } from "../error.ts";
import { ECDSA_CURVES, jwsHashOf, rsaOaepHashOf } from "./_key-algorithm.ts";
import { quoteTokenValue } from "../utils/_text.ts";

/** Import a JWK for its `alg`; `key_ops` (RFC 7517 §4.3) and `ext` only ever narrow usages and extractability. */
export async function jwkTokey(
  jwk: JWK,
  options: { extractable?: boolean; alg?: JWKAlgorithm } = {},
): Promise<CryptoKey> {
  const alg = jwk.alg ?? options.alg;
  if (!alg) {
    throw new JWTError(
      '"alg" argument is required when "jwk.alg" is not present',
      "ERR_JWK_INVALID",
    );
  }

  const { algorithm, keyUsages } = subtleMapping(jwk, alg);
  const material: JsonWebKey = { ...jwk, alg };

  const isPrivate = "d" in jwk && jwk.d !== undefined;
  const extractable = jwk.ext === false ? false : (options.extractable ?? !isPrivate);

  try {
    return await crypto.subtle.importKey(
      "jwk",
      material,
      algorithm,
      extractable,
      permittedUsages(jwk, keyUsages),
    );
  } catch (error) {
    if (error instanceof JWTError) throw error;
    throw new JWTError(`Key is not usable for ${quoteTokenValue(alg)}.`, "ERR_JWK_INVALID", error);
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
    // `ext` and `key_ops` describe the CryptoKey, not required by JWK.
    const { ext: _ext, key_ops: _keyOps, ...exported } = await crypto.subtle.exportKey("jwk", key);
    jwk = exported;
  }

  // oxlint-disable-next-line typescript/no-unsafe-type-assertion -- WebCrypto exports a complete JWK of the key's own kty
  return jwk as T;
}

/** Intersect a JWK's `key_ops` with the usages the operation needs. */
function permittedUsages(jwk: JWK, keyUsages: KeyUsage[]): KeyUsage[] {
  const keyOps = jwk.key_ops;
  if (!keyOps || keyUsages.length === 0) return keyUsages;
  const permitted = keyUsages.filter((usage) => keyOps.includes(usage));
  if (permitted.length === 0) {
    throw new JWTError(`JWK "key_ops" does not permit ${keyUsages.join(", ")}.`, "ERR_JWK_INVALID");
  }
  return permitted;
}

function subtleMapping(
  jwk: JWK,
  alg: JWKAlgorithm,
): {
  algorithm: RsaHashedImportParams | EcKeyAlgorithm | Algorithm;
  keyUsages: KeyUsage[];
} {
  let algorithm: RsaHashedImportParams | EcKeyAlgorithm | Algorithm;
  let keyUsages: KeyUsage[];

  switch (jwk.kty) {
    case "RSA": {
      switch (alg) {
        case "PS256":
        case "PS384":
        case "PS512": {
          algorithm = { name: "RSA-PSS", hash: jwsHashOf(alg) };
          keyUsages = hasPrivateMember(jwk) ? ["sign"] : ["verify"];
          break;
        }
        case "RS256":
        case "RS384":
        case "RS512": {
          algorithm = { name: "RSASSA-PKCS1-v1_5", hash: jwsHashOf(alg) };
          keyUsages = hasPrivateMember(jwk) ? ["sign"] : ["verify"];
          break;
        }
        case "RSA-OAEP":
        case "RSA-OAEP-256":
        case "RSA-OAEP-384":
        case "RSA-OAEP-512": {
          algorithm = { name: "RSA-OAEP", hash: rsaOaepHashOf(alg) };
          keyUsages = hasPrivateMember(jwk) ? ["decrypt", "unwrapKey"] : ["encrypt", "wrapKey"];
          break;
        }
        default: {
          throw new JWTError(
            `Invalid or unsupported JWK "alg" (Algorithm) Parameter value: ${quoteTokenValue(alg)}.`,
            "ERR_JWK_INVALID",
          );
        }
      }
      break;
    }
    case "EC": {
      switch (alg) {
        case "ES256":
        case "ES384":
        case "ES512": {
          algorithm = { name: "ECDSA", namedCurve: ECDSA_CURVES[alg] };
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
            `Invalid or unsupported JWK "alg" (Algorithm) Parameter value: ${quoteTokenValue(alg)}.`,
            "ERR_JWK_INVALID",
          );
        }
      }
      break;
    }
    case "OKP": {
      switch (alg) {
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
            `Invalid or unsupported JWK "alg" (Algorithm) Parameter value: ${quoteTokenValue(alg)}.`,
            "ERR_JWK_INVALID",
          );
        }
      }
      break;
    }
    default: {
      throw new JWTError(
        `Invalid or unsupported JWK "kty" (Key Type) Parameter value: ${quoteTokenValue((jwk as { kty?: unknown }).kty)}.`,
        "ERR_JWK_INVALID",
      );
    }
  }

  return { algorithm, keyUsages };
}

/** The JWK's own `crv`, once known to be one of `allowed`; never assumed from `alg`. */
function requireCurve(jwk: JWK, allowed: readonly string[]): string {
  const crv: unknown = "crv" in jwk ? jwk.crv : undefined;
  if (typeof crv !== "string" || !allowed.includes(crv)) {
    throw new JWTError(
      `Invalid or unsupported JWK "crv" (Curve) Parameter value: ${quoteTokenValue(crv)}. Expected one of: ${allowed.join(", ")}.`,
      "ERR_JWK_INVALID",
    );
  }
  return crv;
}

/** Whether the JWK carries a non-empty private `d` member. */
function hasPrivateMember(jwk: JWK): boolean {
  return "d" in jwk && Boolean(jwk.d);
}
