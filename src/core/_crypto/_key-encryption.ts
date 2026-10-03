import { sanitizeObjectCopy } from "unsecure/sanitize";
import { base64UrlStringify, base64UrlParse } from "../utils/base64";
import { JWTError } from "../error";

import type {
  JWEKeyManagementHeaderParameters,
  JWEHeaderParameters,
  JWK,
  JWK_EC,
  JWK_EC_Public,
  JWK_OKP_Public,
} from "../types";
import { isJWK, isAsymmetricJWK, assertCryptoKey, isCryptoKey } from "../utils";
import { bitLengthCEK, generateCEK, gcmkwEncrypt, aesKwWrap } from "./_aes";
import { jwkTokey, keyToJWK } from "./_key-codec";
import { encryptRSAES } from "./_rsa";
import { deriveECDHESKey, isECDHKeyAllowed } from "./_ecdh";
import { pbes2Wrap } from "./_pbes2";

const PUBLIC_EPK_FIELDS = new Set([
  "kty",
  "crv",
  "x",
  "y",
  "kid",
  "use",
  "key_ops",
  "alg",
  "x5c",
  "x5t",
  "x5t#S256",
  "x5u",
]);

export async function encryptKey(
  alg: string,
  enc: string,
  key: CryptoKey | Uint8Array<ArrayBuffer>,
  providedCek?: Uint8Array<ArrayBuffer>,
  providedParameters: JWEKeyManagementHeaderParameters = {},
): Promise<{
  cek: CryptoKey | Uint8Array<ArrayBuffer>;
  encryptedKey?: Uint8Array<ArrayBuffer>;
  parameters?: JWEHeaderParameters;
}> {
  let encryptedKey: Uint8Array<ArrayBuffer> | undefined;
  let parameters: JWEHeaderParameters = {};
  let cek: CryptoKey | Uint8Array<ArrayBuffer>;

  switch (alg) {
    case "dir": {
      cek = key;
      break;
    }
    case "ECDH-ES":
    case "ECDH-ES+A128KW":
    case "ECDH-ES+A192KW":
    case "ECDH-ES+A256KW": {
      assertCryptoKey(key);
      if (!isECDHKeyAllowed(key)) {
        throw new JWTError(
          "ECDH with the provided key is not allowed or not supported by your javascript runtime",
          "ERR_JWK_INVALID",
        );
      }
      const { apu, apv, epk: providedEpk, epkPrivateKey } = providedParameters;

      if (providedEpk && !epkPrivateKey) {
        throw new JWTError(
          "ECDH-ES custom ephemeral key material must include the matching private key.",
          "ERR_JWK_INVALID",
        );
      }

      let ephemeralPrivateKey: CryptoKey;
      let epkHeader: JWK_EC_Public;

      if (epkPrivateKey) {
        ephemeralPrivateKey = await ensurePrivateKey(alg, epkPrivateKey);
        const publicSource = providedEpk ?? epkPrivateKey;
        epkHeader = await exportPublicJwkFrom(alg, publicSource);
      } else {
        if (providedEpk) {
          throw new JWTError(
            "ECDH-ES custom ephemeral public key requires a matching private key.",
            "ERR_JWK_INVALID",
          );
        }
        const generated = await crypto.subtle.generateKey(key.algorithm as EcKeyAlgorithm, true, [
          "deriveBits",
        ]);
        ephemeralPrivateKey = generated.privateKey;
        epkHeader = await exportPublicJwkFrom(alg, generated.publicKey);
      }

      const sharedSecret = await deriveECDHESKey(
        key,
        ephemeralPrivateKey,
        alg === "ECDH-ES" ? enc : alg,
        alg === "ECDH-ES" ? bitLengthCEK(enc) : Number.parseInt(alg.slice(-5, -2), 10),
        apu,
        apv,
      );
      parameters = { epk: epkHeader };
      if (apu) parameters.apu = base64UrlStringify(apu);
      if (apv) parameters.apv = base64UrlStringify(apv);

      if (alg === "ECDH-ES") {
        cek = sharedSecret;
        break;
      }

      cek = providedCek || generateCEK(enc);
      const kwAlg = alg.slice(-6);
      encryptedKey = await aesKwWrap(kwAlg, sharedSecret, cek as Uint8Array<ArrayBuffer>);
      break;
    }
    case "RSA-OAEP":
    case "RSA-OAEP-256":
    case "RSA-OAEP-384":
    case "RSA-OAEP-512": {
      cek = providedCek || generateCEK(enc);
      assertCryptoKey(key);
      encryptedKey = await encryptRSAES(alg, key, cek as Uint8Array<ArrayBuffer>);
      break;
    }
    case "PBES2-HS256+A128KW":
    case "PBES2-HS384+A192KW":
    case "PBES2-HS512+A256KW": {
      cek = providedCek || generateCEK(enc);
      const { p2c, p2s } = providedParameters;
      ({ encryptedKey, ...parameters } = await pbes2Wrap(
        alg,
        key,
        cek as Uint8Array<ArrayBuffer>,
        p2c!,
        p2s!,
      ));
      break;
    }
    case "A128KW":
    case "A192KW":
    case "A256KW": {
      cek = providedCek || generateCEK(enc);
      encryptedKey = await aesKwWrap(alg, key, cek as Uint8Array<ArrayBuffer>);
      break;
    }
    case "A128GCMKW":
    case "A192GCMKW":
    case "A256GCMKW": {
      cek = providedCek || generateCEK(enc);
      const { iv } = providedParameters;
      ({ encryptedKey, ...parameters } = await gcmkwEncrypt(
        alg,
        key,
        cek as Uint8Array<ArrayBuffer>,
        iv,
      ));
      break;
    }
    default: {
      throw new JWTError(
        `Invalid or unsupported "alg" (JWE Algorithm) header value: ${alg}`,
        "ERR_JWE_ALG_NOT_ALLOWED",
      );
    }
  }

  return { cek, encryptedKey, parameters };
}

export async function normalizeKey(
  key: CryptoKey | JWK | Uint8Array<ArrayBuffer>,
  alg: string,
): Promise<CryptoKey | Uint8Array<ArrayBuffer>> {
  if (key instanceof Uint8Array) {
    return key;
  }

  if (isCryptoKey(key)) {
    return key;
  }

  if (isJWK(key)) {
    if ("k" in key && key.k) {
      try {
        return base64UrlParse(key.k as string, { returnAs: "uint8array" });
      } catch (error) {
        throw new JWTError('Invalid JWK: "k" could not be decoded.', "ERR_JWK_INVALID", error);
      }
    }
    return jwkTokey(key.alg ? key : { ...key, alg });
  }

  throw new JWTError("Invalid key type provided", "ERR_JWK_INVALID");
}

/**
 * Import a wire-supplied ECDH-ES `"epk"` (RFC 7518 §4.6.1.1) as a public
 * CryptoKey.
 *
 * The ephemeral public key travels inside the JWE header, so every member of it
 * is attacker-controlled: only `kty`, `crv` and the public coordinates are
 * carried into the import, the curve must be one the library agrees on *and*
 * the one the recipient key uses (a mismatched curve would otherwise reach
 * WebCrypto as a cross-curve derivation attempt), and private key material is
 * refused outright.
 */
export async function normalizeEpk(
  epk: JWK_EC_Public | JWK_OKP_Public | CryptoKey,
  options: { alg: string; recipientKey: CryptoKey },
): Promise<CryptoKey> {
  const recipientCurve = cryptoKeyCurve(options.recipientKey);

  if (isCryptoKey(epk)) {
    if (epk.type !== "public") throw invalidEpk("must not contain private key material.");
    assertEpkCurve(cryptoKeyCurve(epk), recipientCurve);
    return epk;
  }

  if (!isJWK(epk) || (epk.kty !== "EC" && epk.kty !== "OKP")) {
    throw invalidEpk("must be an EC or OKP public key.");
  }
  if ((epk as { d?: unknown }).d !== undefined) {
    throw invalidEpk("must not contain private key material.");
  }

  const crv = (epk as { crv?: unknown }).crv;
  const allowed = epk.kty === "EC" ? EC_ECDH_CURVES : OKP_ECDH_CURVES;
  if (typeof crv !== "string" || !allowed.has(crv)) {
    throw invalidEpk(`curve ${JSON.stringify(crv ?? null)} is not supported for ${options.alg}.`);
  }
  assertEpkCurve(crv, recipientCurve);

  const { x, y } = epk as { x?: unknown; y?: unknown };
  if (typeof x !== "string" || (epk.kty === "EC" && typeof y !== "string")) {
    throw invalidEpk("is missing its public coordinates.");
  }

  // Only the public key material crosses into the import — `alg`, `key_ops`,
  // `ext`, `use` and any extension member are the library's to decide.
  const publicJwk =
    epk.kty === "EC"
      ? { kty: "EC" as const, crv, x, y: y as string, alg: options.alg }
      : { kty: "OKP" as const, crv, x, alg: options.alg };

  return jwkTokey(publicJwk as unknown as JWK);
}

// --- Internal helpers ---

const EC_ECDH_CURVES: ReadonlySet<string> = /* @__PURE__ */ new Set(["P-256", "P-384", "P-521"]);
const OKP_ECDH_CURVES: ReadonlySet<string> = /* @__PURE__ */ new Set(["X25519"]);

function invalidEpk(detail: string): JWTError {
  return new JWTError(`Invalid JWE: "epk" ${detail}`, "ERR_JWE_INVALID");
}

function cryptoKeyCurve(key: CryptoKey): string | undefined {
  const algorithm = key.algorithm as EcKeyAlgorithm;
  if (typeof algorithm.namedCurve === "string") return algorithm.namedCurve;
  return algorithm.name === "X25519" ? algorithm.name : undefined;
}

function assertEpkCurve(epkCurve: string | undefined, recipientCurve: string | undefined): void {
  if (!recipientCurve || !epkCurve || epkCurve === recipientCurve) return;
  throw invalidEpk(
    `curve "${epkCurve}" does not match the recipient key curve "${recipientCurve}".`,
  );
}

function toPublicEpkJwk(jwk: JWK_EC): JWK_EC_Public {
  const filtered: Record<string, unknown> = {};
  for (const [key, value] of Object.entries(jwk)) {
    if (value !== undefined && PUBLIC_EPK_FIELDS.has(key)) {
      filtered[key] = value;
    }
  }

  const { kty, crv, x, y } = filtered as {
    kty?: unknown;
    crv?: unknown;
    x?: unknown;
    y?: unknown;
  };

  if (typeof kty !== "string") {
    throw new JWTError(
      'ECDH-ES ephemeral key JWK must include the "kty" parameter.',
      "ERR_JWK_INVALID",
    );
  }
  if (typeof crv !== "string") {
    throw new JWTError(
      'ECDH-ES ephemeral key JWK must include the "crv" parameter.',
      "ERR_JWK_INVALID",
    );
  }
  if (typeof x !== "string") {
    throw new JWTError(
      'ECDH-ES ephemeral key JWK must include the "x" coordinate.',
      "ERR_JWK_INVALID",
    );
  }
  if (kty === "EC" && typeof y !== "string") {
    throw new JWTError(
      'ECDH-ES EC ephemeral key JWK must include both "x" and "y" coordinates.',
      "ERR_JWK_INVALID",
    );
  }

  const publicJwk: Record<string, unknown> = { ...filtered, kty, crv, x };

  if (typeof y === "string") {
    publicJwk.y = y;
  } else {
    delete publicJwk.y;
  }

  return sanitizeObjectCopy(publicJwk) as unknown as JWK_EC_Public;
}

async function ensurePrivateKey(alg: string, value: CryptoKey | JWK_EC): Promise<CryptoKey> {
  const normalized = await normalizeKey(value, alg);
  if (!(normalized instanceof CryptoKey)) {
    throw new JWTError(
      "ECDH-ES ephemeral private key must be a CryptoKey or convertible JWK.",
      "ERR_JWK_INVALID",
    );
  }
  if (normalized.type !== "private") {
    throw new JWTError(
      'ECDH-ES ephemeral private key must have type "private".',
      "ERR_JWK_INVALID",
    );
  }
  return normalized;
}

async function exportPublicJwkFrom(alg: string, value: CryptoKey | JWK_EC): Promise<JWK_EC_Public> {
  if (isCryptoKey(value)) {
    try {
      return toPublicEpkJwk(await keyToJWK(value));
    } catch (error_) {
      throw new JWTError(
        "ECDH-ES ephemeral CryptoKey must be extractable to export as JWK.",
        "ERR_JWK_INVALID",
        error_,
      );
    }
  }
  if (isJWK(value) && isAsymmetricJWK(value) && value.kty === "EC") {
    return toPublicEpkJwk(value);
  }
  const normalized = await normalizeKey(value, alg);
  if (!(normalized instanceof CryptoKey)) {
    throw new JWTError(
      "ECDH-ES ephemeral public key must be a CryptoKey or convertible JWK.",
      "ERR_JWK_INVALID",
    );
  }
  return exportPublicJwkFrom(alg, normalized);
}
