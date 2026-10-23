import { base64UrlStringify } from "../utils/base64.ts";
import { JWTError } from "../error.ts";
import { quoteTokenValue } from "../utils/_text.ts";
import { cryptoKeyCurve, innerKeyWrapAlg } from "./_key-algorithm.ts";

import type {
  ContentEncryptionAlgorithm,
  KeyManagementAlgorithm,
  JWK_ECDH_ES,
  JWEKeyManagementHeaderParameters,
  JWEHeaderParameters,
  JWK,
  JWK_EC,
  JWK_OKP,
  JWK_EC_Public,
  JWK_OKP_Public,
} from "../types/index.ts";
import { isJWK, assertCryptoKey, isCryptoKey } from "../utils/guards.ts";
import { generateCEK, gcmkwEncrypt, aesKwWrap } from "./_aes.ts";
import { jwkTokey, keyToJWK } from "./_key-codec.ts";
import { encryptRSAES } from "./_rsa.ts";
import {
  deriveECDHESKey,
  ecdhDerivedBits,
  generateEphemeralKeyPair,
  assertECDHKeyAllowed,
} from "./_ecdh.ts";
import { pbes2Wrap } from "./_pbes2.ts";

export async function encryptKey(
  alg: KeyManagementAlgorithm,
  enc: ContentEncryptionAlgorithm,
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
      ({ cek, encryptedKey, parameters } = await ecdhesWrap(alg, {
        enc,
        recipientKey: key,
        cek: providedCek,
        parameters: providedParameters,
      }));
      break;
    }
    case "RSA-OAEP":
    case "RSA-OAEP-256":
    case "RSA-OAEP-384":
    case "RSA-OAEP-512": {
      cek = providedCek || generateCEK(enc);
      assertCryptoKey(key);
      encryptedKey = await encryptRSAES(alg, key, cek);
      break;
    }
    case "PBES2-HS256+A128KW":
    case "PBES2-HS384+A192KW":
    case "PBES2-HS512+A256KW": {
      cek = providedCek || generateCEK(enc);
      const { p2c, p2s } = providedParameters;
      if (p2c === undefined || p2s === undefined) {
        throw new JWTError(`${alg} requires "p2c" and "p2s"`, "ERR_JWE_INVALID");
      }
      ({ encryptedKey, ...parameters } = await pbes2Wrap(alg, key, cek, p2c, p2s));
      break;
    }
    case "A128KW":
    case "A192KW":
    case "A256KW": {
      cek = providedCek || generateCEK(enc);
      encryptedKey = await aesKwWrap(alg, key, cek);
      break;
    }
    case "A128GCMKW":
    case "A192GCMKW":
    case "A256GCMKW": {
      cek = providedCek || generateCEK(enc);
      const { iv } = providedParameters;
      ({ encryptedKey, ...parameters } = await gcmkwEncrypt(alg, key, cek, iv));
      break;
    }
    default: {
      throw new JWTError(
        `Unsupported JWE "alg" ${quoteTokenValue(alg)}`,
        "ERR_JWE_ALG_NOT_ALLOWED",
      );
    }
  }

  return { cek, encryptedKey, parameters };
}

/** RFC 7518 §4.6 — ECDH-ES: the derived key is the CEK (direct) or wraps it (`+A*KW`). */
export async function ecdhesWrap(
  alg: JWK_ECDH_ES,
  options: {
    enc: ContentEncryptionAlgorithm | undefined;
    recipientKey: CryptoKey;
    cek: Uint8Array<ArrayBuffer> | undefined;
    parameters: Pick<JWEKeyManagementHeaderParameters, "apu" | "apv" | "epk" | "epkPrivateKey">;
  },
): Promise<{
  cek: Uint8Array<ArrayBuffer>;
  encryptedKey?: Uint8Array<ArrayBuffer>;
  parameters: { epk: JWK_EC_Public | JWK_OKP_Public; apu?: string; apv?: string };
}> {
  const { enc, recipientKey } = options;
  const { apu, apv, epk: providedEpk, epkPrivateKey } = options.parameters;
  assertECDHKeyAllowed(recipientKey);

  if (providedEpk && !epkPrivateKey) {
    throw new JWTError(
      "ECDH-ES custom ephemeral key material must include the matching private key.",
      "ERR_JWK_INVALID",
    );
  }

  let ephemeralPrivateKey: CryptoKey;
  let epk: JWK_EC_Public | JWK_OKP_Public;
  if (epkPrivateKey) {
    ephemeralPrivateKey = await ensurePrivateKey(alg, epkPrivateKey);
    assertEphemeralCurve(ephemeralPrivateKey, recipientKey);
    epk = await exportPublicJwkFrom(providedEpk ?? epkPrivateKey);
  } else {
    const generated = await generateEphemeralKeyPair(recipientKey);
    ephemeralPrivateKey = generated.privateKey;
    epk = await exportPublicJwkFrom(generated.publicKey);
  }

  const kdfAlg = alg === "ECDH-ES" ? contentAlgorithm(enc) : alg;
  const sharedSecret = await deriveECDHESKey(
    recipientKey,
    ephemeralPrivateKey,
    kdfAlg,
    ecdhDerivedBits(alg, enc),
    apu,
    apv,
  );
  const parameters: { epk: JWK_EC_Public | JWK_OKP_Public; apu?: string; apv?: string } = { epk };
  if (apu) parameters.apu = base64UrlStringify(apu);
  if (apv) parameters.apv = base64UrlStringify(apv);

  if (alg === "ECDH-ES") return { cek: sharedSecret, parameters };

  const cek = options.cek ?? generateCEK(contentAlgorithm(enc));
  const encryptedKey = await aesKwWrap(innerKeyWrapAlg(alg), sharedSecret, cek);
  return { cek, encryptedKey, parameters };
}

/** Import a wire-supplied `epk` (RFC 7518 §4.6.1.1) from its public members, on the recipient's curve. */
export async function normalizeEpk(
  epk: JWK_EC_Public | JWK_OKP_Public | CryptoKey,
  options: { alg: JWK_ECDH_ES; recipientKey: CryptoKey },
): Promise<CryptoKey> {
  const { alg } = options;
  const recipientCurve = cryptoKeyCurve(options.recipientKey);

  if (isCryptoKey(epk)) {
    if (epk.type !== "public") throw invalidEpk("must not contain private key material.");
    assertEpkCurve(cryptoKeyCurve(epk), recipientCurve);
    return epk;
  }

  if (!isJWK(epk) || (epk.kty !== "EC" && epk.kty !== "OKP")) {
    throw invalidEpk("must be an EC or OKP public key.");
  }
  if ("d" in epk && epk.d !== undefined) {
    throw invalidEpk("must not contain private key material.");
  }

  const crv: unknown = epk.crv;
  const allowed = epk.kty === "EC" ? EC_ECDH_CURVES : OKP_ECDH_CURVES;
  if (typeof crv !== "string" || !allowed.has(crv)) {
    throw invalidEpk(`curve ${quoteTokenValue(crv)} is not supported for ${options.alg}.`);
  }
  assertEpkCurve(crv, recipientCurve);

  const x: unknown = epk.x;
  const y: unknown = epk.kty === "EC" ? epk.y : undefined;
  if (typeof x !== "string" || (epk.kty === "EC" && typeof y !== "string")) {
    throw invalidEpk("is missing its public coordinates.");
  }

  const publicJwk =
    epk.kty === "EC" && typeof y === "string"
      ? { kty: "EC" as const, crv, x, y, alg }
      : { kty: "OKP" as const, crv, x, alg };

  return jwkTokey(publicJwk);
}

const EC_ECDH_CURVES: ReadonlySet<string> = /* @__PURE__ */ new Set(["P-256", "P-384", "P-521"]);
const OKP_ECDH_CURVES: ReadonlySet<string> = /* @__PURE__ */ new Set(["X25519"]);

/** RFC 7518 §4.6.2 — direct ECDH-ES agrees on a key for one content encryption algorithm. */
function contentAlgorithm(enc: ContentEncryptionAlgorithm | undefined): ContentEncryptionAlgorithm {
  if (enc) return enc;
  throw new JWTError('ECDH-ES requires "enc" to derive the key.', "ERR_JWE_INVALID");
}

/** RFC 7518 §4.6 — the ephemeral key agrees with the recipient key only on the same curve. */
function assertEphemeralCurve(ephemeralKey: CryptoKey, recipientKey: CryptoKey): void {
  assertECDHKeyAllowed(ephemeralKey);
  const ephemeralCurve = cryptoKeyCurve(ephemeralKey);
  const recipientCurve = cryptoKeyCurve(recipientKey);
  if (ephemeralCurve === recipientCurve) return;
  throw new JWTError(
    `ECDH-ES ephemeral key curve ${quoteTokenValue(ephemeralCurve)} does not match recipient curve ${quoteTokenValue(recipientCurve)}.`,
    "ERR_JWK_INVALID",
  );
}

function invalidEpk(detail: string): JWTError {
  return new JWTError(`Invalid JWE: "epk" ${detail}`, "ERR_JWE_INVALID");
}

function assertEpkCurve(epkCurve: string | undefined, recipientCurve: string | undefined): void {
  if (!recipientCurve || !epkCurve || epkCurve === recipientCurve) return;
  throw invalidEpk(`curve "${epkCurve}" does not match recipient curve "${recipientCurve}".`);
}

/** The `epk` header member: the public key parameters alone (RFC 7518 §4.6.1.1). */
function toPublicEpkJwk(jwk: JWK): JWK_EC_Public | JWK_OKP_Public {
  const { kty } = jwk;
  const crv: unknown = "crv" in jwk ? jwk.crv : undefined;
  const x: unknown = "x" in jwk ? jwk.x : undefined;
  if (kty !== "EC" && kty !== "OKP") {
    throw new JWTError('ECDH-ES ephemeral key JWK "kty" must be "EC" or "OKP".', "ERR_JWK_INVALID");
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
  if (kty === "OKP") return { kty, crv, x };

  const y: unknown = "y" in jwk ? jwk.y : undefined;
  if (typeof y !== "string") {
    throw new JWTError(
      'ECDH-ES EC ephemeral key JWK must include both "x" and "y" coordinates.',
      "ERR_JWK_INVALID",
    );
  }
  return { kty, crv, x, y };
}

async function ensurePrivateKey(
  alg: JWK_ECDH_ES,
  value: CryptoKey | JWK_EC | JWK_OKP,
): Promise<CryptoKey> {
  const normalized = isCryptoKey(value) ? value : await jwkTokey(value, { alg });
  if (normalized.type !== "private") {
    throw new JWTError(
      'ECDH-ES ephemeral private key must have type "private".',
      "ERR_JWK_INVALID",
    );
  }
  return normalized;
}

async function exportPublicJwkFrom(
  value: CryptoKey | JWK_EC | JWK_OKP,
): Promise<JWK_EC_Public | JWK_OKP_Public> {
  if (!isCryptoKey(value)) return toPublicEpkJwk(value);
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
