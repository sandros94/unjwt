import {
  assertDirectKeyRole,
  buildECDHAgreementParams,
  resolvePasswordKey,
} from "../_internal/keys.ts";
import { assertJWEEncSupported } from "../_internal/algorithms.ts";
import type {
  JWK,
  JWK_ECDH_ES,
  KeyManagementAlgorithm,
  WrapKeyOptions,
  WrapKeyResult,
  WrappingKeyFor,
  UnwrapKeyOptions,
  UnwrapKeyResult,
  UnwrappingKeyFor,
} from "../types/index.ts";
import { assertPlainObject } from "../../utils/guards.ts";
import { JWTError } from "../../error.ts";
import { importKey } from "../_internal/import-key.ts";
import {
  assertPBES2Params,
  assertOctKeyLength,
  pbes2Wrap,
  pbes2Unwrap,
  deriveECDHESKey,
  normalizeEpk,
  bitLengthIV,
  bitLengthTag,
  aesKwWrap,
  aesKwUnwrap,
  gcmkwEncrypt,
  gcmkwDecrypt,
  encryptRSAES,
  decryptRSAES,
} from "../_crypto/index.ts";
import { assertECDHKeyAllowed, ecdhDerivedBits } from "../_crypto/_ecdh.ts";
import { ecdhesWrap } from "../_crypto/_key-encryption.ts";
import { innerKeyWrapAlg } from "../_crypto/_key-algorithm.ts";
import {
  inferAesImportAlgorithm,
  assertWrappableCEK,
  unwrapping,
  assertKeyBytesArg,
  assertPartyInfoLength,
  assertKeyWrapSegmentLength,
  assertCryptoKeyFor,
  segmentBytes,
} from "./_internal/wrap.ts";

/**
 * Wraps a CEK under a JWA key management algorithm. The result members follow `alg`:
 * `iv` and `tag` for AES-GCMKW, `p2s` and `p2c` for PBES2, `epk`, `apu` and `apv` for ECDH-ES.
 *
 * @param wrappingKey A `CryptoKey` or a JWK. For PBES2, also a password string or bytes.
 * @param options `alg` plus its parameters (`p2s` and `p2c` for PBES2, `ecdh` for ECDH-ES, …).
 * @throws `ERR_INVALID_OPTION` if `keyToWrap` is not bytes or a `CryptoKey`, an AES-KW CEK is not
 *   16 bytes or more in whole 8-byte blocks, or `p2s` or `p2c` is out of range.
 * @throws `ERR_JWE_INVALID` if PBES2 lacks `p2s` or `p2c`, or `ecdh.enc` is unsupported.
 * @throws `ERR_JWK_INVALID` if the key does not fit `alg`, a string key is given outside PBES2, or `"ECDH-ES"` lacks `ecdh.enc`.
 * @throws `ERR_JWK_UNSUPPORTED` if `alg` is not a key management algorithm.
 */
export async function wrapKey<TAlg extends KeyManagementAlgorithm>(
  keyToWrap: CryptoKey | Uint8Array<ArrayBuffer>,
  wrappingKey: WrappingKeyFor<TAlg>,
  options: WrapKeyOptions<TAlg>,
): Promise<WrapKeyResult<TAlg>>;
export async function wrapKey(
  keyToWrap: CryptoKey | Uint8Array<ArrayBuffer>,
  wrappingKey: CryptoKey | JWK | string | Uint8Array<ArrayBuffer>,
  options: WrapKeyOptions,
): Promise<WrapKeyResult> {
  assertPlainObject(options, "options");
  assertKeyBytesArg(keyToWrap, "keyToWrap");
  const { alg } = options;
  const cekBytes =
    keyToWrap instanceof Uint8Array
      ? keyToWrap
      : new Uint8Array(await crypto.subtle.exportKey("raw", keyToWrap));

  if (alg.endsWith("KW")) assertWrappableCEK(cekBytes, alg);
  if (alg.startsWith("PBES2")) assertPBES2Params({ p2s: options.p2s, p2c: options.p2c });

  const importedWrappingKey = await importKey(resolvePasswordKey(alg, wrappingKey), {
    alg,
    expect: "public",
  });

  switch (alg) {
    case "dir": {
      // RFC 7516 §5.1 step 6: direct encryption has an empty JWE Encrypted Key.
      return { encryptedKey: new Uint8Array(0) };
    }

    case "A128KW":
    case "A192KW":
    case "A256KW": {
      const encryptedKey = await aesKwWrap(alg, importedWrappingKey, cekBytes);
      return { encryptedKey };
    }

    case "PBES2-HS256+A128KW":
    case "PBES2-HS384+A192KW":
    case "PBES2-HS512+A256KW": {
      const { p2s, p2c } = options;
      if (!p2s || typeof p2c !== "number") {
        throw new JWTError(
          "PBES2 requires 'p2s' (salt) and 'p2c' (count) options",
          "ERR_JWE_INVALID",
        );
      }
      return pbes2Wrap(alg, importedWrappingKey, cekBytes, p2c, p2s);
    }

    case "A128GCMKW":
    case "A192GCMKW":
    case "A256GCMKW": {
      const { encryptedKey, iv, tag } = await gcmkwEncrypt(
        alg,
        importedWrappingKey,
        cekBytes,
        options.iv,
      );
      return { encryptedKey, iv, tag };
    }

    case "RSA-OAEP":
    case "RSA-OAEP-256":
    case "RSA-OAEP-384":
    case "RSA-OAEP-512": {
      assertCryptoKeyFor(alg, importedWrappingKey, "wrapping");
      const encryptedKey = await encryptRSAES(alg, importedWrappingKey, cekBytes);
      return { encryptedKey };
    }

    case "ECDH-ES":
    case "ECDH-ES+A128KW":
    case "ECDH-ES+A192KW":
    case "ECDH-ES+A256KW": {
      assertCryptoKeyFor(alg, importedWrappingKey, "wrapping");
      const enc = options.ecdh?.enc;
      if (enc !== undefined) assertJWEEncSupported(enc);
      if (alg === "ECDH-ES" && !enc) {
        throw new JWTError(
          "ECDH-ES direct key agreement requires options.ecdh.enc",
          "ERR_JWK_INVALID",
        );
      }

      const { encryptedKey, parameters } = await ecdhesWrap(alg, {
        enc,
        recipientKey: importedWrappingKey,
        cek: cekBytes,
        parameters: buildECDHAgreementParams(options.ecdh),
      });
      const wrapResult: WrapKeyResult<JWK_ECDH_ES> = {
        encryptedKey: encryptedKey ?? new Uint8Array(0),
        epk: parameters.epk,
      };
      if (parameters.apu) wrapResult.apu = parameters.apu;
      if (parameters.apv) wrapResult.apv = parameters.apv;
      return wrapResult;
    }

    default: {
      throw new JWTError(`Unsupported key wrapping algorithm: ${alg}`, "ERR_JWK_UNSUPPORTED");
    }
  }
}

/**
 * Unwraps a CEK under a JWA key management algorithm. Returns an AES-GCM `CryptoKey` unless
 * `format` is `"raw"` or `unwrappedKeyAlgorithm` says otherwise. Pass `format: "raw"` for an `A*CBC-HS*` CEK.
 *
 * @param unwrappingKey A `CryptoKey` or a JWK. For PBES2, also a password string or bytes.
 * @param options `alg`, `format?` (`"cryptokey"` by default, or `"raw"`), plus the algorithm's
 *   parameters (`iv` and `tag`, `p2s` and `p2c`, `epk`, …).
 * @throws `ERR_JWE_DECRYPTION_FAILED` if the unwrap fails. The cause is not disclosed (RFC 7516 §11.5).
 * @throws `ERR_INVALID_OPTION` if `wrappedKey` is not a `Uint8Array` or `options` is not an object.
 * @throws `ERR_JWE_INVALID` if an algorithm parameter is missing or malformed.
 * @throws `ERR_JWK_INVALID` if the key does not fit `alg`.
 * @throws `ERR_JWK_UNSUPPORTED` if `alg` is not a key management algorithm.
 */
export async function unwrapKey<TOptions extends UnwrapKeyOptions>(
  wrappedKey: Uint8Array<ArrayBuffer>,
  unwrappingKey: UnwrappingKeyFor<TOptions["alg"]>,
  options: TOptions,
): Promise<UnwrapKeyResult<TOptions>>;
export async function unwrapKey(
  wrappedKey: Uint8Array<ArrayBuffer>,
  unwrappingKey: CryptoKey | JWK | string | Uint8Array<ArrayBuffer>,
  options: UnwrapKeyOptions,
): Promise<CryptoKey | Uint8Array<ArrayBuffer>> {
  assertPlainObject(options, "options");
  if (!(wrappedKey instanceof Uint8Array)) {
    throw new JWTError('"wrappedKey" must be a Uint8Array.', "ERR_INVALID_OPTION");
  }
  const { alg } = options;
  const returnRaw = options.format === "raw";
  const defaultExtractable = options.extractable !== false;

  const importedUnwrappingKey = await importKey(resolvePasswordKey(alg, unwrappingKey), {
    alg,
    expect: "private",
  });

  let unwrappedCekBytes: Uint8Array<ArrayBuffer>;

  switch (alg) {
    case "dir": {
      assertDirectKeyRole(unwrappingKey, options.enc);
      if (importedUnwrappingKey instanceof Uint8Array) {
        assertOctKeyLength(importedUnwrappingKey, options.enc);
        unwrappedCekBytes = importedUnwrappingKey;
      } else {
        if (!returnRaw) {
          return importedUnwrappingKey;
        }
        unwrappedCekBytes = new Uint8Array(
          await crypto.subtle.exportKey("raw", importedUnwrappingKey),
        );
      }
      break;
    }

    case "A128KW":
    case "A192KW":
    case "A256KW": {
      unwrappedCekBytes = await unwrapping(aesKwUnwrap(alg, importedUnwrappingKey, wrappedKey));
      break;
    }

    case "PBES2-HS256+A128KW":
    case "PBES2-HS384+A192KW":
    case "PBES2-HS512+A256KW": {
      const { p2s, p2c, minIterations, maxIterations } = options;
      if (!p2s || typeof p2c !== "number") {
        throw new JWTError(
          "PBES2 requires 'p2s' (salt) and 'p2c' (count) options",
          "ERR_JWE_INVALID",
        );
      }
      const p2sBytes = segmentBytes(p2s, "p2s");
      unwrappedCekBytes = await unwrapping(
        pbes2Unwrap(
          alg,
          importedUnwrappingKey,
          wrappedKey,
          p2c,
          p2sBytes,
          minIterations,
          maxIterations,
        ),
      );
      break;
    }

    case "A128GCMKW":
    case "A192GCMKW":
    case "A256GCMKW": {
      if (!options.iv || !options.tag) {
        throw new JWTError(
          "AES-GCMKW requires 'iv' and 'tag' options for unwrapping",
          "ERR_JWE_INVALID",
        );
      }
      const ivBytes = segmentBytes(options.iv, "iv");
      const tagBytes = segmentBytes(options.tag, "tag");
      assertKeyWrapSegmentLength("iv", ivBytes, bitLengthIV(alg) >> 3, alg);
      assertKeyWrapSegmentLength("tag", tagBytes, bitLengthTag(alg) >> 3, alg);
      unwrappedCekBytes = await unwrapping(
        gcmkwDecrypt(alg, importedUnwrappingKey, wrappedKey, ivBytes, tagBytes),
      );
      break;
    }

    case "RSA-OAEP":
    case "RSA-OAEP-256":
    case "RSA-OAEP-384":
    case "RSA-OAEP-512": {
      assertCryptoKeyFor(alg, importedUnwrappingKey, "unwrapping");

      unwrappedCekBytes = await unwrapping(decryptRSAES(alg, importedUnwrappingKey, wrappedKey));

      if (returnRaw) {
        break;
      }

      const inferredAlgorithm =
        options.unwrappedKeyAlgorithm ||
        inferAesImportAlgorithm(options.enc, unwrappedCekBytes.length);

      if (!inferredAlgorithm) {
        throw new JWTError(
          'Cannot infer the RSA-OAEP unwrapped key algorithm, pass "unwrappedKeyAlgorithm".',
          "ERR_JWE_INVALID",
        );
      }

      const keyUsages = options.keyUsage || ["encrypt", "decrypt"];
      return await crypto.subtle.importKey(
        "raw",
        unwrappedCekBytes,
        inferredAlgorithm,
        defaultExtractable,
        keyUsages,
      );
    }

    case "ECDH-ES":
    case "ECDH-ES+A128KW":
    case "ECDH-ES+A192KW":
    case "ECDH-ES+A256KW": {
      if (!options.epk) {
        throw new JWTError("ECDH-ES requires 'epk' option", "ERR_JWE_INVALID");
      }
      assertCryptoKeyFor(alg, importedUnwrappingKey, "unwrapping");
      assertECDHKeyAllowed(importedUnwrappingKey);

      const epkCandidate = await normalizeEpk(options.epk, {
        alg,
        recipientKey: importedUnwrappingKey,
      });

      const apuBytes = segmentBytes(options.apu ?? new Uint8Array(0), "apu");
      const apvBytes = segmentBytes(options.apv ?? new Uint8Array(0), "apv");
      assertPartyInfoLength("apu", apuBytes);
      assertPartyInfoLength("apv", apvBytes);

      if (options.enc !== undefined) assertJWEEncSupported(options.enc);
      const infoAlg = alg === "ECDH-ES" ? options.enc : alg;

      if (!infoAlg) {
        throw new JWTError("ECDH-ES requires 'enc' to derive the shared secret", "ERR_JWE_INVALID");
      }

      const keyLength = ecdhDerivedBits(alg, options.enc);

      const sharedSecret = await unwrapping(
        deriveECDHESKey(
          epkCandidate,
          importedUnwrappingKey,
          infoAlg,
          keyLength,
          apuBytes,
          apvBytes,
        ),
      );

      if (alg === "ECDH-ES") {
        unwrappedCekBytes = sharedSecret;
      } else {
        const kwAlg = innerKeyWrapAlg(alg);
        if (!(wrappedKey instanceof Uint8Array) || wrappedKey.length === 0) {
          throw new JWTError(
            "ECDH-ES key agreement with key wrapping requires an encrypted key",
            "ERR_JWE_INVALID",
          );
        }
        unwrappedCekBytes = await unwrapping(aesKwUnwrap(kwAlg, sharedSecret, wrappedKey));
      }

      break;
    }

    default: {
      throw new JWTError(`Unsupported key unwrapping algorithm: ${alg}`, "ERR_JWK_UNSUPPORTED");
    }
  }

  if (returnRaw) {
    return unwrappedCekBytes;
  }

  const importAlgorithm =
    options.unwrappedKeyAlgorithm || inferAesImportAlgorithm(options.enc, unwrappedCekBytes.length);
  if (!importAlgorithm) {
    throw new JWTError(
      'Cannot infer the unwrapped key algorithm, pass "unwrappedKeyAlgorithm" or unwrap to raw bytes.',
      "ERR_JWE_INVALID",
    );
  }

  return crypto.subtle.importKey(
    "raw",
    unwrappedCekBytes,
    importAlgorithm,
    defaultExtractable,
    options.keyUsage || ["encrypt", "decrypt"],
  );
}
