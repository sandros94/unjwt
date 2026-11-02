import { assertJWEEncSupported } from "../_internal/algorithms.ts";
import type {
  JWK_EC_Public,
  JWK_EC_Private,
  JWK_OKP_Public,
  JWK_OKP_Private,
  JWK_ECDH_ES,
  ContentEncryptionAlgorithm,
} from "../types/index.ts";
import { assertPlainObject, isCryptoKey } from "../../utils/guards.ts";
import { isECDHESAlgorithm } from "../../utils/algorithms.ts";
import { JWTError } from "../../error.ts";
import { importKey } from "../_internal/import-key.ts";
import { bitLengthCEK, deriveECDHESKey } from "../_crypto/index.ts";
import { aesBitsOf, innerKeyWrapAlg } from "../_crypto/_key-algorithm.ts";

/**
 * Derives ECDH-ES key material (RFC 7518 §4.6): ECDH on an EC or OKP pair, then the Concat KDF.
 * A JWK is imported under `enc` when `enc` is an `ECDH-ES*` algorithm, else under `"ECDH-ES"`.
 *
 * @param publicKey The recipient's static public key, or the ephemeral one when decrypting.
 * @param privateKey The ephemeral private key, or the recipient's static one when decrypting.
 * @throws `ERR_JWE_INVALID` if `enc` is neither an `ECDH-ES*` nor a content encryption algorithm.
 * @throws `ERR_INVALID_OPTION` if `keyLength` is not a positive multiple of 8 up to 8192.
 * @throws `ERR_JWK_INVALID` if `enc` is `"ECDH-ES"` without `keyLength`, a key is the wrong half or has another `alg`,
 *   or the keys are not agreement keys on one curve.
 */
export async function deriveSharedSecret(
  publicKey: CryptoKey | JWK_EC_Public | JWK_OKP_Public,
  privateKey: CryptoKey | JWK_EC_Private | JWK_OKP_Private,
  options: {
    /** The algorithm identifier the Concat KDF uses as `AlgorithmID`. */
    enc: JWK_ECDH_ES | ContentEncryptionAlgorithm;
    /** The derived length in bits. Required for `"ECDH-ES"`. @default the key length of `enc` */
    keyLength?: number;
    /** The agreement PartyUInfo (`apu`). @default empty */
    partyUInfo?: Uint8Array<ArrayBuffer>;
    /** The agreement PartyVInfo (`apv`). @default empty */
    partyVInfo?: Uint8Array<ArrayBuffer>;
  },
): Promise<Uint8Array<ArrayBuffer>> {
  assertPlainObject(options, "options");
  const { enc: alg, keyLength: requestedKeyLength, partyUInfo, partyVInfo } = options;
  if (!isECDHESAlgorithm(alg)) assertJWEEncSupported(alg);
  if (requestedKeyLength !== undefined) {
    assertDerivedKeyLength(requestedKeyLength);
  }

  // RFC 7517 §4.4: a JWK is imported under the `ECDH-ES*` alg it may declare.
  const importAlg: JWK_ECDH_ES = isECDHESAlgorithm(alg) ? alg : "ECDH-ES";
  const pubCryptoKey = isCryptoKey(publicKey)
    ? publicKey
    : await importKey(publicKey, { alg: importAlg, expect: "public" });
  const privCryptoKey = isCryptoKey(privateKey)
    ? privateKey
    : await importKey(privateKey, { alg: importAlg, expect: "private" });

  let keyLength: number;
  if (requestedKeyLength !== undefined) {
    keyLength = requestedKeyLength;
  } else if (alg === "ECDH-ES") {
    throw new JWTError(
      'deriveSharedSecret with enc "ECDH-ES" requires an explicit keyLength in options',
      "ERR_INVALID_OPTION",
    );
  } else if (isECDHESAlgorithm(alg)) {
    keyLength = aesBitsOf(innerKeyWrapAlg(alg));
  } else {
    keyLength = bitLengthCEK(alg);
  }

  try {
    return await deriveECDHESKey(
      pubCryptoKey,
      privCryptoKey,
      alg,
      keyLength,
      partyUInfo ?? new Uint8Array(0),
      partyVInfo ?? new Uint8Array(0),
    );
  } catch (error_) {
    throw new JWTError(
      "Key agreement failed: both keys must be agreement keys on the same curve.",
      "ERR_JWK_INVALID",
      error_,
    );
  }
}

function assertDerivedKeyLength(keyLength: number): void {
  if (!Number.isInteger(keyLength) || keyLength <= 0 || keyLength % 8 !== 0 || keyLength > 8192) {
    throw new JWTError(
      `keyLength must be a positive multiple of 8 no greater than 8192 bits, got ${keyLength}`,
      "ERR_INVALID_OPTION",
    );
  }
}
