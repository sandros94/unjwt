import { assertJWEEncSupported } from "../_internal/algorithms.ts";
import type {
  JWK_EC_Public,
  JWK_EC_Private,
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
 * Derives ECDH-ES key material (RFC 7518 §4.6): ECDH followed by the Concat KDF.
 *
 * @param publicKey The recipient's static public key (the ephemeral one when decrypting).
 * @param privateKey The ephemeral private key (the recipient's static one when decrypting).
 */
export async function deriveSharedSecret(
  publicKey: CryptoKey | JWK_EC_Public,
  privateKey: CryptoKey | JWK_EC_Private,
  options: {
    /** Algorithm identifier fed to the concat KDF as `AlgorithmID`. */
    enc: JWK_ECDH_ES | ContentEncryptionAlgorithm;
    /** Derived length in bits. Defaults to `enc`'s length; required for `"ECDH-ES"`. */
    keyLength?: number;
    /** Agreement PartyUInfo (apu). */
    partyUInfo?: Uint8Array<ArrayBuffer>;
    /** Agreement PartyVInfo (apv). */
    partyVInfo?: Uint8Array<ArrayBuffer>;
  },
): Promise<Uint8Array<ArrayBuffer>> {
  assertPlainObject(options, "options");
  const { enc: alg, keyLength: requestedKeyLength, partyUInfo, partyVInfo } = options;
  if (!isECDHESAlgorithm(alg)) assertJWEEncSupported(alg);
  if (requestedKeyLength !== undefined) {
    assertDerivedKeyLength(requestedKeyLength);
  }

  // RFC 7517 §4.4: import under the `ECDH-ES*` alg a JWK may declare.
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
      "ERR_JWK_INVALID",
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
