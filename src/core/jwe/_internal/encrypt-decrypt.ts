import { secureRandomBytes } from "unsecure/random";

import type { JWEEncryptOptions, JWEKeyManagementHeaderParameters } from "../../types/jwe.ts";
import type { JOSEPayloadMode, PayloadOf } from "../../types/index.ts";
import type {
  ContentEncryptionAlgorithm,
  JWK,
  JWKSet,
  KeyManagementAlgorithm,
  UnwrapKeyOptions,
} from "../../types/jwk.ts";
import { unwrapKey } from "../../jwk/wrap.ts";
import { importKey, getJWKsFromSet } from "../../_internal/import-key.ts";
import { decrypt as joseDecrypt } from "../../_crypto/_aes.ts";
import { JWTError } from "../../../error.ts";
import { isJWKSet } from "../../../utils/guards.ts";
import { parsePayloadBytes } from "../../_internal/jwt.ts";
import type { PBES2Budget } from "./keys.ts";
import { DEFAULT_PBES2_ITERATIONS, assertJWKSetCandidates } from "../../_internal/limits.ts";
import { asDecryptionError } from "../../_internal/errors.ts";
import {
  assertDirectKeyRole,
  buildECDHAgreementParams,
  buildJWKSetFilter,
  resolvePasswordKey,
} from "../../_internal/keys.ts";

export type DecryptionKeyMaterial = CryptoKey | JWK | JWKSet | Uint8Array<ArrayBuffer> | string;

/** Build one recipient's key management parameters; PBES2 gets a fresh salt and the default count unless given. */
export function buildKeyManagementParams(
  alg: KeyManagementAlgorithm,
  source: Pick<JWEEncryptOptions, "keyManagementIV" | "p2s" | "p2c" | "ecdh">,
): JWEKeyManagementHeaderParameters {
  const { keyManagementIV, p2s, p2c, ecdh } = source;
  const isPBES2 = alg.startsWith("PBES2");
  const params: JWEKeyManagementHeaderParameters = buildECDHAgreementParams(ecdh);
  if (keyManagementIV) params.iv = keyManagementIV;
  if (p2s !== undefined) params.p2s = p2s;
  else if (isPBES2) params.p2s = secureRandomBytes(16);
  if (p2c !== undefined) params.p2c = p2c;
  else if (isPBES2) params.p2c = DEFAULT_PBES2_ITERATIONS;
  return params;
}

export interface UnwrapAndDecryptOptions {
  enc: ContentEncryptionAlgorithm;
  encryptedKey: Uint8Array<ArrayBuffer>;
  unwrapKeyOptions: UnwrapKeyOptions;
  ciphertext: Uint8Array<ArrayBuffer>;
  iv: Uint8Array<ArrayBuffer>;
  tag: Uint8Array<ArrayBuffer>;
  aad: Uint8Array<ArrayBuffer>;
  kid: string | undefined;
  allowSymmetric: boolean | undefined;
  keyCandidates: number;
  pbes2Budget: PBES2Budget;
}

/** Unwrap the CEK and decrypt; a JWK Set tries each candidate, failing with one `ERR_JWE_DECRYPTION_FAILED` (RFC 7516 §11.5). */
export async function unwrapAndDecrypt(
  alg: KeyManagementAlgorithm,
  rawKeyMaterial: DecryptionKeyMaterial,
  options: UnwrapAndDecryptOptions,
): Promise<{
  cek: Uint8Array<ArrayBuffer> | CryptoKey;
  plaintextBytes: Uint8Array<ArrayBuffer>;
}> {
  const {
    enc,
    encryptedKey,
    unwrapKeyOptions,
    ciphertext,
    iv,
    tag,
    aad,
    kid,
    allowSymmetric,
    keyCandidates,
    pbes2Budget,
  } = options;

  if (isJWKSet(rawKeyMaterial)) {
    const candidates = getJWKsFromSet(
      rawKeyMaterial,
      buildJWKSetFilter({ kid, alg }, { op: "enc", allowSymmetric }),
    );
    assertJWKSetCandidates(candidates, { limit: keyCandidates, kid });
    const attempts: JWTError[] = [];
    for (const candidate of candidates) {
      try {
        if (alg === "dir") assertDirectKeyRole(candidate, enc);
        pbes2Budget.spend(unwrapKeyOptions);
        const unwrappingKey = await importKey(candidate, { alg, expect: "private" });
        const cek = await unwrapKey(encryptedKey, unwrappingKey, unwrapKeyOptions);
        const plaintextBytes = await joseDecrypt(enc, cek, ciphertext, iv, tag, aad);
        return { cek, plaintextBytes };
      } catch (err) {
        attempts.push(asDecryptionError(err));
      }
    }
    throw new JWTError("JWE decryption failed.", "ERR_JWE_DECRYPTION_FAILED", attempts);
  }

  if (alg === "dir") assertDirectKeyRole(rawKeyMaterial, enc);
  pbes2Budget.spend(unwrapKeyOptions);
  try {
    const unwrappingKey = await importKey(resolvePasswordKey(alg, rawKeyMaterial), {
      alg,
      expect: "private",
    });
    const cek = await unwrapKey(encryptedKey, unwrappingKey, unwrapKeyOptions);
    const plaintextBytes = await joseDecrypt(enc, cek, ciphertext, iv, tag, aad);
    return { cek, plaintextBytes };
  } catch (err) {
    throw asDecryptionError(err);
  }
}

export function decodeJWEPayload(
  plaintext: Uint8Array<ArrayBuffer>,
  mode: JOSEPayloadMode,
): PayloadOf<JOSEPayloadMode> {
  return parsePayloadBytes(plaintext, { payload: mode, family: "JWE" });
}
