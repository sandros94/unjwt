import { secureRandomBytes } from "unsecure/random";
import { sanitizeObjectCopy } from "unsecure/sanitize";
import { textEncoder } from "unsecure/utils";
import { base64UrlStringify } from "./utils/base64";

import type {
  JWKSet,
  JWKLookupFunction,
  KeyManagementAlgorithm,
  ContentEncryptionAlgorithm,
} from "./types/jwk";
import type { JOSEPayload, JOSEPayloadMode, JWTClaims, PayloadOf } from "./types/jwt";
import type {
  JWEEncryptJWK,
  JWEDecryptJWK,
  JWEEncryptOptions,
  JWEDecryptOptions,
  JWEDecryptResult,
  JWEHeaderParameters,
  JWEProtectedHeader,
  JWEKeyManagementHeaderParameters,
} from "./types/jwe";

import { importKey, unwrapKey, getJWKsFromSet } from "./jwk";
import {
  encrypt as joseEncrypt,
  decrypt as joseDecrypt,
  assertPBES2Params,
  generateIV,
  encryptKey,
} from "./_crypto";
import { JWTError } from "./error";
import { isContentEncryptionAlgorithm } from "./utils/algorithms";
import { isJWK, isJWKSet } from "./utils/guards";
import {
  applyTypDefault,
  computeJwtTimeClaims,
  getPlaintextBytes,
  validateCriticalHeadersJWE,
} from "./_jwt-internal";
import {
  DEFAULT_PBES2_ITERATIONS,
  JWE_ALG_CTX,
  assertCompactToken,
  assertDirectKeyRole,
  checkProtectedTyp,
  assertOptionEntry,
  assertJWKSetCandidates,
  assertNoZipOption,
  assertProducerCEK,
  assertProducerCrit,
  assertProducerIV,
  assertProducerPartyInfo,
  asKeyUsageError,
  assertConsumerOptions,
  buildJWKSetFilter,
  buildUnwrapKeyOptions,
  checkAlgAllowed,
  assertJWEAlgSupported,
  checkJWEContentSegments,
  checkJWEDirectEncryptedKey,
  checkJWEEncAllowed,
  assertJWEEncSupported,
  checkJWEZip,
  createPBES2Budget,
  decodeProtectedHeader,
  exportReturnedCek,
  parseEphemeralKey,
  resolveKeyInput,
  resolveLimit,
  resolvePasswordKey,
  resolvePayloadMode,
  serializeProtectedHeader,
  validateClaimsIfJson,
  decodeSegment,
  decodeJWEPayload,
} from "./_internal";

export type * from "./types/jwe";
export type { JOSEPayloadMode, JOSEPayloadTypeMap, PayloadOf } from "./types/jwt";
export {
  type JWTErrorCode,
  type KnownJWTErrorCode,
  type JWTErrorCauseMap,
  type UnsecureErrorCode,
  JWTError,
  isJWTError,
  UnsecureError,
  isUnsecureError,
} from "./error";
export { encryptMulti, decryptMulti, generalToFlattened } from "./jwe-multi";
export { DEFAULT_JOSE_LIMITS } from "./_internal";

/**
 * Encrypts a payload to produce a JWE Compact Serialization string.
 *
 * @param payload The payload to encrypt. Can be a string, Uint8Array, or a JSON-serializable object.
 * @param key The key encryption key (KEK). Can be a CryptoKey, JWK, or for PBES2, a password string/Uint8Array.
 * @param options JWE encryption options, including `alg` (key management algorithm) and `enc` (content encryption algorithm).
 * @returns A Promise resolving to the JWE Compact Serialization string.
 */
export async function encrypt(
  payload: JOSEPayload,
  key: JWEEncryptJWK | string | Uint8Array<ArrayBuffer>,
  options?: JWEEncryptOptions,
): Promise<string>;
export async function encrypt(
  payload: JOSEPayload,
  key: CryptoKey | Extract<JWEEncryptJWK, { kty: "oct" }> | Uint8Array<ArrayBuffer>,
  options: JWEEncryptOptions & { alg: "dir"; enc: ContentEncryptionAlgorithm },
): Promise<string>;
export async function encrypt(
  payload: JOSEPayload,
  key: CryptoKey,
  options: JWEEncryptOptions & {
    alg: KeyManagementAlgorithm;
    enc: ContentEncryptionAlgorithm;
  },
): Promise<string>;
export async function encrypt(
  payload: JOSEPayload,
  key: CryptoKey | JWEEncryptJWK | string | Uint8Array<ArrayBuffer>,
  options: JWEEncryptOptions & {
    alg: KeyManagementAlgorithm;
    enc: ContentEncryptionAlgorithm;
  },
): Promise<string>;
export async function encrypt(
  payload: string | Uint8Array<ArrayBuffer> | Record<string, unknown>,
  key: CryptoKey | JWEEncryptJWK | string | Uint8Array<ArrayBuffer>,
  options: JWEEncryptOptions = {},
): Promise<string> {
  assertOptionEntry(options, { label: "options", objects: ["protectedHeader"] });
  const {
    protectedHeader: userHeader,
    cek: providedCek,
    contentEncryptionIV: providedContentIV,
    keyManagementIV,
    p2s,
    p2c,
    ecdh,
  } = options;
  let alg: string | undefined = options.alg;
  let enc: unknown = options.enc;

  assertNoZipOption(userHeader, "protected");

  // An `oct` JWK whose `alg` is a content encryption algorithm is a CEK, and a
  // CEK is what `dir` consumes — the same role mapping the decrypt side reads.
  // Raw bytes carry no role at all, so nothing is inferred from them.
  const cekRole =
    isJWK(key) && key.kty === "oct" && typeof key.alg === "string"
      ? isContentEncryptionAlgorithm(key.alg)
        ? key.alg
        : undefined
      : undefined;

  if (!alg) {
    if (typeof key === "string") {
      alg = "PBES2-HS256+A128KW";
    } else if (cekRole) {
      alg = "dir";
    } else if (isJWK(key)) {
      alg = key.alg;
    }
  }
  if (!alg) {
    throw new JWTError(
      'JWE "alg" (Key Management Algorithm) must be provided in options or inferable from the key',
      "ERR_JWE_ALG_MISSING",
    );
  }
  if (!enc) {
    if (alg === "dir") {
      // Under `dir` the `enc` rides on the JWK: either as its own `alg` — the
      // algorithm the CEK was minted for — or as an explicit `enc` member.
      enc = cekRole ?? (isJWK(key) ? key.enc : undefined);
      if (!enc) {
        throw new JWTError('JWE "enc" must be provided when alg is "dir"', "ERR_JWE_ENC_MISSING");
      }
    } else {
      enc = isJWK(key) && key.enc !== undefined ? key.enc : "A256GCM";
    }
  }

  // Both algorithms are settled before any key work, so an algorithm the
  // library does not implement fails with the code and message decrypt uses.
  assertJWEAlgSupported(alg);
  assertJWEEncSupported(enc);

  assertProducerCEK(providedCek, enc);
  assertProducerIV(providedContentIV, enc);
  if (alg.startsWith("PBES2")) assertPBES2Params({ p2s, p2c });

  const jweKeyManagementParams: JWEKeyManagementHeaderParameters = {};
  if (keyManagementIV) jweKeyManagementParams.iv = keyManagementIV;
  if (p2s !== undefined) jweKeyManagementParams.p2s = p2s;
  else if (alg.startsWith("PBES2")) jweKeyManagementParams.p2s = secureRandomBytes(16);
  if (p2c !== undefined) jweKeyManagementParams.p2c = p2c;
  else if (alg.startsWith("PBES2")) jweKeyManagementParams.p2c = DEFAULT_PBES2_ITERATIONS;
  if (ecdh?.partyUInfo !== undefined) {
    assertProducerPartyInfo("apu", ecdh.partyUInfo);
    jweKeyManagementParams.apu = ecdh.partyUInfo;
  }
  if (ecdh?.partyVInfo !== undefined) {
    assertProducerPartyInfo("apv", ecdh.partyVInfo);
    jweKeyManagementParams.apv = ecdh.partyVInfo;
  }
  if (ecdh?.ephemeralKey) {
    const parsed = parseEphemeralKey(ecdh.ephemeralKey);
    jweKeyManagementParams.epk = parsed.epk;
    jweKeyManagementParams.epkPrivateKey = parsed.epkPrivateKey;
  }

  const wrappingKeyMaterial = await importKey(resolvePasswordKey(alg, key), {
    alg,
    expect: "public",
  });
  if (alg === "dir") assertDirectKeyRole(key, enc);

  const {
    cek: finalCek,
    encryptedKey: jweEncryptedKey,
    parameters: keyManagementHeaderParams,
  } = await encryptKey(alg, enc, wrappingKeyMaterial, providedCek, jweKeyManagementParams);

  const protectedHeader = _buildJWEHeader(
    alg,
    enc,
    key,
    userHeader,
    keyManagementHeaderParams,
    payload,
  );

  const computedPayload: JWTClaims | undefined = computeJwtTimeClaims(payload, options);

  const plaintextBytes = getPlaintextBytes(computedPayload || payload);

  const protectedHeaderSerialized = serializeProtectedHeader(protectedHeader);
  const protectedHeaderEncoded = base64UrlStringify(protectedHeaderSerialized);

  const aadBytes = textEncoder.encode(protectedHeaderEncoded);
  const contentIVBytes = providedContentIV ?? generateIV(enc);

  const {
    ciphertext: contentCiphertext,
    tag: contentAuthTag,
    iv: actualContentIV,
  } = await joseEncrypt(enc, plaintextBytes, finalCek, contentIVBytes, aadBytes);

  if (!actualContentIV) {
    throw new JWTError("Content encryption IV was not generated or returned.", "ERR_JWE_INVALID");
  }
  if (!contentAuthTag) {
    throw new JWTError(
      "Content encryption auth tag was not generated or returned.",
      "ERR_JWE_INVALID",
    );
  }

  // `dir` and `ECDH-ES` (direct key agreement) have no encrypted key — RFC 7516 §5.2 step 6.
  const encryptedKeyEncoded = jweEncryptedKey ? base64UrlStringify(jweEncryptedKey) : "";

  const jweParts: string[] = [
    protectedHeaderEncoded,
    encryptedKeyEncoded,
    base64UrlStringify(actualContentIV),
    base64UrlStringify(contentCiphertext),
    base64UrlStringify(contentAuthTag),
  ];

  return jweParts.join(".");
}

/**
 * Decrypts a JWE Compact Serialization string.
 *
 * The payload type follows `options.payload` (see {@link JOSEPayloadTypeMap}):
 *
 * - no `payload`, or `payload: "json"` → `T`, the claims (`JWTClaims` unless
 *   given, as in `decrypt<MyClaims>(jwe, key)`);
 * - `payload: "string"` → `string`; `payload: "bytes"` → `Uint8Array`;
 * - a `payload` that is not a literal → the union of what its modes return.
 *
 * @param jwe The JWE Compact Serialization string.
 * @param key The key decryption key (KEK) or a function to look up the key.
 * @param options JWE decryption options.
 * @returns A Promise resolving to an object containing the decrypted plaintext, protected header, CEK, and AAD.
 * @throws If JWE is invalid, decryption fails, or options are not met.
 */
export async function decrypt<T extends Record<string, unknown> = JWTClaims>(
  jwe: string,
  key: CryptoKey | JWKSet | JWEDecryptJWK | string | Uint8Array<ArrayBuffer> | JWKLookupFunction,
  options?: JWEDecryptOptions<"json"> & { forceUint8Array?: false },
): Promise<JWEDecryptResult<T>>;
/** @deprecated `forceUint8Array` is replaced by `payload: "bytes"`; removed in v0.9.0. */
export async function decrypt(
  jwe: string,
  key: CryptoKey | JWKSet | JWEDecryptJWK | string | Uint8Array<ArrayBuffer> | JWKLookupFunction,
  options: JWEDecryptOptions & { forceUint8Array: true },
): Promise<JWEDecryptResult<Uint8Array<ArrayBuffer>>>;
/** Decrypts a compact JWE whose plaintext decodes under `options.payload`; see {@link PayloadOf}. */
export async function decrypt<Mode extends JOSEPayloadMode = JOSEPayloadMode>(
  jwe: string,
  key: CryptoKey | JWKSet | JWEDecryptJWK | string | Uint8Array<ArrayBuffer> | JWKLookupFunction,
  options?: JWEDecryptOptions<Mode>,
): Promise<JWEDecryptResult<PayloadOf<Mode>>>;
export async function decrypt<T extends JOSEPayload>(
  jwe: string,
  key: CryptoKey | JWKSet | JWEDecryptJWK | string | Uint8Array<ArrayBuffer> | JWKLookupFunction,
  options: JWEDecryptOptions = {},
): Promise<JWEDecryptResult<T>> {
  assertCompactToken(jwe, "JWE");
  assertConsumerOptions(options);

  const payloadMode = resolvePayloadMode(options);
  const keyCandidateLimit = resolveLimit(options.limits, "keyCandidates");
  const pbes2Budget = createPBES2Budget(resolveLimit(options.limits, "pbes2Iterations"));

  const parts = jwe.split(".");
  if (parts.length !== 5) {
    throw new JWTError(
      "Invalid JWE: Must contain five sections (RFC7516, section-3).",
      "ERR_JWE_INVALID",
    );
  }
  const [
    protectedHeaderEncoded,
    encryptedKeyEncoded,
    ivEncoded,
    ciphertextEncoded,
    authTagEncoded,
  ] = parts;

  const protectedHeader = decodeProtectedHeader<JWEHeaderParameters>(protectedHeaderEncoded, "JWE");

  // Everything the protected header alone decides — algorithm support, `enc`,
  // compression, `crit`, `typ` — is settled before any key is resolved or
  // imported, so a malformed token never reaches key management.
  assertHeaderAlgorithms(protectedHeader);
  const { alg, enc } = protectedHeader;
  const headerError =
    checkJWEZip(protectedHeader) ?? checkJWEEncAllowed(enc, options.encryptionAlgorithms);
  if (headerError) throw headerError;

  validateCriticalHeadersJWE(protectedHeader, options.recognizedHeaders);

  const typError = checkProtectedTyp(options.typ, protectedHeader, { family: "JWE" });
  if (typError) throw typError;

  const directKeyError = checkJWEDirectEncryptedKey(alg, encryptedKeyEncoded);
  if (directKeyError) throw directKeyError;

  const encryptedKeyBytes = decodeSegment(encryptedKeyEncoded, {
    family: "JWE",
    what: "Encrypted key",
  });
  const contentIVBytes = decodeSegment(ivEncoded, {
    family: "JWE",
    what: "Initialization vector",
  });
  const contentAuthTagBytes = decodeSegment(authTagEncoded, {
    family: "JWE",
    what: "Authentication tag",
  });
  const ciphertextBytes = decodeSegment(ciphertextEncoded, { family: "JWE", what: "Ciphertext" });

  const segmentError = checkJWEContentSegments(enc, contentIVBytes, contentAuthTagBytes);
  if (segmentError) throw segmentError;

  const rawKeyMaterial = await resolveKeyInput(key, {
    header: protectedHeader,
    token: jwe,
    what: "the JWE",
  });

  const algError = checkAlgAllowed(alg, rawKeyMaterial, {
    ctx: JWE_ALG_CTX,
    algorithms: options.algorithms,
    allowSymmetric: options.allowSymmetricJWKSet,
  });
  if (algError) throw algError;

  const unwrapKeyOpts = buildUnwrapKeyOptions(protectedHeader, { alg, enc }, options);

  const aadBytes = textEncoder.encode(protectedHeaderEncoded);

  let cek!: Uint8Array<ArrayBuffer> | CryptoKey;
  let plaintextBytes!: Uint8Array<ArrayBuffer>;

  if (isJWKSet(rawKeyMaterial)) {
    const candidates = getJWKsFromSet(
      rawKeyMaterial,
      buildJWKSetFilter(protectedHeader, {
        op: "enc",
        allowSymmetric: options?.allowSymmetricJWKSet,
      }),
    );
    assertJWKSetCandidates(candidates, { limit: keyCandidateLimit, kid: protectedHeader.kid });
    // A candidate this token was not encrypted to — unusable key material as
    // much as a failed unwrap — only means "try the next one"; the collected
    // reasons become the `cause` when none decrypts.
    let decrypted = false;
    const attempts: JWTError[] = [];
    for (const candidate of candidates) {
      try {
        if (alg === "dir") assertDirectKeyRole(candidate, enc);
        pbes2Budget.spend(unwrapKeyOpts);
        const unwrappingKey = await importKey(candidate, { alg, expect: "private" });
        const candidateCek = await unwrapKey(encryptedKeyBytes, unwrappingKey, unwrapKeyOpts);
        plaintextBytes = await joseDecrypt(
          enc,
          candidateCek,
          ciphertextBytes,
          contentIVBytes,
          contentAuthTagBytes,
          aadBytes,
        );
        cek = candidateCek;
        decrypted = true;
        break;
      } catch (err) {
        attempts.push(asKeyUsageError(err, alg));
      }
    }
    if (!decrypted) {
      throw new JWTError("JWE decryption failed.", "ERR_JWE_DECRYPTION_FAILED", attempts);
    }
  } else {
    if (alg === "dir") assertDirectKeyRole(rawKeyMaterial, enc);
    pbes2Budget.spend(unwrapKeyOpts);
    try {
      const unwrappingKey = await importKey(resolvePasswordKey(alg, rawKeyMaterial), {
        alg,
        expect: "private",
      });
      cek = await unwrapKey(encryptedKeyBytes, unwrappingKey, unwrapKeyOpts);
      plaintextBytes = await joseDecrypt(
        enc,
        cek,
        ciphertextBytes,
        contentIVBytes,
        contentAuthTagBytes,
        aadBytes,
      );
    } catch (error_) {
      if (error_ instanceof JWTError) throw error_;
      throw new JWTError("JWE decryption failed.", "ERR_JWE_DECRYPTION_FAILED", error_);
    }
  }

  const payload = decodeJWEPayload<T>(plaintextBytes, payloadMode);

  validateClaimsIfJson(payload, payloadMode, options);

  const result: JWEDecryptResult<T> = {
    payload,
    protectedHeader,
  };

  if (options.returnCek) {
    result.cek = await exportReturnedCek(cek);
    result.aad = aadBytes;
  }

  return result;
}

function _buildJWEHeader(
  alg: KeyManagementAlgorithm,
  enc: ContentEncryptionAlgorithm,
  key: CryptoKey | JWEEncryptJWK | string | Uint8Array<ArrayBuffer>,
  userHeader: JWEEncryptOptions["protectedHeader"],
  keyManagementParams: JWEHeaderParameters | undefined,
  payload: unknown,
): JWEHeaderParameters {
  const safeHeader = sanitizeObjectCopy<JWEHeaderParameters | undefined>(userHeader);
  // Precedence: top-level `alg`/`enc` > key management params > user header > JWK `kid`.
  // Build imperatively to avoid the intermediate `{ kid }` / spread-output allocations.
  const header = {} as JWEHeaderParameters;
  if (isJWK(key) && key.kid) header.kid = key.kid;
  if (safeHeader) Object.assign(header, safeHeader);
  if (keyManagementParams) Object.assign(header, keyManagementParams);
  header.alg = alg;
  header.enc = enc;
  applyTypDefault(header, payload);
  assertProducerCrit(header, "JWE");
  return header;
}

/** A protected header naming an `alg` and an `enc` the library implements. */
function assertHeaderAlgorithms(header: JWEHeaderParameters): asserts header is JWEProtectedHeader {
  if (!header.alg || !header.enc) {
    throw new JWTError(
      'Invalid JWE: Protected header must be an object with "alg" and "enc" properties.',
      "ERR_JWE_INVALID",
    );
  }
  assertJWEAlgSupported(header.alg);
  assertJWEEncSupported(header.enc);
}
