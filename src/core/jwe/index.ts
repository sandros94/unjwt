import { textEncoder } from "unsecure/utils";
import { base64UrlStringify } from "../../utils/base64.ts";

import type {
  JWKSet,
  KeyManagementAlgorithm,
  JWKAlgorithm,
  ContentEncryptionAlgorithm,
} from "../types/jwk.ts";
import type { JOSEPayload, JOSEPayloadMode, JWTClaims, PayloadOf } from "../types/jwt.ts";
import type {
  JWEEncryptJWK,
  JWEDecryptJWK,
  JWEEncryptOptions,
  JWEDecryptOptions,
  JWEDecryptResult,
  JWEHeaderParameters,
  JWEProtectedHeader,
  JWEKeyLookup,
} from "../types/jwe.ts";

import { importKey } from "../_internal/import-key.ts";
import {
  encrypt as joseEncrypt,
  assertPBES2Params,
  generateIV,
  encryptKey,
} from "../_crypto/index.ts";
import { JWTError } from "../../error.ts";
import { isContentEncryptionAlgorithm, isPBES2Algorithm } from "../../utils/algorithms.ts";
import { isJWK } from "../../utils/guards.ts";
import {
  applyTypDefault,
  computeJwtTimeClaims,
  getPlaintextBytes,
  validateCriticalHeadersJWE,
} from "../_internal/jwt.ts";
import { JWE_ALG_CTX, assertJWEAlgSupported, checkJWEEncAllowed } from "./_internal/algorithms.ts";
import {
  assertCompactToken,
  checkProtectedTyp,
  assertOptionEntry,
  assertProducerCrit,
  assertProducerKeyHeaders,
  assertProducerConfirmation,
  assertConsumerOptions,
  decodeProtectedHeader,
  serializeProtectedHeader,
  decodeSegment,
} from "../_internal/headers.ts";
import { assertDirectKeyRole, resolveKeyInput, resolvePasswordKey } from "../_internal/keys.ts";
import {
  assertNoZipOption,
  assertProducerCEK,
  assertProducerIV,
  checkJWEContentSegments,
  checkJWEDirectEncryptedKey,
  checkJWEZip,
} from "./_internal/checks.ts";
import { buildUnwrapKeyOptions, createPBES2Budget, exportReturnedCek } from "./_internal/keys.ts";
import { checkAlgAllowed, assertJWEEncSupported } from "../_internal/algorithms.ts";
import { copyJsonObject } from "../_internal/errors.ts";
import { resolveLimit } from "../_internal/limits.ts";
import { resolvePayloadMode, validateClaimsIfJson } from "../_internal/payload.ts";
import {
  buildKeyManagementParams,
  decodeJWEPayload,
  unwrapAndDecrypt,
} from "./_internal/encrypt-decrypt.ts";

export type * from "../types/jwe.ts";
export type { JOSEPayloadMode, JOSEPayloadTypeMap, PayloadOf } from "../types/jwt.ts";
export {
  type JWTErrorCode,
  type KnownJWTErrorCode,
  type JWTErrorCauseMap,
  type UnsecureErrorCode,
  JWTError,
  isJWTError,
  UnsecureError,
  isUnsecureError,
} from "../../error.ts";
export { encryptMulti, decryptMulti, generalToFlattened } from "./multi.ts";
export { DEFAULT_JOSE_LIMITS } from "../_internal/limits.ts";

/**
 * Encrypt a payload into a JWE Compact Serialization string. `key` is a CryptoKey, a JWK, or
 * a PBES2 password; `alg` is inferred from it when omitted and `enc` defaults to `A256GCM`.
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
  payload: JOSEPayload,
  key: CryptoKey | JWEEncryptJWK | string | Uint8Array<ArrayBuffer>,
  options: JWEEncryptOptions = {},
): Promise<string> {
  assertOptionEntry(options, { label: "options", objects: ["protectedHeader"] });
  assertProducerKeyHeaders(options.protectedHeader, { tier: "protected", family: "JWE" });
  assertProducerConfirmation(payload);
  const {
    protectedHeader: userHeader,
    cek: providedCek,
    contentEncryptionIV: providedContentIV,
    keyManagementIV,
    p2s,
    p2c,
    ecdh,
  } = options;
  let alg: JWKAlgorithm | undefined = options.alg;
  let enc: unknown = options.enc;

  assertNoZipOption(userHeader, "protected");

  // An `oct` JWK whose `alg` is a content encryption algorithm is a CEK for `dir`.
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
      'JWE "alg" must be provided in options or inferable from the key',
      "ERR_JWE_ALG_MISSING",
    );
  }
  if (!enc) {
    if (alg === "dir") {
      enc = cekRole ?? (isJWK(key) ? key.enc : undefined);
      if (!enc) {
        throw new JWTError('JWE "enc" must be provided when alg is "dir"', "ERR_JWE_ENC_MISSING");
      }
    } else {
      enc = isJWK(key) && key.enc !== undefined ? key.enc : "A256GCM";
    }
  }

  assertJWEAlgSupported(alg);
  assertJWEEncSupported(enc);

  assertProducerCEK(providedCek, enc);
  assertProducerIV(providedContentIV, enc);
  if (isPBES2Algorithm(alg)) assertPBES2Params({ p2s, p2c });

  const jweKeyManagementParams = buildKeyManagementParams(alg, {
    keyManagementIV,
    p2s,
    p2c,
    ecdh,
  });

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
 * Decrypt a JWE Compact Serialization string; `key` may be a lookup function.
 * The payload type follows `options.payload` (claims `T` by default).
 * A compact JWE has five sections (RFC 7516 §3).
 */
export async function decrypt<T extends object = JWTClaims>(
  jwe: string,
  key: CryptoKey | JWKSet | JWEDecryptJWK | string | Uint8Array<ArrayBuffer> | JWEKeyLookup,
  options?: JWEDecryptOptions<"json">,
): Promise<JWEDecryptResult<T>>;
/** Decrypts a compact JWE whose plaintext decodes under `options.payload`; see {@link PayloadOf}. */
export async function decrypt<Mode extends JOSEPayloadMode = JOSEPayloadMode>(
  jwe: string,
  key: CryptoKey | JWKSet | JWEDecryptJWK | string | Uint8Array<ArrayBuffer> | JWEKeyLookup,
  options?: JWEDecryptOptions<Mode>,
): Promise<JWEDecryptResult<PayloadOf<Mode>>>;
export async function decrypt(
  jwe: string,
  key: CryptoKey | JWKSet | JWEDecryptJWK | string | Uint8Array<ArrayBuffer> | JWEKeyLookup,
  options: JWEDecryptOptions = {},
): Promise<JWEDecryptResult> {
  assertCompactToken(jwe, "JWE");
  assertConsumerOptions(options);

  const payloadMode = resolvePayloadMode(options);
  const keyCandidateLimit = resolveLimit(options.limits, "keyCandidates");
  const pbes2Budget = createPBES2Budget(resolveLimit(options.limits, "pbes2Iterations"));

  const parts = jwe.split(".");
  if (parts.length !== 5) {
    throw new JWTError("Invalid JWE: Must contain five sections.", "ERR_JWE_INVALID");
  }
  const [
    protectedHeaderEncoded,
    encryptedKeyEncoded,
    ivEncoded,
    ciphertextEncoded,
    authTagEncoded,
  ] = parts;

  const protectedHeader = decodeProtectedHeader(protectedHeaderEncoded, "JWE");

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
  });
  if (algError) throw algError;

  const unwrapKeyOpts = buildUnwrapKeyOptions(protectedHeader, { alg, enc }, options);

  const aadBytes = textEncoder.encode(protectedHeaderEncoded);

  const { cek, plaintextBytes } = await unwrapAndDecrypt(alg, rawKeyMaterial, {
    enc,
    encryptedKey: encryptedKeyBytes,
    unwrapKeyOptions: unwrapKeyOpts,
    ciphertext: ciphertextBytes,
    iv: contentIVBytes,
    tag: contentAuthTagBytes,
    aad: aadBytes,
    kid: protectedHeader.kid,
    keyCandidates: keyCandidateLimit,
    pbes2Budget,
  });

  const payload = decodeJWEPayload(plaintextBytes, payloadMode);

  validateClaimsIfJson(payload, payloadMode, options);

  const result: JWEDecryptResult = {
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
  const safeHeader = copyJsonObject<JWEHeaderParameters | undefined>(userHeader, {
    code: "ERR_INVALID_OPTION",
    message: '"protectedHeader" must hold only JSON values.',
  });
  // Precedence: top-level `alg`/`enc` > key management params > user header > JWK `kid`.
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
      'Invalid JWE: Protected header must carry "alg" and "enc".',
      "ERR_JWE_INVALID",
    );
  }
  assertJWEAlgSupported(header.alg);
  assertJWEEncSupported(header.enc);
}
