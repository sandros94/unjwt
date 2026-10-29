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
 * Encrypts `payload` and returns a JWE Compact Serialization (RFC 7516 §7.1).
 * `key` is a `CryptoKey`, a JWK, raw bytes, or a password string for PBES2.
 * Without `alg`, a password uses `PBES2-HS256+A128KW` and an `oct` JWK whose `alg` is an `enc` uses `dir`.
 * Any other JWK uses its own `alg`.
 * Without `enc`, the JWK's `enc` applies, else `A256GCM`. For `dir`, `enc` comes from the CEK JWK.
 *
 * @throws `ERR_JWE_ALG_MISSING` if no `alg` is given and none can be inferred.
 * @throws `ERR_JWE_ENC_MISSING` if `alg` is `dir` and neither `enc` nor the JWK names one.
 * @throws `ERR_JWE_ALG_NOT_ALLOWED` if `alg` is `"none"` or not a supported key management algorithm.
 * @throws `ERR_JWE_INVALID` if `enc` is not a supported content encryption algorithm.
 * @throws `ERR_JWK_INVALID` if the key cannot serve `alg`, or a string key is used without PBES2.
 * @throws `ERR_INVALID_OPTION` if an option is malformed, `cek` or `contentEncryptionIV` has the wrong length, or a time option is set on a string or bytes payload.
 * @throws `ERR_JWT_CLAIM_INVALID` if both members of a time option pair are set, or `cnf.jwk` is not a public JWK.
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

  // RFC 7516 §5.2 step 6: `dir` and `ECDH-ES` (direct key agreement) have an empty encrypted key.
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
 * Decrypts a JWE Compact Serialization (RFC 7516 §7.1) with a key, a JWK Set, a password or a key lookup function.
 * The header `alg` must be in `algorithms`, else match the JWK's `alg`, else fit the key type.
 * `encryptionAlgorithms` restricts the header `enc`.
 * The payload type follows `options.payload`: claims `T` for `"json"` (default), `string`, or `Uint8Array`.
 * With `returnCek`, the result includes the CEK and the AAD.
 *
 * @throws `ERR_JWE_INVALID` if the token is malformed, uses `zip`, has the wrong `typ`, an unrecognized `crit` member, or an unsupported `enc`.
 * @throws `ERR_JWE_INVALID` if a PBES2 `p2c` is outside the iteration bounds or `limits.pbes2Iterations`.
 * @throws `ERR_JWE_ALG_NOT_ALLOWED` if the header `alg` is unsupported or not allowed, or `enc` is outside `encryptionAlgorithms`.
 * @throws `ERR_JWE_DECRYPTION_FAILED` if the CEK does not unwrap or the content does not decrypt.
 * @throws `ERR_JWK_INVALID` if no key is given, or the key cannot serve the header `alg`.
 * @throws `ERR_JWK_KEY_NOT_FOUND` if the lookup throws an error that is not a `JWTError` (as `cause`), or a JWK Set has no candidate.
 * @throws `ERR_INVALID_OPTION` if an option is malformed, a claim option is set where claims are not validated, or `returnCek` meets a non-extractable CEK.
 * @throws `ERR_JWT_EXPIRED` if `exp` has passed or the token is older than `maxTokenAge`.
 * @throws `ERR_JWT_NBF` if `nbf` is in the future.
 * @throws `ERR_JWT_CLAIM_INVALID` if a claim does not match its option or has the wrong type.
 * @throws `ERR_JWT_CLAIM_MISSING` if a claim in `requiredClaims` or one an option checks is absent.
 */
export async function decrypt<T extends object = JWTClaims>(
  jwe: string,
  key: CryptoKey | JWKSet | JWEDecryptJWK | string | Uint8Array<ArrayBuffer> | JWEKeyLookup,
  options?: JWEDecryptOptions<"json">,
): Promise<JWEDecryptResult<T>>;
/** Decrypts a JWE Compact Serialization whose plaintext decodes under `options.payload`. See {@link PayloadOf}. */
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

/** Asserts the protected header names a supported `alg` and `enc`. */
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
