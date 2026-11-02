import { textEncoder } from "unsecure/utils";
import { base64UrlStringify } from "../../utils/base64.ts";

import type {
  JWKSet,
  JWSSignJWK,
  JWSVerifyJWK,
  JWSAlgorithm,
  JWSSignOptions,
  JWSKeyLookup,
  JWSVerifyOptions,
  JWSVerifyResult,
  JOSEPayload,
  JOSEPayloadMode,
  JWTClaims,
  PayloadOf,
} from "../types/index.ts";
import { importKey } from "../_internal/import-key.ts";
import { sign as joseSign } from "../_crypto/index.ts";
import { JWTError } from "../../error.ts";
import { isJWK } from "../../utils/guards.ts";
import {
  computeJwtTimeClaims,
  getPlaintextBytes,
  parsePayloadText,
  validateCriticalHeadersJWS,
} from "../_internal/jwt.ts";
import { JWS_ALG_CTX, checkAlgAllowed } from "../_internal/algorithms.ts";
import {
  asKeyUsageError,
  assertNotStringKey,
  resolveSigningKey,
  signingAlgOf,
} from "./_internal/keys.ts";
import {
  assertCompactToken,
  assertConsumerOptions,
  assertProducerKeyHeaders,
  assertProducerConfirmation,
  decodeProtectedHeader,
  serializeProtectedHeader,
  checkProtectedTyp,
  assertOptionEntry,
  decodeSegment,
} from "../_internal/headers.ts";
import { assertJWSAlgSupported } from "./_internal/algorithms.ts";
import { checkJWSB64, decodeJWSPayload } from "./_internal/b64.ts";
import { resolveKeyInput } from "../_internal/keys.ts";
import { resolveLimit } from "../_internal/limits.ts";
import { resolvePayloadMode, validateClaimsIfJson } from "../_internal/payload.ts";
import { buildJWSProtectedHeader, verifyWithKey } from "./_internal/sign-verify.ts";

export type * from "../types/jws.ts";
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
export { signMulti, verifyMulti, verifyMultiAll, generalToFlattenedJWS } from "./multi.ts";
export { DEFAULT_JOSE_LIMITS } from "../_internal/limits.ts";

/**
 * Signs `payload` and returns a JWS Compact Serialization (RFC 7515 §7.1).
 * An object payload is serialized as JSON and gets `typ: "JWT"` unless `protectedHeader` sets one.
 * Pass `alg` unless the JWK names one or is an EC or Ed25519 JWK, whose curve names it (`ES256`, `ES384`, `ES512`, `EdDSA`).
 * With `b64: false`, the payload must not contain "." (RFC 7797 §5.2).
 *
 * @throws `ERR_JWS_ALG_MISSING` if no `alg` is given and the key names none: a `CryptoKey`, raw bytes, or an RSA or `oct` JWK without `alg`.
 * @throws `ERR_JWS_ALG_NOT_ALLOWED` if `alg` is `"none"` or not a supported signing algorithm.
 * @throws `ERR_JWK_INVALID` if the key is a string or cannot sign with `alg`.
 * @throws `ERR_INVALID_OPTION` if an option is malformed, or a time option is set on a string or bytes payload.
 * @throws `ERR_JWT_CLAIM_INVALID` if both members of a time option pair are set, or `cnf.jwk` is not a public JWK.
 * @throws `ERR_JWS_INVALID` if an unencoded payload contains ".".
 */
export async function sign(
  payload: JOSEPayload,
  key: JWSSignJWK,
  options?: JWSSignOptions,
): Promise<string>;
export async function sign(
  payload: JOSEPayload,
  key: CryptoKey | Uint8Array<ArrayBuffer>,
  options: JWSSignOptions & { alg: JWSAlgorithm },
): Promise<string>;
export async function sign(
  payload: JOSEPayload,
  key: CryptoKey | JWSSignJWK | Uint8Array<ArrayBuffer>,
  options: JWSSignOptions = {},
): Promise<string> {
  assertOptionEntry(options, { label: "options", objects: ["protectedHeader"] });
  assertNotStringKey(key);

  const { protectedHeader: userHeader } = options;
  assertProducerKeyHeaders(userHeader, { tier: "protected", family: "JWS" });
  assertProducerConfirmation(payload);
  let { alg } = options;

  alg ??= isJWK(key) ? signingAlgOf(key) : undefined;
  if (!alg) {
    throw new JWTError(
      'JWS "alg" must be provided in options or inferable from the key',
      "ERR_JWS_ALG_MISSING",
    );
  }

  assertJWSAlgSupported(alg);

  let signingKey: CryptoKey;
  try {
    signingKey = await resolveSigningKey(
      alg,
      await importKey(key, { alg, expect: "private" }),
      "sign",
    );
  } catch (error) {
    throw asKeyUsageError(error, alg);
  }

  const protectedHeader = buildJWSProtectedHeader(alg, key, userHeader, { payload });

  const computedPayload: JWTClaims | undefined = computeJwtTimeClaims(payload, options);

  const protectedHeaderString = serializeProtectedHeader(protectedHeader);
  const protectedHeaderEncoded = base64UrlStringify(protectedHeaderString);

  const payloadBytes = getPlaintextBytes(computedPayload || payload);

  // RFC 7797: `b64: false` leaves the payload unencoded.
  const useB64 = protectedHeader.b64 !== false;
  let payloadEncoded: string;
  if (useB64) {
    payloadEncoded = base64UrlStringify(payloadBytes);
  } else {
    payloadEncoded = parsePayloadText(payloadBytes);
    if (payloadEncoded.includes(".")) {
      throw new JWTError(
        'Invalid JWS: unencoded compact payload must not contain ".".',
        "ERR_JWS_INVALID",
      );
    }
  }

  const signingInputString = `${protectedHeaderEncoded}.${payloadEncoded}`;
  const signingInputBytes = textEncoder.encode(signingInputString);

  let signatureBytes: Uint8Array<ArrayBuffer>;
  try {
    signatureBytes = await joseSign(alg, signingKey, signingInputBytes);
  } catch (error) {
    throw asKeyUsageError(error, alg);
  }
  const signatureEncoded = base64UrlStringify(signatureBytes);

  return `${signingInputString}.${signatureEncoded}`;
}

/**
 * Verifies a JWS Compact Serialization against a key, a JWK Set or a key lookup function.
 * The header `alg` must be in `algorithms`, else match the JWK's `alg`, else fit the key type.
 * Pass `algorithms` for a raw-bytes key.
 * The payload type follows `options.payload`: claims `T` for `"json"` (default), `string`, or `Uint8Array`.
 * A `"json"` payload has its claims validated unless `validateClaims: false`.
 *
 * @throws `ERR_JWS_INVALID` if the token is malformed, its `b64` or `typ` is wrong, or a `crit` member is not recognized.
 * @throws `ERR_JWS_ALG_NOT_ALLOWED` if the header `alg` is unsupported or not allowed for the key.
 * @throws `ERR_JWS_SIGNATURE_INVALID` if the signature does not verify.
 * @throws `ERR_JWK_INVALID` if no key is given, or the key cannot verify with the header `alg`.
 * @throws `ERR_JWK_KEY_NOT_FOUND` if the lookup returns `undefined` or throws an error that is not a `JWTError` (as `cause`), or a JWK Set has no candidate.
 * @throws `ERR_INVALID_OPTION` if an option is malformed, or a claim option is set where claims are not validated.
 * @throws `ERR_JWT_EXPIRED` if `exp` has passed or the token is older than `maxTokenAge`.
 * @throws `ERR_JWT_NBF` if `nbf` is in the future.
 * @throws `ERR_JWT_CLAIM_INVALID` if a claim does not match its option or has the wrong type.
 * @throws `ERR_JWT_CLAIM_MISSING` if a claim in `requiredClaims` or one an option checks is absent.
 */
export async function verify<T extends object = JWTClaims>(
  jws: string,
  key: CryptoKey | JWKSet | JWSVerifyJWK | Uint8Array<ArrayBuffer> | JWSKeyLookup,
  options?: JWSVerifyOptions<"json">,
): Promise<JWSVerifyResult<T>>;
export async function verify<Mode extends JOSEPayloadMode = JOSEPayloadMode>(
  jws: string,
  key: CryptoKey | JWKSet | JWSVerifyJWK | Uint8Array<ArrayBuffer> | JWSKeyLookup,
  options?: JWSVerifyOptions<Mode>,
): Promise<JWSVerifyResult<PayloadOf<Mode>>>;
export async function verify(
  jws: string,
  key: CryptoKey | JWKSet | JWSVerifyJWK | Uint8Array<ArrayBuffer> | JWSKeyLookup,
  options: JWSVerifyOptions = {},
): Promise<JWSVerifyResult> {
  assertCompactToken(jws, "JWS");
  assertConsumerOptions(options);

  const payloadMode = resolvePayloadMode(options);
  const keyCandidateLimit = resolveLimit(options.limits, "keyCandidates");

  const parts = jws.split(".");
  if (parts.length !== 3) {
    throw new JWTError(
      "Invalid JWS: Must contain three parts separated by dots.",
      "ERR_JWS_INVALID",
    );
  }
  const [protectedHeaderEncoded, payloadEncoded, signatureEncoded] = parts;

  const protectedHeader = decodeProtectedHeader(protectedHeaderEncoded, "JWS");

  if (!protectedHeader.alg) {
    throw new JWTError(
      'Invalid JWS: Protected header must be an object with an "alg" property.',
      "ERR_JWS_INVALID",
    );
  }

  const alg = protectedHeader.alg;

  assertJWSAlgSupported(alg);

  const headerError =
    checkJWSB64(protectedHeader) ??
    checkProtectedTyp(options.typ, protectedHeader, { family: "JWS" });
  if (headerError) throw headerError;

  const signatureBytes = decodeSegment(signatureEncoded, { family: "JWS", what: "Signature" });

  const keyInput = await resolveKeyInput(key, {
    header: protectedHeader,
    token: jws,
    what: "the JWS",
  });
  assertNotStringKey(keyInput);

  const algError = checkAlgAllowed(alg, keyInput, {
    ctx: JWS_ALG_CTX,
    algorithms: options.algorithms,
  });
  if (algError) throw algError;

  const signingInputBytes = textEncoder.encode(`${protectedHeaderEncoded}.${payloadEncoded}`);

  const verified = await verifyWithKey(alg, keyInput, {
    signature: signatureBytes,
    signingInput: signingInputBytes,
    kid: protectedHeader.kid,
    keyCandidates: keyCandidateLimit,
  });
  if (!verified) {
    throw new JWTError("JWS signature verification failed.", "ERR_JWS_SIGNATURE_INVALID");
  }

  validateCriticalHeadersJWS(protectedHeader, options.recognizedHeaders);

  // RFC 7797: `b64: false` leaves the payload unencoded.
  const useB64 = protectedHeader.b64 !== false;
  const payload = decodeJWSPayload(payloadEncoded, useB64, payloadMode);

  validateClaimsIfJson(payload, payloadMode, options);

  return {
    payload,
    protectedHeader,
  };
}
