import { textEncoder } from "unsecure/utils";
import { base64UrlStringify } from "./utils/base64.ts";

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
} from "./types/index.ts";
import { importKey } from "./jwk.ts";
import { sign as joseSign } from "./_crypto/index.ts";
import { JWTError } from "./error.ts";
import { isJWK } from "./utils/guards.ts";
import {
  computeJwtTimeClaims,
  getPlaintextBytes,
  parsePayloadText,
  validateCriticalHeadersJWS,
} from "./_jwt-internal.ts";
import {
  JWS_ALG_CTX,
  asKeyUsageError,
  assertCompactToken,
  assertConsumerOptions,
  checkAlgAllowed,
  assertJWSAlgSupported,
  checkJWSB64,
  assertNotStringKey,
  decodeJWSPayload,
  decodeProtectedHeader,
  resolveKeyInput,
  resolveLimit,
  resolvePayloadMode,
  resolveSigningKey,
  serializeProtectedHeader,
  checkProtectedTyp,
  assertOptionEntry,
  validateClaimsIfJson,
  decodeSegment,
} from "./_internal.ts";
import { buildJWSProtectedHeader, verifyWithKey } from "./_jws-internal.ts";

export type * from "./types/jws.ts";
export type { JOSEPayloadMode, JOSEPayloadTypeMap, PayloadOf } from "./types/jwt.ts";
export {
  type JWTErrorCode,
  type KnownJWTErrorCode,
  type JWTErrorCauseMap,
  type UnsecureErrorCode,
  JWTError,
  isJWTError,
  UnsecureError,
  isUnsecureError,
} from "./error.ts";
export { signMulti, verifyMulti, verifyMultiAll, generalToFlattenedJWS } from "./jws-multi.ts";
export { DEFAULT_JOSE_LIMITS } from "./_internal.ts";

/** Creates a JWS Compact Serialization; an object payload is JSON-serialized, `alg` is required unless the JWK carries one. */
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
  let { alg } = options;

  if (!alg) {
    if (isJWK(key) && key.alg) {
      alg = key.alg;
    } else {
      throw new JWTError(
        'JWS "alg" (Algorithm) must be provided in options',
        "ERR_JWS_ALG_MISSING",
      );
    }
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
        'Invalid JWS: unencoded compact payload must not contain "." (RFC 7797 §5.2).',
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
 * Verifies a JWS Compact Serialization against a key, JWK Set or key resolver.
 * The payload type follows `options.payload`: claims `T` for `"json"` (default), `string`, or `Uint8Array`.
 */
export async function verify<T extends object = JWTClaims>(
  jws: string,
  key: CryptoKey | JWKSet | JWSVerifyJWK | Uint8Array<ArrayBuffer> | JWSKeyLookup,
  options?: JWSVerifyOptions<"json"> & { forceUint8Array?: false },
): Promise<JWSVerifyResult<T>>;
/** @deprecated `forceUint8Array` is replaced by `payload: "bytes"`; removed in v0.9.0. */
export async function verify(
  jws: string,
  key: CryptoKey | JWKSet | JWSVerifyJWK | Uint8Array<ArrayBuffer> | JWSKeyLookup,
  options: JWSVerifyOptions & { forceUint8Array: true },
): Promise<JWSVerifyResult<Uint8Array<ArrayBuffer>>>;
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
    allowSymmetric: options.allowSymmetricJWKSet,
  });
  if (algError) throw algError;

  const signingInputBytes = textEncoder.encode(`${protectedHeaderEncoded}.${payloadEncoded}`);

  const verified = await verifyWithKey(alg, keyInput, {
    signature: signatureBytes,
    signingInput: signingInputBytes,
    kid: protectedHeader.kid,
    allowSymmetric: options.allowSymmetricJWKSet,
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
