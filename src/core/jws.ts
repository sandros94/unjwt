import { sanitizeObjectCopy } from "unsecure/sanitize";
import { textEncoder } from "unsecure/utils";
import { base64UrlStringify } from "./utils/base64";

import type {
  JWKSet,
  JWSSignJWK,
  JWSVerifyJWK,
  JWSAlgorithm,
  JWSSignOptions,
  JWSHeaderParameters,
  JWSProtectedHeader,
  JWKLookupFunction,
  JWSVerifyOptions,
  JWSVerifyResult,
  JOSEPayload,
  JOSEPayloadMode,
  JWTClaims,
  PayloadOf,
} from "./types";
import { importKey, getJWKsFromSet } from "./jwk";
import { sign as joseSign, verify as joseVerify } from "./_crypto";
import { JWTError } from "./error";
import { isJWK, isJWKSet } from "./utils/guards";
import {
  applyTypDefault,
  computeJwtTimeClaims,
  getPlaintextBytes,
  parsePayloadText,
  validateCriticalHeadersJWS,
} from "./_jwt-internal";
import {
  JWS_ALG_CTX,
  applyB64Header,
  assertProducerCrit,
  asKeyUsageError,
  assertCompactToken,
  assertConsumerOptions,
  assertJWKSetCandidates,
  buildJWKSetFilter,
  checkAlgAllowed,
  checkJWSAlgSupported,
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
} from "./_internal";

export type * from "./types/jws";
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
export { signMulti, verifyMulti, verifyMultiAll, generalToFlattenedJWS } from "./jws-multi";
export { DEFAULT_JOSE_LIMITS } from "./_internal";

/**
 * Creates a JWS (JSON Web Signature) in Compact Serialization format.
 *
 * @param payload The payload to sign. Can be a string, Uint8Array, or an object (which will be JSON stringified).
 * @param key The signing key (CryptoKey, JWK, or raw symmetric key as Uint8Array).
 * @param options Signing options, including the algorithm (`alg`) and protected header parameters.
 * @returns A Promise resolving to the JWS Compact Serialization string.
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
  payload: string | Uint8Array<ArrayBuffer> | Record<string, unknown>,
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

  // The algorithm is settled before any key work, so `"none"` and a misspelled
  // alg fail the same way, with the same code and message, as on verify.
  const algSupportError = checkJWSAlgSupported(alg);
  if (algSupportError) throw algSupportError;

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

  const protectedHeader = _buildJWSHeader(alg, key, userHeader, payload);

  const computedPayload: JWTClaims | undefined = computeJwtTimeClaims(payload, options);

  const protectedHeaderString = serializeProtectedHeader(protectedHeader);
  const protectedHeaderEncoded = base64UrlStringify(protectedHeaderString);

  const payloadBytes = getPlaintextBytes(computedPayload || payload);

  // RFC 7797: when `b64: false`, the payload is not base64url-encoded in the signing input.
  const useB64 = protectedHeader.b64 !== false;
  let payloadEncoded: string;
  if (useB64) {
    payloadEncoded = base64UrlStringify(payloadBytes);
  } else {
    // An unencoded payload travels as text inside the token, so its bytes must
    // be UTF-8; RFC 7797 §5.2 — a "." in it would split the compact form.
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
 * Verifies a JWS (JSON Web Signature) in Compact Serialization format.
 *
 * The payload type follows `options.payload` (see {@link JOSEPayloadTypeMap}):
 *
 * - no `payload`, or `payload: "json"` → `T`, the claims (`JWTClaims` unless
 *   given, as in `verify<MyClaims>(jws, key)`);
 * - `payload: "string"` → `string`; `payload: "bytes"` → `Uint8Array`;
 * - a `payload` that is not a literal → the union of what its modes return.
 *
 * @param jws The JWS Compact Serialization string.
 * @param key The verification key (CryptoKey, JWK, JWKSet, raw symmetric key as Uint8Array, or a function resolving the key or set).
 * @param options Verification options, such as allowed algorithms.
 * @returns A Promise resolving to an object containing the verified payload and protected header.
 * @throws If the JWS is invalid, signature verification fails, or options are not met.
 */
export async function verify<T extends Record<string, unknown> = JWTClaims>(
  jws: string,
  key: CryptoKey | JWKSet | JWSVerifyJWK | Uint8Array<ArrayBuffer> | JWKLookupFunction,
  options?: JWSVerifyOptions<"json"> & { forceUint8Array?: false },
): Promise<JWSVerifyResult<T>>;
/** @deprecated `forceUint8Array` is replaced by `payload: "bytes"`; removed in v0.9.0. */
export async function verify(
  jws: string,
  key: CryptoKey | JWKSet | JWSVerifyJWK | Uint8Array<ArrayBuffer> | JWKLookupFunction,
  options: JWSVerifyOptions & { forceUint8Array: true },
): Promise<JWSVerifyResult<Uint8Array<ArrayBuffer>>>;
/** Verifies a compact JWS whose payload decodes under `options.payload`; see {@link PayloadOf}. */
export async function verify<Mode extends JOSEPayloadMode = JOSEPayloadMode>(
  jws: string,
  key: CryptoKey | JWKSet | JWSVerifyJWK | Uint8Array<ArrayBuffer> | JWKLookupFunction,
  options?: JWSVerifyOptions<Mode>,
): Promise<JWSVerifyResult<PayloadOf<Mode>>>;
export async function verify<T extends JOSEPayload>(
  jws: string,
  key: CryptoKey | JWKSet | JWSVerifyJWK | Uint8Array<ArrayBuffer> | JWKLookupFunction,
  options: JWSVerifyOptions = {},
): Promise<JWSVerifyResult<T>> {
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

  const protectedHeader = decodeProtectedHeader<JWSProtectedHeader>(protectedHeaderEncoded, "JWS");

  if (!protectedHeader.alg) {
    throw new JWTError(
      'Invalid JWS: Protected header must be an object with an "alg" property.',
      "ERR_JWS_INVALID",
    );
  }

  const alg = protectedHeader.alg;

  const algSupportError = checkJWSAlgSupported(alg);
  if (algSupportError) throw algSupportError;

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

  // Key import, resolution and the WebCrypto call are a single failure boundary:
  // anything they raise that is not already a `JWTError` (WebCrypto `TypeError` /
  // `DOMException`, codec `SyntaxError`, …) means the key cannot serve this alg.
  try {
    if (isJWKSet(keyInput)) {
      const candidates = getJWKsFromSet(
        keyInput,
        buildJWKSetFilter(protectedHeader, {
          op: "sig",
          allowSymmetric: options.allowSymmetricJWKSet,
        }),
      );
      assertJWKSetCandidates(candidates, { limit: keyCandidateLimit, kid: protectedHeader.kid });
      // A candidate this token cannot have been signed with — unusable key
      // material as much as a signature mismatch — only means "try the next
      // one"; the collected reasons become the `cause` when none verifies.
      let verified = false;
      const attempts: JWTError[] = [];
      for (const candidate of candidates) {
        try {
          const verificationKey = await resolveSigningKey(
            alg,
            await importKey(candidate, { alg, expect: "public" }),
            "verify",
          );
          if (await joseVerify(alg, verificationKey, signatureBytes, signingInputBytes)) {
            verified = true;
            break;
          }
          attempts.push(
            new JWTError("JWS signature verification failed.", "ERR_JWS_SIGNATURE_INVALID"),
          );
        } catch (error) {
          attempts.push(asKeyUsageError(error, alg));
        }
      }
      if (!verified) {
        throw new JWTError(
          "JWS signature verification failed.",
          "ERR_JWS_SIGNATURE_INVALID",
          attempts,
        );
      }
    } else {
      const verificationKey = await resolveSigningKey(
        alg,
        await importKey(keyInput, { alg, expect: "public" }),
        "verify",
      );
      const isValid = await joseVerify(alg, verificationKey, signatureBytes, signingInputBytes);
      if (!isValid) {
        throw new JWTError("JWS signature verification failed.", "ERR_JWS_SIGNATURE_INVALID");
      }
    }
  } catch (error) {
    throw asKeyUsageError(error, alg);
  }

  validateCriticalHeadersJWS(protectedHeader, options.recognizedHeaders);

  // RFC 7797: when `b64: false`, the payload segment is the raw payload (not base64url-encoded).
  const useB64 = protectedHeader.b64 !== false;
  const payload = decodeJWSPayload<T>(payloadEncoded, useB64, payloadMode);

  validateClaimsIfJson(payload, payloadMode, options);

  return {
    payload,
    protectedHeader,
  };
}

function _buildJWSHeader(
  alg: JWSAlgorithm,
  key: CryptoKey | JWSSignJWK | Uint8Array<ArrayBuffer>,
  userHeader: JWSHeaderParameters | undefined,
  payload: unknown,
): JWSProtectedHeader {
  const safeHeader = sanitizeObjectCopy<JWSHeaderParameters | undefined>(userHeader);
  // Precedence: top-level `alg` > user header > JWK `kid`. Build imperatively to
  // avoid the intermediate `{ kid }` / spread-output allocations.
  // oxlint-disable-next-line typescript/no-unsafe-type-assertion -- `alg` is assigned below, before the header leaves this function
  const header = {} as JWSProtectedHeader;
  if (isJWK(key) && key.kid) header.kid = key.kid;
  if (safeHeader) Object.assign(header, safeHeader);
  header.alg = alg;
  applyTypDefault(header, payload);
  applyB64Header(header);
  assertProducerCrit(header, "JWS");
  return header;
}
