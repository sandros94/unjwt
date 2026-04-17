import type {
  JWK,
  JWK_Symmetric,
  JWK_Public,
  JWK_Private,
  JWKSet,
  JWSAlgorithm,
  JWSSignOptions,
  JWSHeaderParameters,
  JWSProtectedHeader,
  JWKLookupFunction,
  JWSVerifyOptions,
  JWSVerifyResult,
  JOSEPayload,
  JWTClaims,
} from "./types";
import { importKey, getJWKsFromSet } from "./jwk";
import { sign as joseSign, verify as joseVerify } from "./_crypto";
import { JWTError } from "./error";
import {
  base64UrlEncode,
  base64UrlDecode,
  textEncoder,
  textDecoder,
  isJWK,
  isJWKSet,
  sanitizeObject,
  applyTypCtyDefaults,
  computeJwtTimeClaims,
  decodePayloadFromB64UrlSegment,
  inferJWSAllowedAlgorithms,
  validateCriticalHeadersJWS,
  validateJwtClaims,
} from "./utils";

export type * from "./types/jws";
export { type JWTErrorCode, type JWTErrorCauseMap, JWTError, isJWTError } from "./error";

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
  key: JWK_Symmetric | JWK_Private,
  options?: JWSSignOptions,
): Promise<string>;
export async function sign(
  payload: JOSEPayload,
  key: CryptoKey | Uint8Array<ArrayBuffer>,
  options: JWSSignOptions & { alg: JWSAlgorithm },
): Promise<string>;
export async function sign(
  payload: string | Uint8Array<ArrayBuffer> | Record<string, unknown>,
  key: CryptoKey | JWK_Symmetric | JWK_Private | Uint8Array<ArrayBuffer>,
  options: JWSSignOptions = {},
): Promise<string> {
  const { protectedHeader: userHeader } = options;
  let { alg } = options;

  if (!alg) {
    if (isJWK(key) && key.alg) {
      alg = key.alg as JWSAlgorithm;
    } else {
      throw new JWTError(
        'JWS "alg" (Algorithm) must be provided in options',
        "ERR_JWS_ALG_MISSING",
      );
    }
  }

  // Belt-and-suspenders guard against callers that bypass the type system with `as any`.
  if ((alg as string) === "none") {
    throw new JWTError('"none" is not a valid signing algorithm', "ERR_JWS_ALG_NOT_ALLOWED");
  }

  // 1. Validate and import Key
  const signingKey = await _resolveSigningKey(
    alg,
    await importKey(key, { alg, expect: "private" }),
    "sign",
  );

  // 2. Construct Protected Header
  const protectedHeader = _buildJWSHeader(alg, key, userHeader, payload);

  // 3. Calculate expiresIn for JWT
  const computedPayload: JWTClaims | undefined = computeJwtTimeClaims(
    payload,
    options.expiresIn,
    options.currentDate,
  );

  const protectedHeaderString = JSON.stringify(protectedHeader);
  const protectedHeaderEncoded = base64UrlEncode(protectedHeaderString);

  // 4. Prepare Payload
  let payloadBytes: Uint8Array<ArrayBuffer>;
  if (payload instanceof Uint8Array) {
    payloadBytes = payload;
  } else if (typeof payload === "string") {
    // Handle string payload
    payloadBytes = textEncoder.encode(payload);
  } else if (typeof payload === "object" && payload !== null) {
    payloadBytes = textEncoder.encode(JSON.stringify(computedPayload || payload));
  } else {
    throw new TypeError("Payload must be a string, Uint8Array, or a JSON-serializable object.");
  }

  // 5. Encode Payload (conditionally based on b64 header)
  const useB64 = protectedHeader.b64 !== false;
  const payloadEncoded = useB64 ? base64UrlEncode(payloadBytes) : textDecoder.decode(payloadBytes);

  // 6. Construct Signing Input
  const signingInputString = `${protectedHeaderEncoded}.${payloadEncoded}`;
  const signingInputBytes = textEncoder.encode(signingInputString);

  // 7. Sign
  const signatureBytes = await joseSign(alg, signingKey, signingInputBytes); // signingKey is always CryptoKey
  const signatureEncoded = base64UrlEncode(signatureBytes);

  // 8. Assemble JWS Compact Serialization
  return `${signingInputString}.${signatureEncoded}`;
}

/**
 * Verifies a JWS (JSON Web Signature) in Compact Serialization format.
 *
 * @param jws The JWS Compact Serialization string.
 * @param key The verification key (CryptoKey, JWK, JWKSet, raw symmetric key as Uint8Array, or a function resolving the key or set).
 * @param options Verification options, such as allowed algorithms.
 * @returns A Promise resolving to an object containing the verified payload and protected header.
 * @throws If the JWS is invalid, signature verification fails, or options are not met.
 */
export async function verify<T extends JOSEPayload>(
  jws: string,
  key:
    | CryptoKey
    | JWKSet
    | JWK_Public
    | JWK_Symmetric
    | Uint8Array<ArrayBuffer>
    | JWKLookupFunction,
  options?: JWSVerifyOptions,
): Promise<JWSVerifyResult<T>>;
export async function verify(
  jws: string,
  key:
    | CryptoKey
    | JWKSet
    | JWK_Public
    | JWK_Symmetric
    | Uint8Array<ArrayBuffer>
    | JWKLookupFunction,
  options: JWSVerifyOptions & { forceUint8Array: true },
): Promise<JWSVerifyResult<Uint8Array<ArrayBuffer>>>;
export async function verify<T extends string | Uint8Array<ArrayBuffer> | Record<string, unknown>>(
  jws: string,
  key:
    | CryptoKey
    | JWKSet
    | JWK_Public
    | JWK_Symmetric
    | Uint8Array<ArrayBuffer>
    | JWKLookupFunction,
  options: JWSVerifyOptions = {},
): Promise<JWSVerifyResult<T>> {
  // 1. Parse JWS
  const parts = jws.split(".");
  if (parts.length !== 3) {
    throw new JWTError(
      "Invalid JWS: Must contain three parts separated by dots.",
      "ERR_JWS_INVALID",
    );
  }
  const [protectedHeaderEncoded, payloadEncoded, signatureEncoded] = parts;

  // 2. Decode Header
  let protectedHeader: JWSProtectedHeader;
  try {
    const protectedHeaderString = base64UrlDecode(protectedHeaderEncoded);
    protectedHeader = sanitizeObject<JWSProtectedHeader>(JSON.parse(protectedHeaderString));
  } catch {
    throw new JWTError("Invalid JWS: Protected header could not be decoded.", "ERR_JWS_INVALID");
  }

  if (!protectedHeader || typeof protectedHeader !== "object" || !protectedHeader.alg) {
    throw new JWTError(
      'Invalid JWS: Protected header must be an object with an "alg" property.',
      "ERR_JWS_INVALID",
    );
  }

  const alg = protectedHeader.alg;

  // 3. Check Algorithm Allowed against explicit allowlist (fast path before key resolution).
  if (options.algorithms && !options.algorithms.includes(alg)) {
    throw new JWTError(`Algorithm not allowed: ${alg}`, "ERR_JWS_ALG_NOT_ALLOWED");
  }

  // Validate `typ` Header Parameter
  if (options.typ && protectedHeader.typ !== options.typ) {
    throw new JWTError(
      `Invalid JWS: "typ" (Type) Header Parameter mismatch. Expected "${options.typ}", got "${protectedHeader.typ}".`,
      "ERR_JWS_INVALID",
    );
  }

  // 4. Decode Signature
  let signatureBytes: Uint8Array<ArrayBuffer>;
  try {
    signatureBytes = base64UrlDecode(signatureEncoded, false);
  } catch {
    throw new JWTError("Invalid JWS: Signature could not be decoded.", "ERR_JWS_INVALID");
  }

  // 5. Obtain Key
  const keyInput = typeof key === "function" ? await key(protectedHeader, jws) : key;

  // 5b. If no explicit allowlist, infer one from the key shape and enforce.
  //     Safe default — prevents signer-controlled `alg` from dictating verification.
  if (!options.algorithms) {
    const inferred = inferJWSAllowedAlgorithms(keyInput);
    if (!inferred) {
      throw new JWTError(
        'Cannot infer allowed algorithms from this key; pass "options.algorithms" explicitly.',
        "ERR_JWS_ALG_NOT_ALLOWED",
      );
    }
    if (!inferred.includes(alg)) {
      throw new JWTError(`Algorithm not allowed: ${alg}`, "ERR_JWS_ALG_NOT_ALLOWED");
    }
  }

  // 6. Reconstruct Signing Input
  const signingInputBytes = textEncoder.encode(`${protectedHeaderEncoded}.${payloadEncoded}`);

  // 7. Verify Signature (with multi-key retry for JWKSets)
  if (isJWKSet(keyInput)) {
    const candidates = getJWKsFromSet(keyInput, _buildJWSSetFilter(protectedHeader));
    if (candidates.length === 0) {
      throw new JWTError(
        `No key found in JWK Set${protectedHeader.kid ? ` with kid "${protectedHeader.kid}"` : ""}.`,
        "ERR_JWK_KEY_NOT_FOUND",
      );
    }
    // Malformed candidates (unsupported alg/kty, wrong key usage) surface immediately —
    // the "try next" contract only covers cryptographic signature mismatch, which
    // `joseVerify` reports as `false` rather than by throwing.
    let verified = false;
    for (const candidate of candidates) {
      const verificationKey = await _resolveSigningKey(
        alg,
        await importKey(candidate, { alg, expect: "public" }),
        "verify",
      );
      if (await joseVerify(alg, verificationKey, signatureBytes, signingInputBytes)) {
        verified = true;
        break;
      }
    }
    if (!verified) {
      throw new JWTError("JWS signature verification failed.", "ERR_JWS_SIGNATURE_INVALID");
    }
  } else {
    const verificationKey = await _resolveSigningKey(
      alg,
      await importKey(keyInput, { alg, expect: "public" }),
      "verify",
    );
    const isValid = await joseVerify(alg, verificationKey, signatureBytes, signingInputBytes);
    if (!isValid) {
      throw new JWTError("JWS signature verification failed.", "ERR_JWS_SIGNATURE_INVALID");
    }
  }

  // 8. Decode Payload
  const useB64 = protectedHeader.b64 !== false;
  let payload: T;
  try {
    payload = (
      useB64
        ? decodePayloadFromB64UrlSegment<T>(payloadEncoded as string, options.forceUint8Array)
        : options.forceUint8Array
          ? textEncoder.encode(payloadEncoded)
          : payloadEncoded
    ) as T;
  } catch (error_) {
    throw new JWTError(
      `Invalid JWS: Payload decoding failed (${error_ instanceof Error ? error_.message : error_})`,
      "ERR_JWS_INVALID",
    );
  }

  // 9. Handle Critical Headers
  validateCriticalHeadersJWS(protectedHeader, options.recognizedHeaders);

  // 10. JWT Claim Validations (RFC 7519) — runs for any JSON-object payload; opt out via `validateClaims: false`.
  if (
    payload &&
    typeof payload === "object" &&
    !(payload instanceof Uint8Array) &&
    !options.forceUint8Array &&
    options.validateClaims !== false
  ) {
    validateJwtClaims(payload as JWTClaims, options);
  }

  return {
    payload,
    protectedHeader,
  };
}

async function _resolveSigningKey(
  alg: string,
  key: CryptoKey | Uint8Array<ArrayBuffer>,
  usage: "sign" | "verify",
): Promise<CryptoKey> {
  if (key instanceof Uint8Array) {
    const minBytes = Number.parseInt(alg.slice(2), 10) / 8;
    if (key.length < minBytes) {
      throw new JWTError(`${alg} requires a key of at least ${minBytes} bytes`, "ERR_JWK_INVALID");
    }
    return crypto.subtle.importKey(
      "raw",
      key,
      { name: "HMAC", hash: `SHA-${alg.slice(-3)}` },
      false,
      [usage],
    );
  }
  if (alg.startsWith("RS") || alg.startsWith("PS")) {
    const { modulusLength } = key.algorithm as RsaKeyAlgorithm;
    if (typeof modulusLength !== "number" || modulusLength < 2048) {
      throw new JWTError(
        `${alg} requires a key modulusLength of at least 2048 bits`,
        "ERR_JWK_INVALID",
      );
    }
  }
  return key;
}

function _buildJWSSetFilter(header: JWSProtectedHeader): (k: JWK) => boolean {
  const { kid, alg } = header;
  return (k: JWK) => (!kid || k.kid === kid) && (!k.alg || k.alg === alg);
}

function _buildJWSHeader(
  alg: JWSAlgorithm,
  key: CryptoKey | JWK_Symmetric | JWK_Private | Uint8Array<ArrayBuffer>,
  userHeader: JWSHeaderParameters | undefined,
  payload: unknown,
): JWSProtectedHeader {
  const safeHeader = sanitizeObject<JWSHeaderParameters | undefined>(userHeader);
  const header: JWSProtectedHeader = {
    ...(isJWK(key) && key.kid ? { kid: key.kid } : {}),
    ...safeHeader,
    alg,
  };
  applyTypCtyDefaults(header, payload);
  if (header.b64 === true) delete header.b64;
  return header;
}
