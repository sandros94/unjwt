import type {
  JWK,
  JWKSet,
  JWSAlgorithm,
  JWSSignOptions,
  JWSProtectedHeader,
  JWSKeyLookupFunction,
  JWSVerifyOptions,
  JWSVerifyResult,
  JWTClaims,
} from "./types";
import { importKey, getJWKFromSet } from "./jwk";
import { sign as joseSign, verify as joseVerify } from "./jose";
import {
  base64UrlEncode,
  base64UrlDecode,
  textEncoder,
  textDecoder,
  isJWK,
  isJWKSet,
  applyTypCtyDefaults,
  computeJwtTimeClaims,
  decodePayloadFromB64UrlSegment,
  validateCriticalHeadersJWS,
  validateJwtClaims,
} from "./utils";

export * from "./types/jws";

/**
 * Creates a JWS (JSON Web Signature) in Compact Serialization format.
 *
 * @param payload The payload to sign. Can be a string, Uint8Array, or an object (which will be JSON stringified).
 * @param key The signing key (CryptoKey, JWK, or raw symmetric key as Uint8Array).
 * @param options Signing options, including the algorithm (`alg`) and protected header parameters.
 * @returns A Promise resolving to the JWS Compact Serialization string.
 */
export async function sign(
  payload: JWTClaims,
  key: JWK,
  options?: JWSSignOptions,
): Promise<string>;
export async function sign(
  payload: string | Uint8Array<ArrayBuffer> | Record<string, any>,
  key: JWK,
  options?: JWSSignOptions,
): Promise<string>;
export async function sign(
  payload: JWTClaims,
  key: CryptoKey,
  options: JWSSignOptions & { alg: JWSAlgorithm },
): Promise<string>;
export async function sign(
  payload: string | Uint8Array<ArrayBuffer> | Record<string, any>,
  key: CryptoKey,
  options: JWSSignOptions & { alg: JWSAlgorithm },
): Promise<string>;
export async function sign(
  payload: JWTClaims,
  key: Uint8Array<ArrayBuffer>,
  options: JWSSignOptions & { alg: JWSAlgorithm },
): Promise<string>;
export async function sign(
  payload: string | Uint8Array<ArrayBuffer> | Record<string, any>,
  key: Uint8Array<ArrayBuffer>,
  options: JWSSignOptions & { alg: JWSAlgorithm },
): Promise<string>;
export async function sign(
  payload: string | Uint8Array<ArrayBuffer> | Record<string, any>,
  key: CryptoKey | JWK | Uint8Array<ArrayBuffer>,
  options: JWSSignOptions & { alg: JWSAlgorithm },
): Promise<string>;
export async function sign(
  payload: string | Uint8Array<ArrayBuffer> | Record<string, any>,
  key: CryptoKey | JWK | Uint8Array<ArrayBuffer>,
  options: JWSSignOptions = {},
): Promise<string> {
  const { protectedHeader: additionalProtectedHeader } = options;
  let { alg } = options;

  if (!alg) {
    if (isJWK(key) && key.alg) {
      alg = key.alg as JWSAlgorithm;
    } else {
      throw new TypeError('JWS "alg" (Algorithm) must be provided in options');
    }
  }

  // 1. Validate and import Key
  validateKeyLength(key, alg);
  const signingKey = await importKey(key as any, alg);

  // 2. Construct Protected Header
  const protectedHeader: JWSProtectedHeader = {
    ...additionalProtectedHeader,
    ...(isJWK(key) && key.kid
      ? { kid: additionalProtectedHeader?.kid || key.kid }
      : {}), // Include kid if available
    alg: alg,
    typ: additionalProtectedHeader?.typ,
  };

  applyTypCtyDefaults(protectedHeader, payload);

  if (protectedHeader.b64 === true) {
    delete protectedHeader.b64;
  }

  // 3. Calculate expiresIn for JWT
  const computedPayload: JWTClaims | undefined = computeJwtTimeClaims(
    payload,
    protectedHeader.typ,
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
    payloadBytes = textEncoder.encode(
      JSON.stringify(computedPayload || payload),
    );
  } else {
    throw new TypeError(
      "Payload must be a string, Uint8Array, or a JSON-serializable object.",
    );
  }

  // 5. Encode Payload (conditionally based on b64 header)
  const useB64 = protectedHeader.b64 !== false;
  const payloadEncoded = useB64
    ? base64UrlEncode(payloadBytes)
    : textDecoder.decode(payloadBytes);

  // 6. Construct Signing Input
  const signingInputString = `${protectedHeaderEncoded}.${payloadEncoded}`;
  const signingInputBytes = textEncoder.encode(signingInputString);

  // 7. Sign
  const signatureBytes = await joseSign(alg, signingKey, signingInputBytes);
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
export async function verify<
  T extends JWTClaims | Uint8Array<ArrayBuffer> | string,
>(
  jws: string,
  key:
    | CryptoKey
    | JWK
    | JWKSet
    | Uint8Array<ArrayBuffer>
    | JWSKeyLookupFunction,
  options?: JWSVerifyOptions,
): Promise<JWSVerifyResult<T>>;
export async function verify(
  jws: string,
  key:
    | CryptoKey
    | JWK
    | JWKSet
    | Uint8Array<ArrayBuffer>
    | JWSKeyLookupFunction,
  options: JWSVerifyOptions & { forceUint8Array: true },
): Promise<JWSVerifyResult<Uint8Array<ArrayBuffer>>>;
export async function verify<
  T extends JWTClaims | Uint8Array<ArrayBuffer> | string,
>(
  jws: string,
  key:
    | CryptoKey
    | JWK
    | JWKSet
    | Uint8Array<ArrayBuffer>
    | JWSKeyLookupFunction,
  options: JWSVerifyOptions = {},
): Promise<JWSVerifyResult<T>> {
  // 1. Parse JWS
  const parts = jws.split(".");
  if (parts.length !== 3) {
    throw new Error("Invalid JWS: Must contain three parts separated by dots.");
  }
  const [protectedHeaderEncoded, payloadEncoded, signatureEncoded] = parts;

  // 2. Decode Header
  let protectedHeader: JWSProtectedHeader;
  try {
    const protectedHeaderString = base64UrlDecode(protectedHeaderEncoded);
    protectedHeader = JSON.parse(protectedHeaderString);
  } catch (error_) {
    throw new Error(
      `Invalid JWS: Protected header is not valid Base64URL or JSON (${error_ instanceof Error ? error_.message : error_})`,
    );
  }

  if (
    !protectedHeader ||
    typeof protectedHeader !== "object" ||
    !protectedHeader.alg
  ) {
    throw new Error(
      'Invalid JWS: Protected header must be an object with an "alg" property.',
    );
  }

  const alg = protectedHeader.alg;

  // 3. Check Algorithm Allowed (if options provided)
  if (options.algorithms && !options.algorithms.includes(alg)) {
    throw new Error(`Algorithm not allowed: ${alg}`);
  }

  // Validate `typ` Header Parameter
  if (options.typ && protectedHeader.typ !== options.typ) {
    throw new Error(
      `Invalid JWS: "typ" (Type) Header Parameter mismatch. Expected "${options.typ}", got "${protectedHeader.typ}".`,
    );
  }

  // 4. Decode Signature
  let signatureBytes: Uint8Array<ArrayBuffer>;
  try {
    signatureBytes = base64UrlDecode(signatureEncoded, false);
  } catch (error_) {
    throw new Error(
      `Invalid JWS: Signature is not valid Base64URL (${error_ instanceof Error ? error_.message : error_})`,
    );
  }

  // 5. Obtain and Import Key
  const keyInput: CryptoKey | JWK | JWKSet | Uint8Array<ArrayBuffer> =
    typeof key === "function" ? await key(protectedHeader, jws) : key;
  const resolvedKey: CryptoKey | JWK | Uint8Array<ArrayBuffer> = isJWKSet(
    keyInput,
  )
    ? getJWKFromSet(keyInput, protectedHeader)
    : keyInput;

  const verificationKey = await importKey(resolvedKey as any, alg);

  // 6. Reconstruct Signing Input
  const signingInputString = `${protectedHeaderEncoded}.${payloadEncoded}`;
  const signingInputBytes = textEncoder.encode(signingInputString);

  // 7. Verify Signature
  const isValid = await joseVerify(
    alg,
    verificationKey,
    signatureBytes,
    signingInputBytes,
  );

  if (!isValid) {
    throw new Error("JWS signature verification failed.");
  }

  // 8. Decode Payload
  const useB64 = protectedHeader.b64 !== false;
  let payload: T;
  try {
    payload = (
      useB64
        ? decodePayloadFromB64UrlSegment<T>(
            payloadEncoded as string,
            protectedHeader,
            options.forceUint8Array,
          )
        : options.forceUint8Array
          ? textEncoder.encode(payloadEncoded)
          : payloadEncoded
    ) as T;
  } catch (error_) {
    throw new Error(
      `Invalid JWS: Payload decoding failed (${error_ instanceof Error ? error_.message : error_})`,
    );
  }

  // 9. Handle Critical Headers
  validateCriticalHeadersJWS(protectedHeader, [
    ...(options.critical || []),
    ...(options.requiredHeaders || []),
  ]);

  // 10. JWT Claim Validations (if applicable)
  if (
    payload &&
    typeof payload === "object" &&
    (protectedHeader.typ === "at+jwt" || protectedHeader.typ === "JWT") &&
    !options.forceUint8Array
  ) {
    validateJwtClaims(payload as JWTClaims, options);
  }

  return {
    payload,
    protectedHeader,
  };
}

function validateKeyLength(
  key: JWK | CryptoKey | Uint8Array<ArrayBuffer>,
  alg?: string,
): void {
  if (!alg || isJWK(key)) return;

  if (alg.startsWith("HS") && key instanceof Uint8Array) {
    const algLength = Number.parseInt(alg.slice(2)) / 8; // in bytes

    if (key.length < algLength) {
      throw new TypeError(
        `${alg} requires key length to be ${algLength} bytes or larger`,
      );
    }
  } else if (
    (alg.startsWith("RS") || alg.startsWith("PS")) &&
    key instanceof CryptoKey
  ) {
    const { modulusLength } = key.algorithm as RsaKeyAlgorithm;
    if (typeof modulusLength !== "number" || modulusLength < 2048) {
      throw new TypeError(
        `${alg} requires key modulusLength to be 2048 bits or larger`,
      );
    }
  }
}
