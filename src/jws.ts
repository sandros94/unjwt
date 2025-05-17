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
  maybeArray,
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
  payload: string | Uint8Array | Record<string, any>,
  key: JWK,
  options?: JWSSignOptions,
): Promise<string>;
export async function sign(
  payload: JWTClaims,
  key: CryptoKey,
  options: JWSSignOptions & { alg: JWSAlgorithm },
): Promise<string>;
export async function sign(
  payload: string | Uint8Array | Record<string, any>,
  key: CryptoKey,
  options: JWSSignOptions & { alg: JWSAlgorithm },
): Promise<string>;
export async function sign(
  payload: JWTClaims,
  key: Uint8Array,
  options: JWSSignOptions & { alg: JWSAlgorithm },
): Promise<string>;
export async function sign(
  payload: string | Uint8Array | Record<string, any>,
  key: Uint8Array,
  options: JWSSignOptions & { alg: JWSAlgorithm },
): Promise<string>;
export async function sign(
  payload: string | Uint8Array | Record<string, any>,
  key: CryptoKey | JWK | Uint8Array,
  options: JWSSignOptions & { alg: JWSAlgorithm },
): Promise<string>;
export async function sign(
  payload: string | Uint8Array | Record<string, any>,
  key: CryptoKey | JWK | Uint8Array,
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
    alg: alg,
    typ:
      additionalProtectedHeader?.typ ??
      (typeof payload === "object" && !(payload instanceof Uint8Array)
        ? "JWT"
        : undefined), // Default typ to JWT for objects
  };

  // Set 'typ' if not provided and payload is an object (and not Uint8Array)
  if (
    protectedHeader.typ === undefined &&
    typeof payload === "object" &&
    !(payload instanceof Uint8Array)
  ) {
    protectedHeader.typ = "JWT";
    protectedHeader.cty ||= "json"; // Indicate original payload was JSON
  }

  if (protectedHeader.b64 === true) {
    delete protectedHeader.b64;
  }

  // 3. Calculate expiresIn for JWT
  let computedPayload: JWTClaims | undefined = undefined;
  if (
    options.expiresIn !== undefined &&
    protectedHeader.typ === "JWT" &&
    typeof payload === "object" &&
    !(payload instanceof Uint8Array) &&
    !payload.exp
  ) {
    computedPayload = { ...payload };
    const currentTime = Math.round(
      (options.currentDate ?? new Date()).getTime() / 1000,
    );
    const iat = typeof payload.iat === "number" ? payload.iat : currentTime;
    computedPayload.iat = iat;
    computedPayload.exp = iat + options.expiresIn;
  }

  const protectedHeaderString = JSON.stringify(protectedHeader);
  const protectedHeaderEncoded = base64UrlEncode(protectedHeaderString);

  // 4. Prepare Payload
  let payloadBytes: Uint8Array;
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
export async function verify<T extends JWTClaims | Uint8Array | string>(
  jws: string,
  key: CryptoKey | JWK | JWKSet | Uint8Array | JWSKeyLookupFunction,
  options?: JWSVerifyOptions,
): Promise<JWSVerifyResult<T>>;
export async function verify(
  jws: string,
  key: CryptoKey | JWK | JWKSet | Uint8Array | JWSKeyLookupFunction,
  options: JWSVerifyOptions & { forceUint8Array: true },
): Promise<JWSVerifyResult<Uint8Array>>;
export async function verify<T extends JWTClaims | Uint8Array | string>(
  jws: string,
  key: CryptoKey | JWK | JWKSet | Uint8Array | JWSKeyLookupFunction,
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
  let signatureBytes: Uint8Array;
  try {
    signatureBytes = base64UrlDecode(signatureEncoded, false);
  } catch (error_) {
    throw new Error(
      `Invalid JWS: Signature is not valid Base64URL (${error_ instanceof Error ? error_.message : error_})`,
    );
  }

  // 5. Obtain and Import Key
  const keyInput: CryptoKey | JWK | JWKSet | Uint8Array =
    typeof key === "function" ? await key(protectedHeader, jws) : key;
  const resolvedKey: CryptoKey | JWK | Uint8Array = isJWKSet(keyInput)
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
    if (useB64) {
      if (options.forceUint8Array) {
        payload = base64UrlDecode(payloadEncoded, false) as T;
      } else {
        const cty = protectedHeader.cty?.toLowerCase();
        const isJsonOutput =
          protectedHeader.typ === "JWT" ||
          cty === "json" ||
          cty === "application/json" ||
          (cty && cty.endsWith("+json"));

        const decodedString = base64UrlDecode(payloadEncoded);
        if (isJsonOutput) {
          if (
            (decodedString.startsWith("{") && decodedString.endsWith("}")) ||
            (decodedString.startsWith("[") && decodedString.endsWith("]"))
          ) {
            try {
              payload = JSON.parse(decodedString) as T;
            } catch {
              // Malformed JSON, return as string
              payload = decodedString as T;
            }
          } else {
            // Declared as JSON but not valid JSON structure, return as string
            payload = decodedString as T;
          }
        } else {
          // Default to string if not JSON and not forced to Uint8Array
          payload = decodedString as T;
        }
      }
    } else {
      // RFC7797: Payload is not Base64URL encoded, payloadEncoded is the raw string
      payload = (
        options.forceUint8Array
          ? textEncoder.encode(payloadEncoded)
          : payloadEncoded
      ) as T;
    }
  } catch (error_) {
    // Catch potential base64 decode errors if payloadEncoded is invalid
    throw new Error(
      `Invalid JWS: Payload decoding failed (${error_ instanceof Error ? error_.message : error_})`,
    );
  }

  // 9. Handle Critical Headers
  if (protectedHeader.crit) {
    const missingHeaderParams = new Set();
    const recognizedParams = new Set([
      ...(options.critical || []), // TODO: remove deprecated option
      ...(options.requiredHeaders || []),
      "alg",
      "typ",
      "cty",
      "kid",
      "jwk",
      "jku",
      "x5c",
      "x5t",
      "x5u",
      "b64",
    ]);

    for (const param of protectedHeader.crit) {
      // `b64` is a special header ant its absence should be considered as valid
      if (
        recognizedParams.has(param) &&
        (param in protectedHeader || param === "b64")
      ) {
        continue;
      }
      missingHeaderParams.add(param);
    }

    if (missingHeaderParams.size > 0) {
      throw new Error(
        `Missing critical header parameters: ${[...missingHeaderParams].join(", ")}`,
      );
    }
  }

  // 10. JWT Claim Validations (if applicable)
  if (payload && typeof payload === "object" && !options.forceUint8Array) {
    const jwtClaims = payload as JWTClaims;
    const clockTolerance = options.clockTolerance ?? 0; // in seconds
    const currentTime = Math.round(
      (options.currentDate ?? new Date()).getTime() / 1000,
    );

    const allRequiredClaims = new Set<string>(options.requiredClaims || []);
    const missingClaims = new Set<string>();
    if (options.issuer) allRequiredClaims.add("iss");
    if (options.audience) allRequiredClaims.add("aud");
    if (options.subject) allRequiredClaims.add("sub");
    if (options.maxTokenAge) allRequiredClaims.add("iat");

    for (const claimName of allRequiredClaims) {
      if (!(claimName in jwtClaims)) {
        missingClaims.add(claimName);
      }
    }

    if (missingClaims.size > 0) {
      throw new Error(
        `Missing required JWT Claims: ${[...missingClaims].join(", ")}`,
      );
    }

    if (options.issuer) {
      const expectedIssuers = maybeArray(options.issuer);
      if (!jwtClaims.iss || !expectedIssuers.includes(jwtClaims.iss)) {
        throw new Error(
          `Invalid JWT "iss" (Issuer) Claim: Expected ${expectedIssuers.join(" or ")}, got ${jwtClaims.iss}`,
        );
      }
    }

    if (options.subject && jwtClaims.sub !== options.subject) {
      throw new Error(
        `Invalid JWT "sub" (Subject) Claim: Expected ${options.subject}, got ${jwtClaims.sub}`,
      );
    }

    if (options.audience) {
      const expectedAudiences = maybeArray(options.audience);
      const claimAudience = maybeArray(jwtClaims.aud || []);
      if (!claimAudience.some((aud) => expectedAudiences.includes(aud))) {
        throw new Error(
          `Invalid JWT "aud" (Audience) Claim: Expected ${expectedAudiences.join(" or ")}, got ${claimAudience.join(", ")}`,
        );
      }
    }

    if (
      typeof jwtClaims.nbf === "number" &&
      jwtClaims.nbf > currentTime + clockTolerance
    ) {
      throw new Error(
        `JWT "nbf" (Not Before) Claim validation failed: Token is not yet valid (nbf: ${new Date(jwtClaims.nbf * 1000).toISOString()})`,
      );
    }

    if (
      typeof jwtClaims.exp === "number" &&
      jwtClaims.exp <= currentTime - clockTolerance
    ) {
      throw new Error(
        `JWT "exp" (Expiration Time) Claim validation failed: Token has expired (exp: ${new Date(jwtClaims.exp * 1000).toISOString()})`,
      );
    }

    if (options.maxTokenAge) {
      if (typeof jwtClaims.iat !== "number") {
        throw new TypeError(
          'JWT "iat" (Issued At) Claim must be a number when maxTokenAge is set.',
        );
      }
      // iat must not be in the future (beyond clock tolerance)
      if (jwtClaims.iat > currentTime + clockTolerance) {
        throw new Error(
          `JWT "iat" (Issued At) Claim validation failed: Token was issued in the future (iat: ${new Date(jwtClaims.iat * 1000).toISOString()})`,
        );
      }
      if (jwtClaims.iat < currentTime - options.maxTokenAge - clockTolerance) {
        throw new Error(
          `JWT "iat" (Issued At) Claim validation failed: Token is too old (maxTokenAge: ${options.maxTokenAge}s, iat: ${new Date(jwtClaims.iat * 1000).toISOString()})`,
        );
      }
    }
  }

  return {
    payload,
    protectedHeader,
  };
}

function validateKeyLength(
  key: JWK | CryptoKey | Uint8Array,
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
