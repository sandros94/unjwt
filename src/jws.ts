import type {
  JWK,
  JWSSignOptions,
  JWSProtectedHeader,
  JWSVerifyOptions,
  JWSVerifyResult,
  JWTClaims,
} from "./types";
import { importKey } from "./jwk";
import { sign as joseSign, verify as joseVerify } from "./jose";
import {
  base64UrlEncode,
  base64UrlDecode,
  textEncoder,
  textDecoder,
} from "./utils";

/**
 * Creates a JWS (JSON Web Signature) in Compact Serialization format.
 *
 * @param payload The payload to sign. Can be a string, Uint8Array, or an object (which will be JSON stringified).
 * @param key The signing key (CryptoKey, JWK, or raw symmetric key as Uint8Array).
 * @param options Signing options, including the algorithm (`alg`) and protected header parameters.
 * @returns A Promise resolving to the JWS Compact Serialization string.
 */
export async function sign(
  payload: string | Uint8Array | Record<string, any>,
  key: CryptoKey | JWK | Uint8Array,
  options: JWSSignOptions,
): Promise<string> {
  const { alg, protectedHeader: additionalProtectedHeader } = options;

  if (!alg) {
    throw new TypeError('JWS "alg" (Algorithm) must be provided in options');
  }

  // 1. Import Key
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

  if (protectedHeader.b64 === true) {
    delete protectedHeader.b64;
  }

  const protectedHeaderString = JSON.stringify(protectedHeader);
  const protectedHeaderEncoded = base64UrlEncode(
    textEncoder.encode(protectedHeaderString),
  );

  // 3. Prepare Payload
  let payloadBytes: Uint8Array;
  if (payload instanceof Uint8Array) {
    payloadBytes = payload;
  } else if (typeof payload === "string") {
    // Handle string payload
    payloadBytes = textEncoder.encode(payload);
  } else if (typeof payload === "object" && payload !== null) {
    payloadBytes = textEncoder.encode(JSON.stringify(payload));
  } else {
    throw new TypeError(
      "Payload must be a string, Uint8Array, or a JSON-serializable object.",
    );
  }

  // 4. Encode Payload (conditionally based on b64 header)
  const useB64 = protectedHeader.b64 !== false;
  const payloadEncoded = useB64
    ? base64UrlEncode(payloadBytes)
    : textDecoder.decode(payloadBytes);

  // 5. Construct Signing Input
  const signingInputString = `${protectedHeaderEncoded}.${payloadEncoded}`;
  const signingInputBytes = textEncoder.encode(signingInputString);

  // 6. Sign
  const signatureBytes = await joseSign(alg, signingKey, signingInputBytes);
  const signatureEncoded = base64UrlEncode(signatureBytes);

  // 7. Assemble JWS Compact Serialization
  return `${signingInputString}.${signatureEncoded}`;
}

// Type for the key lookup function
type KeyLookupFunction = (
  header: JWSProtectedHeader,
) => CryptoKey | JWK | Uint8Array | Promise<CryptoKey | JWK | Uint8Array>;

/**
 * Verifies a JWS (JSON Web Signature) in Compact Serialization format.
 *
 * @param jws The JWS Compact Serialization string.
 * @param key The verification key (CryptoKey, JWK, raw symmetric key as Uint8Array, or a function resolving the key).
 * @param options Verification options, such as allowed algorithms.
 * @returns A Promise resolving to an object containing the verified payload and protected header.
 * @throws If the JWS is invalid, signature verification fails, or options are not met.
 */
export async function verify<T = Uint8Array | JWTClaims>(
  jws: string,
  key: CryptoKey | JWK | Uint8Array | KeyLookupFunction, // Updated key type
  options?: JWSVerifyOptions,
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
    const protectedHeaderJson = textDecoder.decode(
      base64UrlDecode(protectedHeaderEncoded, false),
    );
    protectedHeader = JSON.parse(protectedHeaderJson);
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
  if (options?.algorithms && !options.algorithms.includes(alg)) {
    throw new Error(`Algorithm not allowed: ${alg}`);
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
  const resolvedKey: CryptoKey | JWK | Uint8Array =
    typeof key === "function" ? await key(protectedHeader) : key;

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
      payload = base64UrlDecode(payloadEncoded, true) as T;
      if (
        typeof payload === "string" &&
        (protectedHeader.typ === "JWT" || protectedHeader.cty === "json") &&
        payload.startsWith("{") &&
        payload.endsWith("}")
      ) {
        try {
          payload = JSON.parse(payload) as T;
        } catch {
          // Ignore parse error
        }
      } else if (
        typeof payload === "string" &&
        protectedHeader.typ !== "JWT" &&
        protectedHeader.cty !== "json"
      ) {
        payload = base64UrlDecode(payloadEncoded, false) as T;
      }
    } else {
      payload = textEncoder.encode(payloadEncoded) as T;
    }
  } catch (error_) {
    throw new Error(
      `Invalid JWS: Payload decoding failed (${error_ instanceof Error ? error_.message : error_})`,
    );
  }

  // 9. Handle Critical Headers
  if (options?.critical && protectedHeader.crit) {
    const recognizedParams = new Set([
      ...Object.keys(protectedHeader),
      ...(options.critical || []),
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
    for (const critParam of protectedHeader.crit) {
      if (!recognizedParams.has(critParam)) {
        throw new Error(
          `Critical header parameter not understood: ${critParam}`,
        );
      }
    }
  } else if (!options?.critical && protectedHeader.crit) {
    throw new Error(
      `Unprocessed critical header parameters: ${protectedHeader.crit.join(", ")}`,
    );
  }

  return {
    payload,
    protectedHeader,
  };
}
