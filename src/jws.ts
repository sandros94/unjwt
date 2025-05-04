import type {
  JWSHeaderParameters,
  JWSSignOptions,
  JWK,
  JoseAlgorithm,
} from "./types";
import {
  base64UrlEncode,
  base64UrlDecode,
  textEncoder,
  concatUint8Arrays,
  isJWK,
} from "./utils";
import { importKey } from "./jwk";
import { JWS_ALGORITHMS } from "./utils/defaults";

/**
 * Signs a payload and produces a JWS Compact Serialization string.
 *
 * @param payload The payload to sign. Can be a string, ArrayBuffer, or Uint8Array.
 * @param key The signing key, either a CryptoKey or a JWK object.
 * @param options Optional parameters for signing, including protected header parameters.
 * @returns A Promise resolving to the JWS Compact Serialization string.
 * @throws Error if the key type is invalid, the algorithm is unsupported, or signing fails.
 */
export async function sign(
  payload: string | ArrayBuffer | Uint8Array,
  key: CryptoKey | JWK,
  options: JWSSignOptions = {},
): Promise<string> {
  let signingKey: CryptoKey;
  let alg: string | undefined;

  // 1. Import key if it's a JWK
  if (isJWK(key)) {
    alg = key.alg; // Prefer alg from JWK
    signingKey = await importKey(key, { alg: key.alg as JoseAlgorithm });
  } else if (key instanceof CryptoKey) {
    signingKey = key;

    // Try to infer algorithm from key if not in options header (might create edge cases)
    if (!options.protectedHeader?.alg) {
      const keyAlgorithmName = signingKey.algorithm.name.toUpperCase();

      // TODO: might need refinement
      switch (keyAlgorithmName) {
        case "HMAC": {
          const hashLength = (
            signingKey.algorithm as HmacKeyAlgorithm
          ).hash.name.split("-")[1];
          alg = `HS${hashLength}`;
          break;
        }

        case "RSASSA-PKCS1-V1_5": {
          const hashLength = (
            signingKey.algorithm as RsaHashedKeyAlgorithm
          ).hash.name.split("-")[1];
          alg = `RS${hashLength}`;
          break;
        }

        case "RSA-PSS": {
          const hashLength = (
            signingKey.algorithm as RsaHashedKeyAlgorithm
          ).hash.name.split("-")[1];
          alg = `PS${hashLength}`;
          break;
        }

        // No default, should throw
        default: {
          throw new Error(
            `Unsupported key algorithm: ${keyAlgorithmName}. Cannot infer alg.`,
          );
        }
      }
    }
  } else {
    throw new TypeError("Invalid key type. Key must be a CryptoKey or JWK.");
  }

  // 2. Determine Algorithm and Protected Header
  const protectedHeader: JWSHeaderParameters = { ...options.protectedHeader };
  protectedHeader.alg = protectedHeader.alg ?? alg;

  if (!protectedHeader.alg || !(protectedHeader.alg in JWS_ALGORITHMS)) {
    throw new Error(
      `Algorithm must be specified in protectedHeader or JWK, and must be a supported JWS algorithm. Got: ${protectedHeader.alg}`,
    );
  }

  const algInfo =
    JWS_ALGORITHMS[protectedHeader.alg as keyof typeof JWS_ALGORITHMS];
  const algorithm: AlgorithmIdentifier | RsaPssParams =
    "saltLength" in algInfo
      ? { name: algInfo.name, saltLength: algInfo.saltLength } // RSA-PSS
      : { name: algInfo.name }; // HMAC or RSASSA

  // 3. Encode Header and Payload
  const encodedProtectedHeader = base64UrlEncode(
    JSON.stringify(protectedHeader),
  );

  const payloadBytes =
    typeof payload === "string"
      ? textEncoder.encode(payload)
      : payload instanceof Uint8Array
        ? payload
        : new Uint8Array(payload); // Assume ArrayBuffer

  const encodedPayload = base64UrlEncode(payloadBytes);

  // 4. Construct Signing Input
  const signingInput = concatUint8Arrays(
    textEncoder.encode(encodedProtectedHeader),
    textEncoder.encode("."),
    textEncoder.encode(encodedPayload),
  );

  // 5. Sign
  const signature = await crypto.subtle.sign(
    algorithm,
    signingKey,
    signingInput,
  );

  // 6. Encode Signature
  const encodedSignature = base64UrlEncode(new Uint8Array(signature));

  // 7. Assemble JWS
  return `${encodedProtectedHeader}.${encodedPayload}.${encodedSignature}`;
}

/**
 * Verifies a JWS Compact Serialization string.
 *
 * @param jws The JWS Compact Serialization string.
 * @param key The verification key (CryptoKey or JWK) or a function to retrieve the key.
 *          If a function is provided, it receives the protected header and should return a Promise resolving to the CryptoKey or JWK.
 * @param options Optional parameters for verification, including whether to return the payload as a string.
 * @returns A Promise resolving to an object containing the decoded payload and the protected header if verification is successful.
 * @throws Error if the JWS format is invalid, the algorithm is unsupported, the key cannot be retrieved, or verification fails.
 */
export async function verify(
  jws: string,
  key:
    | CryptoKey
    | JWK
    | ((header: JWSHeaderParameters) => Promise<CryptoKey | JWK>),
): Promise<{ payload: string; protectedHeader: JWSHeaderParameters }>;
export async function verify(
  jws: string,
  key:
    | CryptoKey
    | JWK
    | ((header: JWSHeaderParameters) => Promise<CryptoKey | JWK>),
  options?: {
    toString?: true | undefined;
  },
): Promise<{ payload: Uint8Array; protectedHeader: JWSHeaderParameters }>;
export async function verify(
  jws: string,
  key:
    | CryptoKey
    | JWK
    | ((header: JWSHeaderParameters) => Promise<CryptoKey | JWK>),
  options: {
    toString: false;
  },
): Promise<{ payload: string; protectedHeader: JWSHeaderParameters }>;
export async function verify<ToString extends boolean | undefined>(
  jws: string,
  key:
    | CryptoKey
    | JWK
    | ((header: JWSHeaderParameters) => Promise<CryptoKey | JWK>),
  options?: {
    toString?: ToString;
  },
): Promise<{
  payload: ToString extends false ? Uint8Array : string;
  protectedHeader: JWSHeaderParameters;
}> {
  // 1. Parse JWS
  const parts = jws.split(".");
  if (parts.length !== 3) {
    throw new Error(
      "Invalid JWS format: Must contain three parts separated by dots.",
    );
  }
  const [encodedProtectedHeader, encodedPayload, encodedSignature] = parts;

  // 2. Decode Header
  let protectedHeader: JWSHeaderParameters;
  try {
    protectedHeader = JSON.parse(base64UrlDecode(encodedProtectedHeader));
  } catch (error_) {
    throw new Error(
      "Invalid JWS: Failed to decode or parse protected header.",
      {
        cause: error_,
      },
    );
  }

  if (!protectedHeader.alg || !(protectedHeader.alg in JWS_ALGORITHMS)) {
    throw new Error(
      `Unsupported or missing algorithm in JWS header: ${protectedHeader.alg}`,
    );
  }

  // 3. Retrieve/Import Key
  let verificationKey: CryptoKey;
  const retrievedKey: CryptoKey | JWK =
    typeof key === "function" ? await key(protectedHeader) : key;

  if (isJWK(retrievedKey)) {
    // Ensure JWK alg matches header alg if both exist
    if (
      retrievedKey.alg &&
      protectedHeader.alg &&
      retrievedKey.alg !== protectedHeader.alg
    ) {
      throw new Error(
        `JWS header algorithm '${protectedHeader.alg}' does not match JWK algorithm '${retrievedKey.alg}'.`,
      );
    }
    verificationKey = await importKey(retrievedKey, {
      alg: protectedHeader.alg as JoseAlgorithm, // Use header alg for import context
    });
  } else if (retrievedKey instanceof CryptoKey) {
    verificationKey = retrievedKey;
    // TODO: Add checks to ensure the CryptoKey's algorithm is compatible with the header's alg
  } else {
    throw new TypeError(
      "Invalid key type provided or returned by key retrieval function.",
    );
  }

  // 4. Decode Signature
  const signature = base64UrlDecode(encodedSignature, false);

  // 5. Construct Signing Input (same as in sign)
  const signingInput = concatUint8Arrays(
    textEncoder.encode(encodedProtectedHeader),
    textEncoder.encode("."),
    textEncoder.encode(encodedPayload),
  );

  // 6. Determine Algorithm for Verification
  const algInfo =
    JWS_ALGORITHMS[protectedHeader.alg as keyof typeof JWS_ALGORITHMS];
  const algorithm: AlgorithmIdentifier | RsaPssParams =
    "saltLength" in algInfo
      ? { name: algInfo.name, saltLength: algInfo.saltLength } // RSA-PSS
      : { name: algInfo.name }; // HMAC or RSASSA

  // 7. Verify Signature
  const isValid = await crypto.subtle.verify(
    algorithm,
    verificationKey,
    signature,
    signingInput,
  );

  if (!isValid) {
    throw new Error("JWS signature verification failed.");
  }

  // 8. Decode Payload
  const payload = base64UrlDecode(encodedPayload, options?.toString);

  return { payload, protectedHeader };
}
