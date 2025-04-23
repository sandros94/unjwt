import type {
  JWSSignOptions,
  JWSHeaderParameters,
  JWSAlgorithm,
  JWSSymmetricAlgorithm,
} from "./types";
import {
  textEncoder,
  textDecoder,
  base64UrlEncode,
  base64UrlDecode,
} from "./utils";
import { JWS_SYMMETRIC_ALGORITHMS } from "./utils/defaults";
import { lookupAlgorithm } from "./utils/algorithms";

import { importRawSymmetricKey } from "./jwk";

/** The default JWS algorithm. */
export const JWS_DEFAULTS = /* @__PURE__ */ Object.freeze({
  alg: "HS256" as JWSSymmetricAlgorithm,
});

/**
 * Signs data using JWS with a symmetric key (HMAC).
 * @param payload The data to sign.
 * @param secret The symmetric secret key.
 * @param options Optional parameters for signing.
 * @returns Promise resolving to the compact JWS token.
 */
export async function sign(
  payload: string | Uint8Array,
  secret: string | Uint8Array,
  options: JWSSignOptions = {},
): Promise<string> {
  if (!secret) {
    throw new Error("Missing secret key");
  }

  const protectedHeader = options.protectedHeader || {};
  const alg = (protectedHeader.alg || JWS_DEFAULTS.alg) as JWSAlgorithm;

  // Validate algorithm
  const algConfig = validateSymmetricAlgorithm(alg);

  // Prepare header
  const header: JWSHeaderParameters = {
    alg,
    typ: "JWT",
    ...protectedHeader,
  };

  // Encode header and payload
  const encodedHeader = base64UrlEncode(
    textEncoder.encode(JSON.stringify(header)),
  );
  const encodedPayload = base64UrlEncode(
    typeof payload === "string" ? textEncoder.encode(payload) : payload,
  );

  // Create signing input
  const signingInput = textEncoder.encode(`${encodedHeader}.${encodedPayload}`);

  // Import key
  const cryptoKey = await importRawSymmetricKey(
    secret,
    { name: "HMAC", hash: algConfig.hash },
    false,
    ["sign"],
  );

  // Sign the input
  const signature = await crypto.subtle.sign(
    { name: "HMAC" },
    cryptoKey,
    signingInput,
  );

  // Encode signature
  const encodedSignature = base64UrlEncode(new Uint8Array(signature));

  // Construct the JWS compact serialization
  return `${encodedHeader}.${encodedPayload}.${encodedSignature}`;
}

/**
 * Verifies a JWS token signed with a symmetric key (HMAC).
 * @param token The JWS token string in compact serialization format.
 * @param secret The symmetric secret key used for signing.
 * @returns Promise resolving to the verified payload as a string.
 */
export async function verify(
  token: string,
  secret: string | Uint8Array,
): Promise<string>;
/**
 * Verifies a JWS token signed with a symmetric key (HMAC).
 * @param token The JWS token string in compact serialization format.
 * @param secret The symmetric secret key used for signing.
 * @param options Verification options.
 * @returns Promise resolving to the verified payload as a string.
 */
export async function verify(
  token: string,
  secret: string | Uint8Array,
  options: { textOutput: true },
): Promise<string>;
/**
 * Verifies a JWS token signed with a symmetric key (HMAC).
 * @param token The JWS token string in compact serialization format.
 * @param secret The symmetric secret key used for signing.
 * @param options Verification options.
 * @returns Promise resolving to the verified payload as a Uint8Array.
 */
export async function verify(
  token: string,
  secret: string | Uint8Array,
  options: { textOutput: false },
): Promise<Uint8Array>;
/**
 * Verifies a JWS token signed with a symmetric key (HMAC).
 * @param token The JWS token string in compact serialization format.
 * @param secret The symmetric secret key used for signing.
 * @param options Verification options.
 * @returns Promise resolving to the verified payload.
 */
export async function verify(
  token: string,
  secret: string | Uint8Array,
  options: {
    /**
     * Whether to return the verified payload as a string (true) or as a Uint8Array (false).
     * @default true
     */
    textOutput?: boolean;
  } = {},
): Promise<string | Uint8Array> {
  if (!token) {
    throw new Error("Missing JWS token");
  }
  if (!secret) {
    throw new Error("Missing secret key");
  }

  const textOutput = options.textOutput !== false;

  // Split the JWS token
  const parts = token.split(".");
  if (parts.length !== 3) {
    throw new Error("Invalid JWS token format");
  }
  const [encodedHeader, encodedPayload, encodedSignature] = parts;

  // Decode header
  const header = JSON.parse(
    textDecoder.decode(base64UrlDecode(encodedHeader)),
  ) as JWSHeaderParameters;
  const alg = header.alg as JWSAlgorithm;

  // Validate algorithm
  const algConfig = validateSymmetricAlgorithm(alg);

  // Prepare data for verification
  const signingInput = textEncoder.encode(`${encodedHeader}.${encodedPayload}`);
  const signature = base64UrlDecode(encodedSignature);

  // Import key
  const cryptoKey = await importRawSymmetricKey(
    secret,
    { name: "HMAC", hash: algConfig.hash },
    false,
    ["verify"],
  );

  // Verify the signature
  const isValid = await crypto.subtle.verify(
    { name: "HMAC" },
    cryptoKey,
    signature,
    signingInput,
  );

  if (!isValid) {
    throw new Error("Signature verification failed");
  }

  // Decode the payload
  const payloadBytes = base64UrlDecode(encodedPayload);

  // Return the payload
  return textOutput ? textDecoder.decode(payloadBytes) : payloadBytes;
}

/**
 * Validates and returns information about a symmetric JWS algorithm.
 * @param alg The algorithm to validate.
 * @returns The algorithm configuration.
 * @throws Error if the algorithm is not supported or not symmetric.
 */
function validateSymmetricAlgorithm(
  alg: keyof typeof JWS_SYMMETRIC_ALGORITHMS,
) {
  // TODO: Check asymmetric algorithms when added
  return lookupAlgorithm(alg, JWS_SYMMETRIC_ALGORITHMS, "JWS");
}
