import { JWTError } from "../core/error.ts";
import { isJWSAlgorithm } from "../core/utils/algorithms.ts";
import { digestUrl } from "../core/utils/digest.ts";
import type { DPoPAlgorithm } from "./types.ts";

export type DPoPValidationCode =
  | "ERR_INVALID_OPTION"
  | "ERR_DPOP_INVALID"
  | "ERR_DPOP_CLAIM_INVALID";

export function assertDPoPAlgorithm(
  value: unknown,
  code: DPoPValidationCode,
): asserts value is DPoPAlgorithm {
  if (typeof value !== "string" || !isJWSAlgorithm(value) || value.startsWith("HS")) {
    throw new JWTError("DPoP requires a supported asymmetric signing algorithm.", code);
  }
}

export function assertNonce(value: unknown, code: DPoPValidationCode): asserts value is string {
  if (typeof value !== "string" || !/^[\x21\x23-\x5B\x5D-\x7E]+$/.test(value)) {
    throw new JWTError(
      "DPoP nonce must contain printable ASCII excluding space, quotes and backslash.",
      code,
    );
  }
}

export function assertMethod(value: unknown, code: DPoPValidationCode): asserts value is string {
  if (typeof value !== "string" || !/^[!#$%&'*+.^_`|~\da-z-]+$/i.test(value)) {
    throw new JWTError("DPoP method must be a non-empty HTTP method token.", code);
  }
}

export function assertIdentifier(
  value: unknown,
  code: DPoPValidationCode,
): asserts value is string {
  if (typeof value !== "string" || value.length === 0) {
    throw new JWTError("DPoP jti must be a non-empty string unique to this proof.", code);
  }
}

export function assertNumericDate(
  value: unknown,
  options: { claim: "iat" | "exp" | "nbf"; code: DPoPValidationCode },
): asserts value is number {
  if (typeof value !== "number" || !Number.isFinite(value) || value < 0) {
    throw new JWTError(
      `DPoP ${options.claim} must be a finite, non-negative NumericDate.`,
      options.code,
    );
  }
}

export function assertAccessToken(value: unknown): asserts value is string {
  // oxlint-disable-next-line no-control-regex -- RFC 9449 hashes the token's ASCII bytes
  if (typeof value !== "string" || !/^[\x00-\x7F]+$/.test(value)) {
    throw new JWTError(
      "DPoP accessToken.token must be a non-empty ASCII string.",
      "ERR_INVALID_OPTION",
    );
  }
}

export function isSHA256Digest(value: unknown): value is string {
  return typeof value === "string" && /^[\w-]{42}[AEIMQUYcgkosw048]$/.test(value);
}

export async function accessTokenHash(token: string): Promise<string> {
  assertAccessToken(token);
  try {
    return await digestUrl(token);
  } catch (cause) {
    throw new JWTError("DPoP access token hashing failed.", "ERR_DPOP_INVALID", cause);
  }
}
