import { JWTError } from "../core/error.ts";
import { assertPlainObject } from "../core/utils/guards.ts";
import {
  assertAccessToken,
  assertDPoPAlgorithm,
  assertIdentifier,
  assertNumericDate,
  assertMethod,
  assertNonce,
  isSHA256Digest,
} from "./_validation.ts";
import { normalizeTargetURI } from "./_uri.ts";
import type { DPoPPayload, DPoPTarget, DPoPVerifyOptions, DPoPVerifyResult } from "./types.ts";

export function validateVerifyOptions(
  target: DPoPTarget,
  options: DPoPVerifyOptions,
): {
  now: number;
  tolerance: number;
  method: string;
  uri: string;
} {
  assertPlainObject(options, "options");
  if (typeof target !== "object" || target === null) {
    throw new JWTError("DPoP target requires method and url.", "ERR_INVALID_OPTION");
  }
  assertMethod(target.method, "ERR_INVALID_OPTION");
  const uri = normalizeTargetURI(target.url, { code: "ERR_INVALID_OPTION" });
  if (!Array.isArray(options.algorithms) || options.algorithms.length === 0) {
    throw new JWTError(
      "DPoP algorithms must be a non-empty asymmetric algorithm allowlist.",
      "ERR_INVALID_OPTION",
    );
  }
  for (const algorithm of options.algorithms) assertDPoPAlgorithm(algorithm, "ERR_INVALID_OPTION");
  const tolerance = options.clockTolerance === undefined ? 0 : options.clockTolerance;
  if (
    typeof tolerance !== "number" ||
    !Number.isFinite(tolerance) ||
    tolerance < 0 ||
    typeof options.maxTokenAge !== "number" ||
    !Number.isFinite(options.maxTokenAge) ||
    options.maxTokenAge <= 0
  ) {
    throw new JWTError(
      "DPoP maxTokenAge must be positive finite seconds and clockTolerance non-negative finite seconds.",
      "ERR_INVALID_OPTION",
    );
  }
  const date = options.currentDate === undefined ? new Date() : options.currentDate;
  if (!(date instanceof Date) || !Number.isFinite(date.getTime())) {
    throw new JWTError("DPoP currentDate must be a valid Date.", "ERR_INVALID_OPTION");
  }
  if (options.nonce !== undefined) assertNonce(options.nonce, "ERR_INVALID_OPTION");
  if (options.accessToken !== undefined) {
    assertPlainObject(options.accessToken, "accessToken");
    assertAccessToken(options.accessToken.token);
    if (!isSHA256Digest(options.accessToken.thumbprint)) {
      throw new JWTError(
        "DPoP accessToken.thumbprint must be a SHA-256 JWK thumbprint.",
        "ERR_INVALID_OPTION",
      );
    }
  }
  if (options.consumeProof !== undefined && typeof options.consumeProof !== "function") {
    throw new JWTError("DPoP consumeProof must be a function.", "ERR_INVALID_OPTION");
  }
  return { now: date.getTime() / 1000, tolerance, method: target.method, uri };
}

export function validateProofClaims(
  payload: Record<string, unknown>,
  options: DPoPVerifyOptions,
  context: { now: number; tolerance: number; method: string; uri: string },
): asserts payload is DPoPPayload {
  const code = "ERR_DPOP_CLAIM_INVALID";
  assertIdentifier(payload.jti, code);
  assertNumericDate(payload.iat, { claim: "iat", code });
  assertMethod(payload.htm, code);
  if (payload.htm !== context.method || normalizeTargetURI(payload.htu, { code }) !== context.uri) {
    throw new JWTError("DPoP proof does not match the request method and URI.", code);
  }
  if (payload.nonce !== undefined) assertNonce(payload.nonce, code);
  if (options.nonce !== undefined && payload.nonce !== options.nonce) {
    throw new JWTError("DPoP nonce does not match the expected nonce.", code);
  }
  if (payload.ath !== undefined && !isSHA256Digest(payload.ath)) {
    throw new JWTError("DPoP ath must be a base64url SHA-256 access token hash.", code);
  }
  if (
    payload.iat > context.now + context.tolerance ||
    payload.iat < context.now - options.maxTokenAge - context.tolerance
  ) {
    throw new JWTError("DPoP iat is outside the accepted proof age window.", code);
  }
}

export async function consumeValidatedProof(
  result: DPoPVerifyResult,
  consumeProof: NonNullable<DPoPVerifyOptions["consumeProof"]>,
): Promise<void> {
  let accepted: unknown;
  try {
    accepted = await consumeProof(result);
  } catch (cause) {
    throw new JWTError("DPoP replay consumption failed.", "ERR_DPOP_REPLAY", cause);
  }
  if (accepted !== true) {
    throw new JWTError("DPoP proof was rejected by replay consumption.", "ERR_DPOP_REPLAY");
  }
}
