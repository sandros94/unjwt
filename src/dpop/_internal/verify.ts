import { JWTError } from "../../error.ts";
import { assertPlainObject } from "../../utils/guards.ts";
import {
  assertAccessToken,
  assertDPoPAlgorithm,
  assertIdentifier,
  assertNumericDate,
  assertMethod,
  assertNonce,
  isSHA256Digest,
} from "./validation.ts";
import { normalizeTargetURI } from "./uri.ts";
import type {
  DPoPAlgorithm,
  DPoPPayload,
  DPoPTarget,
  DPoPVerifyOptions,
  DPoPVerifyResult,
} from "../types.ts";

export interface VerifyContext {
  now: number;
  tolerance: number;
  maxTokenAge: number;
  method: string;
  uri: string;
  algorithms: DPoPAlgorithm[];
  nonce: string | undefined;
  accessToken: { token: string; thumbprint: string } | undefined;
  consumeProof: DPoPVerifyOptions["consumeProof"];
}

export function validateVerifyOptions(
  target: DPoPTarget,
  options: DPoPVerifyOptions,
): VerifyContext {
  assertPlainObject(options, "options");
  if (typeof target !== "object" || target === null) {
    throw new JWTError("DPoP target requires method and url.", "ERR_INVALID_OPTION");
  }
  const { method, url } = target;
  assertMethod(method, "ERR_INVALID_OPTION");
  const uri = normalizeTargetURI(url, { code: "ERR_INVALID_OPTION" });
  const {
    algorithms: allowed,
    maxTokenAge,
    clockTolerance,
    currentDate,
    nonce,
    accessToken,
    consumeProof,
  } = options;
  const algorithms: DPoPAlgorithm[] = [];
  for (const algorithm of Array.isArray(allowed) ? allowed : []) {
    assertDPoPAlgorithm(algorithm, "ERR_INVALID_OPTION");
    algorithms.push(algorithm);
  }
  if (algorithms.length === 0) {
    throw new JWTError(
      "DPoP algorithms must be a non-empty asymmetric algorithm allowlist.",
      "ERR_INVALID_OPTION",
    );
  }
  const tolerance = clockTolerance === undefined ? 0 : clockTolerance;
  if (
    typeof tolerance !== "number" ||
    !Number.isFinite(tolerance) ||
    tolerance < 0 ||
    typeof maxTokenAge !== "number" ||
    !Number.isFinite(maxTokenAge) ||
    maxTokenAge <= 0
  ) {
    throw new JWTError(
      "DPoP maxTokenAge must be positive finite seconds and clockTolerance non-negative finite seconds.",
      "ERR_INVALID_OPTION",
    );
  }
  const date = currentDate === undefined ? new Date() : currentDate;
  const time = date instanceof Date ? date.getTime() : Number.NaN;
  if (!Number.isFinite(time)) {
    throw new JWTError("DPoP currentDate must be a valid Date.", "ERR_INVALID_OPTION");
  }
  if (nonce !== undefined) assertNonce(nonce, "ERR_INVALID_OPTION");
  let binding: VerifyContext["accessToken"];
  if (accessToken !== undefined) {
    assertPlainObject(accessToken, "accessToken");
    const { token, thumbprint } = accessToken;
    assertAccessToken(token);
    if (!isSHA256Digest(thumbprint)) {
      throw new JWTError(
        "DPoP accessToken.thumbprint must be a SHA-256 JWK thumbprint.",
        "ERR_INVALID_OPTION",
      );
    }
    binding = { token, thumbprint };
  }
  if (consumeProof !== undefined && typeof consumeProof !== "function") {
    throw new JWTError("DPoP consumeProof must be a function.", "ERR_INVALID_OPTION");
  }
  return {
    now: time / 1000,
    tolerance,
    maxTokenAge,
    method,
    uri,
    algorithms,
    nonce,
    accessToken: binding,
    consumeProof,
  };
}

export function validateProofClaims(
  payload: Record<string, unknown>,
  context: VerifyContext,
): asserts payload is DPoPPayload {
  const code = "ERR_DPOP_CLAIM_INVALID";
  assertIdentifier(payload.jti, code);
  assertNumericDate(payload.iat, { claim: "iat", code });
  assertMethod(payload.htm, code);
  if (payload.htm !== context.method || normalizeTargetURI(payload.htu, { code }) !== context.uri) {
    throw new JWTError("DPoP proof does not match the request method and URI.", code);
  }
  if (payload.nonce !== undefined) assertNonce(payload.nonce, code);
  if (payload.ath !== undefined && !isSHA256Digest(payload.ath)) {
    throw new JWTError("DPoP ath must be a base64url SHA-256 access token hash.", code);
  }
  if (
    payload.iat > context.now + context.tolerance ||
    payload.iat < context.now - context.maxTokenAge - context.tolerance
  ) {
    throw new JWTError("DPoP iat is outside the accepted proof age window.", code);
  }
}

export function assertExpectedNonce(payload: DPoPPayload, expected: string | undefined): void {
  if (expected !== undefined && payload.nonce !== expected) {
    throw new JWTError(
      "DPoP nonce is missing or does not match the expected nonce.",
      "ERR_DPOP_NONCE_INVALID",
    );
  }
}

export async function consumeValidatedProof(
  result: DPoPVerifyResult,
  consumeProof: NonNullable<DPoPVerifyOptions["consumeProof"]>,
): Promise<void> {
  let accepted: unknown;
  try {
    accepted = await consumeProof({
      payload: structuredClone(result.payload),
      thumbprint: result.thumbprint,
    });
  } catch (cause) {
    throw new JWTError("DPoP replay consumption failed.", "ERR_DPOP_REPLAY", cause);
  }
  if (accepted !== true) {
    throw new JWTError("DPoP proof was rejected by replay consumption.", "ERR_DPOP_REPLAY");
  }
}

export function asProofError(error: unknown): JWTError {
  if (!(error instanceof JWTError)) {
    return new JWTError("DPoP proof verification failed.", "ERR_DPOP_INVALID", error);
  }
  if (error.code.startsWith("ERR_DPOP_")) return error;
  const code = error.code.startsWith("ERR_JWT_") ? "ERR_DPOP_CLAIM_INVALID" : "ERR_DPOP_INVALID";
  return new JWTError(error.message, code, error);
}
