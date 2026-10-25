import type {
  DPoPCreateOptions,
  DPoPTarget,
  DPoPVerifyOptions,
  DPoPVerifyResult,
} from "./types.ts";
import { sign, verify } from "../core/jws.ts";
import { JWTError } from "../core/error.ts";
import { assertCompactToken, decodeProtectedHeader } from "../core/_internal.ts";
import { thumbprint } from "../core/_crypto/_thumbprint.ts";
import { assertPlainObject, isCryptoKey } from "../core/utils/guards.ts";
import {
  accessTokenHash,
  assertDPoPAlgorithm,
  assertIdentifier,
  assertNumericDate,
  assertMethod,
  assertNonce,
} from "./_validation.ts";
import { publicKeyForProof, projectPublicKey, resolveProofAlgorithm } from "./_key.ts";
import { normalizeTargetURI } from "./_uri.ts";
import { consumeValidatedProof, validateProofClaims, validateVerifyOptions } from "./_verify.ts";
import type { DPoPPayload } from "./types.ts";

export type * from "./types.ts";
export { JWTError, isJWTError, type JWTErrorCode, type KnownJWTErrorCode } from "../core/error.ts";

/** Create a proof with matching private/public signing keys and optional identifier/time overrides. */
export async function createDPoPProof(
  target: DPoPTarget,
  options: DPoPCreateOptions,
): Promise<string> {
  try {
    assertPlainObject(options, "options");
    if (typeof target !== "object" || target === null) {
      throw new JWTError("DPoP target requires method and url.", "ERR_INVALID_OPTION");
    }
    assertMethod(target.method, "ERR_INVALID_OPTION");
    const jti = options.jti === undefined ? crypto.randomUUID() : options.jti;
    const iat = options.iat === undefined ? Math.floor(Date.now() / 1000) : options.iat;
    assertIdentifier(jti, "ERR_INVALID_OPTION");
    assertNumericDate(iat, { claim: "iat", code: "ERR_INVALID_OPTION" });
    const algorithm = resolveProofAlgorithm(options.keyPair, { algorithm: options.algorithm });
    const payload: DPoPPayload = {
      jti,
      iat,
      htm: target.method,
      htu: normalizeTargetURI(target.url, { code: "ERR_INVALID_OPTION" }),
    };
    for (const claim of ["exp", "nbf"] as const) {
      const value = options[claim];
      if (value !== undefined) {
        assertNumericDate(value, { claim, code: "ERR_INVALID_OPTION" });
        payload[claim] = value;
      }
    }
    if (options.nonce !== undefined) {
      assertNonce(options.nonce, "ERR_INVALID_OPTION");
      payload.nonce = options.nonce;
    }
    if (options.accessToken !== undefined) {
      assertPlainObject(options.accessToken, "accessToken");
      payload.ath = await accessTokenHash(options.accessToken.token);
    }
    const jwk = await publicKeyForProof(options.keyPair, algorithm);
    const signingOptions = { alg: algorithm, protectedHeader: { typ: "dpop+jwt", jwk } };
    const privateKey = options.keyPair.privateKey;
    return await (isCryptoKey(privateKey)
      ? sign(payload, privateKey, signingOptions)
      : sign(payload, privateKey, signingOptions));
  } catch (cause) {
    if (cause instanceof JWTError) throw cause;
    throw new JWTError("DPoP proof creation failed.", "ERR_DPOP_INVALID", cause);
  }
}

/** Authenticate and bind a proof; replay storage and access-token validation belong to the caller. */
export async function verifyDPoPProof(
  proof: string,
  target: DPoPTarget,
  options: DPoPVerifyOptions,
): Promise<DPoPVerifyResult> {
  try {
    const context = validateVerifyOptions(target, options);
    assertCompactToken(proof, "JWS");
    const header = decodeProtectedHeader(proof.split(".")[0], "JWS");
    assertDPoPAlgorithm(header.alg, "ERR_DPOP_INVALID");
    if (header.b64 === false) {
      throw new JWTError("DPoP JWT payloads must use base64url encoding.", "ERR_DPOP_INVALID");
    }
    const jwk = projectPublicKey(header.jwk, { algorithm: header.alg, code: "ERR_DPOP_INVALID" });
    const { payload } = await verify<Record<string, unknown>>(proof, jwk, {
      algorithms: options.algorithms,
      typ: "dpop+jwt",
      currentDate: new Date(context.now * 1000),
      clockTolerance: context.tolerance,
    });
    validateProofClaims(payload, options, context);
    const keyThumbprint = await thumbprint(jwk);
    if (
      options.accessToken &&
      (keyThumbprint !== options.accessToken.thumbprint ||
        payload.ath !== (await accessTokenHash(options.accessToken.token)))
    ) {
      throw new JWTError(
        "DPoP access token hash or public key binding does not match.",
        "ERR_DPOP_CLAIM_INVALID",
      );
    }
    const result = { payload, thumbprint: keyThumbprint };
    if (options.consumeProof) await consumeValidatedProof(result, options.consumeProof);
    return result;
  } catch (cause) {
    if (cause instanceof JWTError) throw cause;
    throw new JWTError("DPoP proof verification failed.", "ERR_DPOP_INVALID", cause);
  }
}
