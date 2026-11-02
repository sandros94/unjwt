import type {
  DPoPCreateOptions,
  DPoPTarget,
  DPoPVerifyOptions,
  DPoPVerifyResult,
} from "./types.ts";
import { sign, verify } from "../core/jws/index.ts";
import { JWTError } from "../error.ts";
import { JWS_ALG_CTX, checkAlgAllowed } from "../core/_internal/algorithms.ts";
import { asJWTError } from "../core/_internal/errors.ts";
import { assertCompactToken, decodeProtectedHeader } from "../core/_internal/headers.ts";
import { jwkTokey } from "../core/_crypto/_key-codec.ts";
import { thumbprint } from "../core/_crypto/_thumbprint.ts";
import { assertPlainObject, isCryptoKey } from "../utils/guards.ts";
import {
  accessTokenHash,
  assertDPoPAlgorithm,
  assertIdentifier,
  assertNumericDate,
  assertMethod,
  assertNonce,
} from "./_internal/validation.ts";
import { publicKeyForProof, projectPublicKey, resolveProofAlgorithm } from "./_internal/key.ts";
import { normalizeTargetURI } from "./_internal/uri.ts";
import {
  asProofError,
  assertExpectedNonce,
  consumeValidatedProof,
  validateProofClaims,
  validateVerifyOptions,
  type VerifyContext,
} from "./_internal/verify.ts";
import type { DPoPPayload } from "./types.ts";

export type * from "./types.ts";
export { JWTError, isJWTError, type JWTErrorCode, type KnownJWTErrorCode } from "../error.ts";

/**
 * Creates a DPoP proof (RFC 9449 §4.2) for `target`, signed with `options.keyPair`.
 * The proof has `typ: "dpop+jwt"` and the public key in its `jwk` header.
 * `htu` is `target.url` without query and fragment.
 *
 * @returns The proof as a compact JWS.
 * @throws `ERR_INVALID_OPTION` if the target, the key pair or another option is invalid.
 * @throws `ERR_DPOP_INVALID` if signing fails with an error that is not a `JWTError`.
 */
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

/**
 * Verifies a DPoP proof against `target` and `options`.
 * Returns its claims and the thumbprint of its key.
 * Validate the access token yourself. Pass `consumeProof` to reject a replayed proof.
 * A core error behind a proof failure is kept as `cause`.
 *
 * @throws `ERR_INVALID_OPTION` if the target or an option is invalid.
 * @throws `ERR_DPOP_INVALID` if the proof's structure, header, key, algorithm or signature is invalid.
 * @throws `ERR_DPOP_CLAIM_INVALID` if a claim is invalid, `iat` is outside the age window,
 * or the proof does not match the request or the access token.
 * @throws `ERR_DPOP_NONCE_INVALID` if the proof's `nonce` differs from `options.nonce`.
 * This check runs after every other proof check.
 * @throws `ERR_DPOP_REPLAY` if `consumeProof` does not return `true` or throws.
 */
export async function verifyDPoPProof(
  proof: string,
  target: DPoPTarget,
  options: DPoPVerifyOptions,
): Promise<DPoPVerifyResult> {
  let context: VerifyContext;
  try {
    context = validateVerifyOptions(target, options);
  } catch (cause) {
    throw asJWTError(cause, {
      code: "ERR_INVALID_OPTION",
      message: "DPoP verification options are invalid.",
    });
  }
  let result: DPoPVerifyResult;
  try {
    result = await authenticateProof(proof, context);
  } catch (cause) {
    throw asProofError(cause);
  }
  if (context.consumeProof) await consumeValidatedProof(result, context.consumeProof);
  return result;
}

async function authenticateProof(proof: string, context: VerifyContext): Promise<DPoPVerifyResult> {
  assertCompactToken(proof, "JWS");
  const header = decodeProtectedHeader(proof.split(".")[0], "JWS");
  assertDPoPAlgorithm(header.alg, "ERR_DPOP_INVALID");
  if (header.b64 === false) {
    throw new JWTError("DPoP JWT payloads must use base64url encoding.", "ERR_DPOP_INVALID");
  }
  const jwk = projectPublicKey(header.jwk, { algorithm: header.alg, code: "ERR_DPOP_INVALID" });
  const algError = checkAlgAllowed(header.alg, jwk, {
    ctx: JWS_ALG_CTX,
    algorithms: context.algorithms,
  });
  if (algError) throw algError;
  const key = await jwkTokey(jwk, { alg: header.alg });
  const { payload } = await verify<Record<string, unknown>>(proof, key, {
    algorithms: context.algorithms,
    typ: "dpop+jwt",
    currentDate: new Date(context.now * 1000),
    clockTolerance: context.tolerance,
  });
  validateProofClaims(payload, context);
  const keyThumbprint = await thumbprint(jwk);
  const { accessToken } = context;
  if (
    accessToken &&
    (keyThumbprint !== accessToken.thumbprint ||
      payload.ath !== (await accessTokenHash(accessToken.token)))
  ) {
    throw new JWTError(
      "DPoP access token hash or public key binding does not match.",
      "ERR_DPOP_CLAIM_INVALID",
    );
  }
  assertExpectedNonce(payload, context.nonce);
  return { payload, thumbprint: keyThumbprint };
}
