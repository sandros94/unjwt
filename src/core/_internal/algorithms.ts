import type { JWK, ContentEncryptionAlgorithm, JWKAlgorithm } from "../types/index.ts";
import { JWTError } from "../../error.ts";
import { cryptoKeyCurve } from "../_crypto/_key-algorithm.ts";
import {
  inferJWSAllowedAlgorithms,
  isContentEncryptionAlgorithm,
  isECDHESAlgorithm,
  isSameAlgorithm,
} from "../../utils/algorithms.ts";
import { quoteTokenValue } from "../../utils/_internal/text.ts";
import { isCryptoKey, isJWK, isJWKSet } from "../../utils/guards.ts";
import type { JWKSetOperation } from "./keys.ts";
import { buildJWKSetFilter } from "./keys.ts";

export interface AlgCheckContext {
  infer: (key: unknown) => readonly JWKAlgorithm[] | undefined;
  /** An `oct` JWK's `alg` names a role, not the header `alg` (JWE). */
  octRoles: boolean;
  errorCode: "ERR_JWS_ALG_NOT_ALLOWED" | "ERR_JWE_ALG_NOT_ALLOWED";
  label: string;
  op: JWKSetOperation;
}

export const JWS_ALG_CTX: AlgCheckContext = /* @__PURE__ */ Object.freeze({
  infer: inferJWSAllowedAlgorithms,
  octRoles: false,
  errorCode: "ERR_JWS_ALG_NOT_ALLOWED",
  label: "Algorithm",
  op: "sig",
});

/**
 * Returns an error when the header `alg` is not allowed. The policy is `algorithms` when set,
 * else the JWK's own `alg`, else the algorithms inferred from the key shape.
 * Without `algorithms` or a JWK `alg`, a missing key is `ERR_JWK_INVALID`.
 */
export function checkAlgAllowed<A extends JWKAlgorithm>(
  alg: A,
  key: unknown,
  options: {
    ctx: AlgCheckContext;
    algorithms?: readonly A[];
  },
): JWTError | undefined {
  const { ctx, algorithms } = options;
  if (algorithms !== undefined) {
    return algorithms.includes(alg) ? undefined : notAllowed(alg, ctx);
  }
  if (isJWK(key) && typeof key.alg === "string" && (!ctx.octRoles || key.kty !== "oct")) {
    return isSameAlgorithm(key.alg, alg) ? undefined : notAllowed(alg, ctx);
  }
  if (key === undefined || key === null) {
    return new JWTError("A key is required.", "ERR_JWK_INVALID");
  }
  const inferred = ctx.infer(key);
  if (!inferred) {
    return new JWTError(
      'Cannot infer allowed algorithms from this key, pass "algorithms".',
      ctx.errorCode,
    );
  }
  return inferred.includes(alg) ? undefined : notAllowed(alg, ctx);
}

function notAllowed(alg: JWKAlgorithm, ctx: AlgCheckContext): JWTError {
  return new JWTError(`${ctx.label} not allowed: ${alg}`, ctx.errorCode);
}

/** Whether key material can serve the header's `alg` (RFC 7515 §4.1.4, RFC 7516 §4.1.6 `kid` hint). A JWK Set with no candidate matches. */
export function keyMatchesHeader(
  header: { alg?: JWKAlgorithm; kid?: string; epk?: { crv?: string } },
  keyMaterial: unknown,
  options: { ctx: AlgCheckContext },
): boolean {
  const { ctx } = options;
  if (isJWKSet(keyMaterial)) {
    const candidates = keyMaterial.keys.filter(buildJWKSetFilter(header, { op: ctx.op }));
    return candidates.length === 0 || candidates.some((k) => keyServesHeaderAlg(header, k, ctx));
  }
  if (isJWK(keyMaterial)) return keyServesHeaderAlg(header, keyMaterial, ctx);
  if (isCryptoKey(keyMaterial)) return keyServesHeaderAlg(header, keyMaterial, ctx);
  return true;
}

export function checkJWEEncSupported(enc: unknown): JWTError | undefined {
  if (typeof enc === "string" && isContentEncryptionAlgorithm(enc)) return undefined;
  return new JWTError(`Invalid JWE: unsupported "enc" ${quoteTokenValue(enc)}`, "ERR_JWE_INVALID");
}

export function assertJWEEncSupported(enc: unknown): asserts enc is ContentEncryptionAlgorithm {
  const error = checkJWEEncSupported(enc);
  if (error) throw error;
}

export function checkAlgSupported(
  alg: string,
  options: {
    supported: (alg: string) => boolean;
    code: "ERR_JWS_ALG_NOT_ALLOWED" | "ERR_JWE_ALG_NOT_ALLOWED";
    label: string;
    role: string;
  },
): JWTError | undefined {
  const { supported, code, label, role } = options;
  if (alg === "none") return new JWTError(`"none" is not a valid ${role}`, code);
  if (!supported(alg)) {
    return new JWTError(`${label} not supported: ${quoteTokenValue(alg)}`, code);
  }
  return undefined;
}

function keyServesHeaderAlg(
  header: { alg?: JWKAlgorithm; epk?: { crv?: string } },
  key: JWK | CryptoKey,
  ctx: AlgCheckContext,
): boolean {
  const { alg } = header;
  if (!alg) return false;
  const inferred = ctx.infer(key);
  if (inferred && !inferred.includes(alg)) return false;
  if (!isECDHESAlgorithm(alg)) return true;
  const epkCurve = header.epk?.crv;
  const keyCurve = isCryptoKey(key) ? cryptoKeyCurve(key) : "crv" in key ? key.crv : undefined;
  return !epkCurve || !keyCurve || epkCurve === keyCurve;
}
