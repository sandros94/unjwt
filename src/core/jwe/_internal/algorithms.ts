import type { ContentEncryptionAlgorithm, KeyManagementAlgorithm } from "../../types/index.ts";
import { JWTError } from "../../../error.ts";
import { inferJWEAllowedAlgorithms, isKeyManagementAlgorithm } from "../../../utils/algorithms.ts";
import type { AlgCheckContext } from "../../_internal/algorithms.ts";
import { checkAlgSupported } from "../../_internal/algorithms.ts";

export const JWE_ALG_CTX: AlgCheckContext = /* @__PURE__ */ Object.freeze({
  infer: inferJWEAllowedAlgorithms,
  octRoles: true,
  errorCode: "ERR_JWE_ALG_NOT_ALLOWED",
  label: "Key management algorithm",
  op: "enc",
});

/** RFC 7518 §4.5 / §4.6: the algorithms that agree on the CEK directly. */
export const JWE_DIRECT_ALGS: ReadonlySet<string> = /* @__PURE__ */ new Set(["dir", "ECDH-ES"]);

/** Rejects `"none"` and any key management `alg` outside the implemented set. */
export function checkJWEAlgSupported(alg: string): JWTError | undefined {
  return checkAlgSupported(alg, {
    supported: isKeyManagementAlgorithm,
    code: "ERR_JWE_ALG_NOT_ALLOWED",
    label: "Key management algorithm",
    role: "key management algorithm",
  });
}

export function isJWEAlgSupported(alg: string): alg is KeyManagementAlgorithm {
  return isKeyManagementAlgorithm(alg);
}

export function assertJWEAlgSupported(alg: string): asserts alg is KeyManagementAlgorithm {
  const error = checkJWEAlgSupported(alg);
  if (error) throw error;
}

export function checkJWEEncAllowed(
  enc: ContentEncryptionAlgorithm,
  encryptionAlgorithms: readonly ContentEncryptionAlgorithm[] | undefined,
): JWTError | undefined {
  if (encryptionAlgorithms === undefined || encryptionAlgorithms.includes(enc)) return undefined;
  return new JWTError(
    `Content encryption algorithm not allowed: ${enc}`,
    "ERR_JWE_ALG_NOT_ALLOWED",
  );
}
