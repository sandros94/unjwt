import type { JWSAlgorithm } from "../../types/index.ts";
import type { JWTError } from "../../../error.ts";
import { isJWSAlgorithm } from "../../../utils/algorithms.ts";
import { checkAlgSupported } from "../../_internal/algorithms.ts";

/** Reject `"none"` (RFC 7518 §3.6) and any `alg` outside `JWSAlgorithm`. */
export function assertJWSAlgSupported(alg: string): asserts alg is JWSAlgorithm {
  const error = checkJWSAlgSupported(alg);
  if (error) throw error;
}

export function checkJWSAlgSupported(alg: string): JWTError | undefined {
  return checkAlgSupported(alg, {
    supported: isJWSAlgorithm,
    code: "ERR_JWS_ALG_NOT_ALLOWED",
    label: "Algorithm",
    role: "signing algorithm",
  });
}
