import { decrypt } from "../../core/jwe/index.ts";
import { JWE_ALG_CTX } from "../../core/jwe/_internal/algorithms.ts";
import { createPBES2Budget } from "../../core/jwe/_internal/keys.ts";
import { checkAlgAllowed } from "../../core/_internal/algorithms.ts";
import { assertCandidateLimit, resolveLimit } from "../../core/_internal/limits.ts";
import type {
  JWEDecryptOptions,
  JWEHeaderParameters,
  KeyManagementAlgorithm,
} from "../../core/types/index.ts";
import { JWTError, isJWTError } from "../../error.ts";
import { quoteTokenValue } from "../../utils/_internal/text.ts";
import type { SessionPayload } from "./codec.ts";
import type { JWESessionEntry, JWESessionSecret } from "./codec-jwe-keys.ts";

/** The configured keys that open tokens: in order, `current` first, with the algorithms they serve together. */
export interface JWESessionOpeners {
  entries: readonly JWESessionEntry[];
  rotation: boolean;
  algorithms: KeyManagementAlgorithm[];
}

/**
 * Decrypts with each key that can open the token, in order: of a rotation set, the keys of the token's `kid` when it names one,
 * then of those the keys that serve its `alg`, and under `dir` its `enc`. At most `limits.keyCandidates` keys are tried, and
 * every PBES2 attempt draws on one `limits.pbes2Iterations` budget. A lone key's failure is thrown as is, several keys' failures
 * as `ERR_JWE_DECRYPTION_FAILED` with each key's error in `cause`.
 */
export async function decryptWithKeys(
  token: string,
  openers: JWESessionOpeners,
  options: JWEDecryptOptions<"json">,
): Promise<SessionPayload> {
  const limit = resolveLimit(options.limits, "keyCandidates");
  const budget = createPBES2Budget(resolveLimit(options.limits, "pbes2Iterations"));
  let header: JWEHeaderParameters = {};
  let candidates: readonly JWESessionSecret[] = [];
  const spend = () => {
    if (!header.alg) return;
    const { minIterations, maxIterations } = options;
    budget.spend({ alg: header.alg, p2c: header.p2c, minIterations, maxIterations });
  };
  const select = (protectedHeader: JWEHeaderParameters): JWESessionSecret => {
    header = protectedHeader;
    const selected = candidatesFor(protectedHeader, openers, limit);
    spend();
    candidates = selected;
    return selected[0];
  };

  const attempts: unknown[] = [];
  for (let index = 0; index === 0 || index < candidates.length; index++) {
    try {
      if (index > 0) spend();
    } catch (error) {
      attempts.push(error);
      continue;
    }
    try {
      const key = index === 0 ? select : candidates[index];
      return (await decrypt<SessionPayload>(token, key, options)).payload;
    } catch (error) {
      if (candidates.length === 0 || !isKeyFailure(error)) throw error;
      attempts.push(error);
    }
  }
  throw attempts.length === 1
    ? attempts[0]
    : new JWTError("JWE decryption failed.", "ERR_JWE_DECRYPTION_FAILED", attempts);
}

/** RFC 7516 §4.1.6: a rotation set narrows by `kid`. Of those keys, the ones that serve the header's `alg` and, under `dir`, its `enc`. */
function candidatesFor(
  header: JWEHeaderParameters,
  openers: JWESessionOpeners,
  limit: number,
): JWESessionSecret[] {
  const { alg, enc, kid } = header;
  if (alg) {
    const refused = checkAlgAllowed(alg, undefined, {
      ctx: JWE_ALG_CTX,
      algorithms: openers.algorithms,
    });
    if (refused) throw refused;
  }
  const named =
    openers.rotation && kid !== undefined
      ? openers.entries.filter((entry) => entry.kid === kid)
      : openers.entries;
  if (named.length === 0) {
    throw new JWTError(`No session key with kid ${quoteTokenValue(kid)}.`, "ERR_JWK_KEY_NOT_FOUND");
  }
  const serving = named.filter(
    (entry) =>
      alg !== undefined &&
      entry.algorithms.includes(alg) &&
      (alg !== "dir" || (enc !== undefined && entry.encryptions.includes(enc))),
  );
  if (serving.length === 0) {
    const encryption = alg === "dir" ? ` with "enc" ${quoteTokenValue(enc)}` : "";
    throw new JWTError(
      `No session key serves "alg" ${quoteTokenValue(alg)}${encryption}.`,
      "ERR_JWK_KEY_NOT_FOUND",
    );
  }
  assertCandidateLimit(serving.length, limit);
  return serving.map((entry) => entry.key);
}

/** A failure of the key tried, not of the token: the next key may still open it. */
function isKeyFailure(error: unknown): boolean {
  return isJWTError(error, "ERR_JWE_DECRYPTION_FAILED") || isJWTError(error, "ERR_JWK_INVALID");
}
