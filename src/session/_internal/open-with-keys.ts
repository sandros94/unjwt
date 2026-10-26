import type { AlgCheckContext } from "../../core/_internal/algorithms.ts";
import { checkAlgAllowed } from "../../core/_internal/algorithms.ts";
import { assertCandidateLimit } from "../../core/_internal/limits.ts";
import type { JWKAlgorithm } from "../../core/types/index.ts";
import { JWTError, isJWTError } from "../../error.ts";
import { quoteTokenValue } from "../../utils/_internal/text.ts";
import type { SessionPayload } from "./codec.ts";
import type { SessionOpeners } from "./key-set.ts";

/** The protected header members the candidate keys are picked by. */
export interface KeyHeader<A extends string> {
  alg?: A;
  enc?: string;
  kid?: string;
}

/**
 * Opens a token with each key that can, in order: of a rotation set, the keys of the token's `kid` when it names one, then of
 * those the keys that serve its `alg`, and under `dir` its `enc`. At most `limit` keys are tried; `spend` charges each attempt.
 * `attempt` gets a key lookup for the first key, so the family checks the token before any key is picked.
 * A lone key's failure is thrown as is, several keys' failures as `failure` with each key's error in `cause`.
 */
export async function openWithKeys<K, A extends JWKAlgorithm, H extends KeyHeader<A>>(
  openers: SessionOpeners<K, A>,
  options: {
    ctx: AlgCheckContext;
    limit: number;
    failure: { code: "ERR_JWE_DECRYPTION_FAILED" | "ERR_JWS_SIGNATURE_INVALID"; message: string };
    attempt: (key: K | ((header: H) => K)) => Promise<SessionPayload>;
    spend?: (header: H) => void;
  },
): Promise<SessionPayload> {
  const { failure, spend } = options;
  let header: H | undefined;
  let candidates: readonly K[] = [];
  const select = (protectedHeader: H): K => {
    header = protectedHeader;
    const selected = candidatesFor(protectedHeader, openers, options);
    spend?.(protectedHeader);
    candidates = selected;
    return selected[0];
  };

  const attempts: unknown[] = [];
  for (let index = 0; index === 0 || index < candidates.length; index++) {
    try {
      if (index > 0 && header) spend?.(header);
    } catch (error) {
      attempts.push(error);
      continue;
    }
    try {
      return await options.attempt(index === 0 ? select : candidates[index]);
    } catch (error) {
      const keyFailure = isJWTError(error, failure.code) || isJWTError(error, "ERR_JWK_INVALID");
      if (candidates.length === 0 || !keyFailure) throw error;
      attempts.push(error);
    }
  }
  throw attempts.length === 1 ? attempts[0] : new JWTError(failure.message, failure.code, attempts);
}

/** RFC 7515 §4.1.4, RFC 7516 §4.1.6: a rotation set narrows by `kid`. Of those keys, the ones that serve the header's `alg` and, under `dir`, its `enc`. */
function candidatesFor<K, A extends JWKAlgorithm>(
  header: KeyHeader<A>,
  openers: SessionOpeners<K, A>,
  options: { ctx: AlgCheckContext; limit: number },
): K[] {
  const { alg, enc, kid } = header;
  if (alg) {
    const refused = checkAlgAllowed(alg, undefined, {
      ctx: options.ctx,
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
      (alg !== "dir" || (enc !== undefined && entry.encryptions?.includes(enc) === true)),
  );
  if (serving.length === 0) {
    const encryption = alg === "dir" ? ` with "enc" ${quoteTokenValue(enc)}` : "";
    throw new JWTError(
      `No session key serves "alg" ${quoteTokenValue(alg)}${encryption}.`,
      "ERR_JWK_KEY_NOT_FOUND",
    );
  }
  assertCandidateLimit(serving.length, options.limit);
  return serving.map((entry) => entry.key);
}
