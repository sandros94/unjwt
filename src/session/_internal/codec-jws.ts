import { sign, verify } from "../../core/jws/index.ts";
import type {
  ExpiresIn,
  JWKSet,
  JWSSignJWK,
  JWSVerifyJWK,
  JWSSignOptions,
  JWSVerifyOptions,
  JWSKeyLookup,
  JWSHeaderParameters,
  JWSAlgorithm,
} from "../../core/types/index.ts";
import type { StrictOmit } from "../../utils/types.ts";
import {
  type SessionPayload,
  createSessionCodec,
  sessionIssueOptions,
  sessionOpenOptions,
} from "./codec.ts";
import { type JWSSessionKey, getSignKey, resolveVerifyKeys } from "./codec-jws-keys.ts";
import { JWS_ALG_CTX } from "../../core/_internal/algorithms.ts";
import { resolveLimit } from "../../core/_internal/limits.ts";
import { openWithKeys } from "./open-with-keys.ts";
import type { SessionCodec, SessionCoreConfig, SessionCoreHooks } from "./types.ts";
import type { SessionBaseConfig, SessionHooks } from "../types.ts";

/**
 * JWS verify options a session accepts. `algorithms` names the `alg` values a key without its own `alg` (a `CryptoKey`, an `oct` or RSA JWK
 * without `alg`) verifies. The session sets `typ`, `maxTokenAge`, `validateClaims` and `payload` itself.
 */
export type SessionVerifyOptions = StrictOmit<
  JWSVerifyOptions,
  "typ" | "maxTokenAge" | "validateClaims" | "payload"
>;

/** JWS sign options a session accepts. The session sets `exp` from `maxAge` and never sets `nbf`. */
export type SessionSignOptions = StrictOmit<
  JWSSignOptions,
  "expiresIn" | "expiresAt" | "notBeforeIn" | "notBeforeAt"
>;

/** The JWS options of a session: `signOptions` for each issued token, `verifyOptions` for each incoming one. */
export interface JWSSessionOptions {
  signOptions?: SessionSignOptions;
  verifyOptions?: SessionVerifyOptions;
}

/** The config of a JWS session, without its hooks. */
export interface JWSSessionConfig<
  MaxAge extends ExpiresIn | undefined = ExpiresIn | undefined,
  TCookie extends object = object,
> extends SessionBaseConfig<MaxAge> {
  /** The key that signs and verifies the token. See {@link JWSSessionKey}. */
  key: JWSSessionKey;
  /** Cookie attributes, or `false` for no cookie. `chunkMaxLength` is the size the token is split at (`4000` when unset). `httpOnly: false` lets page scripts read the signed payload. @default { path: "/", secure: true, httpOnly: true, sameSite: "lax" } */
  cookie?: false | (TCookie & { chunkMaxLength?: number });
  /**
   * `signOptions.alg` is what each token is signed with, and names the algorithm of the keys without their own `alg`: both halves of a pair,
   * a rotation set's `current` alone. Verification accepts every `alg` the keys serve: a JWK's own `alg` (or an EC or OKP JWK's curve),
   * and for a key without one, the algorithms the pin or `verifyOptions.algorithms` names that its material carries.
   * `signOptions.protectedHeader.typ` defaults to `"session+jwt"` (RFC 8725 §3.11).
   */
  jws?: JWSSessionOptions;
}

/** JWS session hooks, with the verify key lookup. */
export interface JWSSessionHooks<
  TSession,
  TManager,
  TArgs extends Record<string, unknown>,
  TConfig,
> extends SessionHooks<TSession, TManager, TArgs, TConfig> {
  /** Returns the key or JWK Set that verifies an incoming token, picked from its protected header (by `kid`, for example). Set, it replaces `key` for verification: the token's `alg` is still one `key` serves or `verifyOptions.algorithms` lists. `open()` passes it no event. */
  onKeyLookup?: (
    args: Partial<TArgs> & { header: JWSHeaderParameters; config: TConfig },
  ) => JWKSet | JWSVerifyJWK | Promise<JWKSet | JWSVerifyJWK>;
}

export interface JWSCodecConfig extends SessionCoreConfig {
  key: JWSSessionKey;
  jws?: JWSSessionOptions;
  hooks?: SessionCoreHooks & {
    onKeyLookup?(args: {
      header: JWSHeaderParameters;
      config: unknown;
      [arg: string]: unknown;
    }): JWKSet | JWSVerifyJWK | Promise<JWKSet | JWSVerifyJWK>;
  };
}

/** The configured keys, or with a key lookup hook the lookup of one request. */
type JWSOpenKey =
  | ReturnType<typeof resolveVerifyKeys>
  | { lookup: JWSKeyLookup<JWKSet | JWSVerifyJWK>; algorithms: JWSAlgorithm[] };

export const JWS_DEFAULT_COOKIE = {
  path: "/",
  secure: true,
  httpOnly: true,
  sameSite: "lax",
} as const;

/** Signs session claims into a compact JWS and verifies them, checking claims, `typ` and the algorithms the keys serve. */
export function createJWSCodec(options: {
  prefix: string;
  defaultName: string;
}): SessionCodec<JWSCodecConfig> {
  const { prefix, defaultName } = options;

  return createSessionCodec<JWSCodecConfig, JWSSignJWK | CryptoKey, JWSOpenKey>({
    family: "jws",
    prefix,
    defaultName,
    defaultCookie: JWS_DEFAULT_COOKIE,

    issueOptions: (config) => config.jws?.signOptions,
    openOptions: (config) => config.jws?.verifyOptions,
    issueKey: (config) => getSignKey(config.key, { pin: config.jws?.signOptions?.alg, prefix }),
    openKey: (config) => resolveKeys(config, prefix),
    lookup: (config) => {
      const hooks = config.hooks;
      if (!hooks?.onKeyLookup) return undefined;
      const { algorithms } = resolveKeys(config, prefix);
      return (args) => ({
        lookup: (header: JWSHeaderParameters) => hooks.onKeyLookup?.({ header, ...args, config }),
        algorithms,
      });
    },
    importable: (config) => {
      const pin = config.jws?.signOptions?.alg;
      return resolveKeys(config, prefix).entries.map(({ key, algorithms }) => ({
        key,
        alg: pin !== undefined && algorithms.includes(pin) ? pin : algorithms[0],
      }));
    },

    issue: (config, payload, key) =>
      // oxlint-disable-next-line typescript/no-unsafe-type-assertion -- picks the JWK overload; a key without `alg` reaches here only with `alg` pinned
      sign(payload, key as JWSSignJWK, sessionIssueOptions(config.jws?.signOptions)),

    open: async (config, token, key) => {
      const { verifyOptions, signOptions } = config.jws ?? {};
      const opening = {
        ...verifyOptions,
        ...sessionOpenOptions({
          maxAge: config.maxAge,
          requiredClaims: verifyOptions?.requiredClaims,
          typ: signOptions?.protectedHeader?.typ,
          algorithms: key.algorithms,
        }),
      };
      const attempt = async (candidate: Parameters<typeof verify>[1]) =>
        (await verify<SessionPayload>(token, candidate, opening)).payload;
      if ("lookup" in key) return attempt(key.lookup);
      if ("key" in key) return attempt(key.key);
      return openWithKeys(key, {
        ctx: JWS_ALG_CTX,
        limit: resolveLimit(opening.limits, "keyCandidates"),
        failure: {
          code: "ERR_JWS_SIGNATURE_INVALID",
          message: "JWS signature verification failed.",
        },
        attempt,
      });
    },
  });
}

function resolveKeys(config: JWSCodecConfig, prefix: string): ReturnType<typeof resolveVerifyKeys> {
  return resolveVerifyKeys(config.key, {
    pin: config.jws?.signOptions?.alg,
    listed: config.jws?.verifyOptions?.algorithms,
    keyCandidates: resolveLimit(config.jws?.verifyOptions?.limits, "keyCandidates"),
    lookup: typeof config.hooks?.onKeyLookup === "function",
    prefix,
  });
}
