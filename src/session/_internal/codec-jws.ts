import { sign, verify } from "../../core/jws/index.ts";
import { isJWKSet } from "../../utils/guards.ts";
import type {
  ExpiresIn,
  JWKSet,
  JWSSignJWK,
  JWSVerifyJWK,
  JWSSignOptions,
  JWSVerifyOptions,
  JWSKeyLookup,
  JWSHeaderParameters,
} from "../../core/types/index.ts";
import type { StrictOmit } from "../../utils/types.ts";
import {
  type SessionPayload,
  createSessionCodec,
  sessionIssueOptions,
  sessionOpenOptions,
} from "./codec.ts";
import { type JWSSessionKey, getSignKey, getVerifyKey } from "./codec-jws-keys.ts";
import type { SessionCodec, SessionCoreConfig, SessionCoreHooks } from "./types.ts";
import type { SessionBaseConfig, SessionHooks } from "../types.ts";

/** JWS verify options a session accepts. The session sets `algorithms`, `typ`, `maxTokenAge`, `validateClaims` and `payload` itself. */
export type SessionVerifyOptions = StrictOmit<
  JWSVerifyOptions,
  "algorithms" | "typ" | "maxTokenAge" | "validateClaims" | "payload"
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
  /** A pinned `signOptions.alg` is the only algorithm verification accepts. `signOptions.protectedHeader.typ` defaults to `"session+jwt"` (RFC 8725 §3.11). */
  jws?: JWSSessionOptions;
}

/** JWS session hooks, with the verify key lookup. */
export interface JWSSessionHooks<
  TSession,
  TManager,
  TArgs extends Record<string, unknown>,
  TConfig,
> extends SessionHooks<TSession, TManager, TArgs, TConfig> {
  /** Returns the key or JWK Set that verifies an incoming token, picked from its protected header (by `kid`, for example). Set, it replaces `key` for verification. `open()` passes it no event. */
  onVerifyKeyLookup?: (
    args: Partial<TArgs> & { header: JWSHeaderParameters; config: TConfig },
  ) => JWKSet | JWSVerifyJWK | Promise<JWKSet | JWSVerifyJWK>;
}

export interface JWSCodecConfig extends SessionCoreConfig {
  key: JWSSessionKey;
  jws?: JWSSessionOptions;
  hooks?: SessionCoreHooks & {
    onVerifyKeyLookup?(args: {
      header: JWSHeaderParameters;
      config: unknown;
      [arg: string]: unknown;
    }): JWKSet | JWSVerifyJWK | Promise<JWKSet | JWSVerifyJWK>;
  };
}

type JWSOpenKey = JWSVerifyJWK | JWKSet | CryptoKey | JWSKeyLookup<JWKSet | JWSVerifyJWK>;

export const JWS_DEFAULT_COOKIE = {
  path: "/",
  secure: true,
  httpOnly: true,
  sameSite: "lax",
} as const;

/** Signs session claims into a compact JWS and verifies them, checking claims, `typ` and the pinned `alg`. */
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
    openKey: (config) => getVerifyKey(config.key, { pin: config.jws?.signOptions?.alg, prefix }),
    lookup: (config) => {
      const hooks = config.hooks;
      if (!hooks?.onVerifyKeyLookup) return undefined;
      return (args) => (header: JWSHeaderParameters) =>
        hooks.onVerifyKeyLookup?.({ header, ...args, config });
    },
    importable: (key) => (isJWKSet(key) ? key.keys : [key]),

    issue: (config, payload, key) =>
      // oxlint-disable-next-line typescript/no-unsafe-type-assertion -- picks the JWK overload; a key without `alg` reaches here only with `alg` pinned
      sign(payload, key as JWSSignJWK, sessionIssueOptions(config.jws?.signOptions)),

    open: async (config, token, key) => {
      const { verifyOptions, signOptions } = config.jws ?? {};
      const { payload } = await verify<SessionPayload>(token, key, {
        ...verifyOptions,
        ...sessionOpenOptions({
          maxAge: config.maxAge,
          requiredClaims: verifyOptions?.requiredClaims,
          typ: signOptions?.protectedHeader?.typ,
          alg: signOptions?.alg,
        }),
      });
      return payload;
    },
  });
}
