import type { ExpiresIn } from "../core/types/index.ts";
import type { SessionDriver } from "./_driver.ts";
import { type SessionIssueOptions, resolveExpiresAt, sanitizeSessionUpdate } from "./_session.ts";
import { bindSession, sessionToken } from "./_session-bind.ts";
import {
  type SessionActions,
  type SessionCodec,
  type SessionCoreConfig,
  type OpenedSessionState,
  mintSessionId,
  openSessionToken,
  sessionInstant,
} from "./_session-core.ts";
import { loadSession } from "./_session-read.ts";
import { sessionActions, sessionManager } from "./_session-write.ts";
import type {
  SessionClaims,
  SessionData,
  SessionManager,
  SessionRecord,
} from "./_session-types.ts";

/** One session, defined once from its config and used on any request. */
export interface SessionDefinition<
  TContext,
  T extends SessionRecord = SessionClaims,
  MaxAge extends ExpiresIn | undefined = ExpiresIn | undefined,
> {
  /** Reads the request's session once and returns its manager; later calls on the same request share that state. */
  use: (context: TContext) => Promise<SessionManager<T, MaxAge>>;
  /** The token the request carries (this response's own write first), unopened. */
  token: (context: TContext) => string | undefined;
  /** Mints a token for `data` with a fresh `jti` and `iat`, and `exp` from `maxAge` (`options.maxAge` overrides it); reads and writes nothing. */
  issue: (data?: Partial<SessionData<T>>, options?: SessionIssueOptions) => Promise<string>;
  /** Opens a token into session state, checking `typ`, pinned algorithms, `jti`/`iat` and `exp` when `maxAge` is set; the key-lookup hook receives no request. */
  open: (token: string) => Promise<OpenedSessionState<T, MaxAge>>;
}

/** Binds a config to a framework driver and a codec; nothing is validated or read until a method runs. */
export function defineSession<
  T extends SessionRecord,
  MaxAge extends ExpiresIn | undefined,
  TContext,
  Config extends SessionCoreConfig,
>(
  config: Config,
  options: {
    driver: SessionDriver<TContext>;
    codec: SessionCodec<Config>;
    /** The hook argument naming the request, as the public entry names it. */
    hookArgs: (context: TContext) => Record<string, unknown>;
  },
): SessionDefinition<TContext, T, MaxAge> {
  const { driver, codec, hookArgs } = options;
  const actions: SessionActions<TContext, Config> = sessionActions();
  const bind = (context: TContext) =>
    bindSession(context, config, { driver, codec, actions, hookArgs });

  return {
    use: async (context) => {
      const binding = bind(context);
      await loadSession<T, MaxAge, TContext, Config>(binding);
      return sessionManager<T, MaxAge, TContext, Config>(binding);
    },

    token: (context) => sessionToken(bind(context)),

    issue: async (data, issueOptions) => {
      await codec.assertKeys(config);
      const issue = codec.issuer(config);
      const createdAt = sessionInstant({ codec, config });
      return issue({
        id: mintSessionId(config),
        createdAt,
        expiresAt: resolveExpiresAt(createdAt, { maxAge: issueOptions?.maxAge ?? config.maxAge }),
        data: sanitizeSessionUpdate(data ?? {}, { prefix: driver.prefix }),
        token: undefined,
      });
    },

    open: (token) => openSessionToken<T, MaxAge, Config>(codec, config, { token, args: {} }),
  };
}
