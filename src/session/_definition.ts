import type { ExpiresIn } from "../core/types/index.ts";
import type { SessionDriver } from "./_driver.ts";
import type { SessionDefinition, SessionRecord } from "./types.ts";
import { resolveExpiresAt, sanitizeSessionUpdate } from "./_contract.ts";
import { bindSession, sessionToken } from "./_bind.ts";
import type { SessionActions, SessionCodec, SessionCoreConfig } from "./_types.ts";
import { mintSessionId, openSessionToken, sessionInstant } from "./_core.ts";
import { loadSession } from "./_read.ts";
import { sessionActions, sessionManager } from "./_write.ts";

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
