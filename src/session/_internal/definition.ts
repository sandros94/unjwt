import type { ExpiresIn } from "../../core/types/index.ts";
import type { SessionDriver } from "./driver.ts";
import { resolveExpiresAt, sanitizeSessionUpdate } from "./contract.ts";
import { bindSession, sessionToken } from "./bind.ts";
import type { SessionActions, SessionCodec, SessionCoreConfig } from "./types.ts";
import { mintSessionId, openSessionToken, sessionInstant } from "./core.ts";
import { loadSession } from "./read.ts";
import { sessionActions, sessionManager } from "./write.ts";
import type { SessionDefinition, SessionRecord } from "../types.ts";

/** Binds a config to a framework driver and a codec; nothing is validated or read until a method runs. */
export function defineSession<
  T extends SessionRecord,
  MaxAge extends ExpiresIn | undefined,
  TEvent,
  Config extends SessionCoreConfig,
>(
  config: Config,
  options: {
    driver: SessionDriver<TEvent>;
    codec: SessionCodec<Config>;
    /** The hook argument naming the request, as the public entry names it. */
    hookArgs: (event: TEvent) => Record<string, unknown>;
  },
): SessionDefinition<T, MaxAge, TEvent> {
  const { driver, codec, hookArgs } = options;
  const actions: SessionActions<TEvent, Config> = sessionActions();
  const bind = (event: TEvent) => bindSession(event, config, { driver, codec, actions, hookArgs });

  return {
    use: async (event) => {
      const binding = bind(event);
      await loadSession<T, MaxAge, TEvent, Config>(binding);
      return sessionManager<T, MaxAge, TEvent, Config>(binding);
    },

    token: (event) => sessionToken(bind(event)),

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
