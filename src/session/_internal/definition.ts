import type { ExpiresIn } from "../../core/types/index.ts";
import type { SessionDriver } from "./driver.ts";
import { resolveExpiresAt, sanitizeSessionUpdate } from "./contract.ts";
import { assertSessionConfig, bindSession, sessionToken } from "./bind.ts";
import type { SessionActions, SessionCodec, SessionCoreConfig } from "./types.ts";
import { mintSessionId, openSessionToken, sessionInstant } from "./core.ts";
import { loadSession } from "./read.ts";
import { sessionActions, sessionManager } from "./write.ts";
import type { SessionDefinition, SessionRecord } from "../types.ts";

/** Binds a config to a framework driver and a codec, checking the config and resolving its keys up front; key imports and requests wait for a method to run. */
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
  const name = config.name || codec.defaultName;
  assertSessionConfig(config, { name, prefix: driver.prefix, defaultCookie: codec.defaultCookie });
  const keys = codec.keys(config);
  const actions: SessionActions<TEvent, Config> = sessionActions();
  const bind = (event: TEvent) =>
    bindSession(event, { config, name, driver, codec, keys, actions, hookArgs });

  return {
    use: async (event) => {
      const binding = bind(event);
      await loadSession<T, MaxAge, TEvent, Config>(binding);
      return sessionManager<T, MaxAge, TEvent, Config>(binding);
    },

    token: (event) => sessionToken(bind(event)),

    issue: async (data, issueOptions) => {
      await keys.assertKeys();
      const createdAt = sessionInstant({ codec, config });
      return keys.issue({
        id: mintSessionId(config),
        createdAt,
        expiresAt: resolveExpiresAt(createdAt, { maxAge: issueOptions?.maxAge ?? config.maxAge }),
        data: sanitizeSessionUpdate(data ?? {}, { prefix: driver.prefix }),
        token: undefined,
      });
    },

    open: (token) => openSessionToken<T, MaxAge>(keys, { token, args: {} }),
  };
}
