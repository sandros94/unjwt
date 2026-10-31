import type { ExpiresIn } from "../../core/types/index.ts";
import type { SessionDriver } from "./driver.ts";
import { resolveExpiresAt, sanitizeSessionUpdate } from "./contract.ts";
import { assertSessionConfig, bindSession, transportToken } from "./bind.ts";
import type { SessionActions, SessionCodec, SessionCoreConfig } from "./types.ts";
import { mintSessionId, openSessionToken, sessionInstant } from "./core.ts";
import { loadSession } from "./read.ts";
import { sessionActions, sessionManager } from "./write.ts";
import type { SessionDefinition, SessionRecord } from "../types.ts";

/** Binds a config to a driver and a codec. Checks the config and resolves its keys at once. Key imports wait for the first `use()`, `issue()` or `open()`. */
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
  },
): SessionDefinition<T, MaxAge, TEvent> {
  const { driver, codec } = options;
  const name = config.name || codec.defaultName;
  assertSessionConfig(config, { name, prefix: driver.prefix, defaultCookie: codec.defaultCookie });
  const keys = codec.keys(config);
  const actions: SessionActions<TEvent, Config> = sessionActions();
  const bind = (event: TEvent) =>
    bindSession(event, { config, name, driver, codec, keys, actions });

  return {
    use: async (event) => {
      const binding = bind(event);
      await loadSession<T, MaxAge, TEvent, Config>(binding);
      return sessionManager<T, MaxAge, TEvent, Config>(binding);
    },

    token: (event) => transportToken(bind(event)),

    issue: async (data, issueOptions) => {
      await keys.assertKeys();
      const createdAt = sessionInstant({ codec, config });
      return keys.issue({
        id: mintSessionId(config),
        createdAt,
        expiresAt: resolveExpiresAt(createdAt, { maxAge: issueOptions?.maxAge ?? config.maxAge }),
        data: sanitizeSessionUpdate(data ?? {}, { prefix: driver.prefix }),
        token: undefined,
        source: "token",
        error: undefined,
      });
    },

    open: (token) => openSessionToken<T, MaxAge>(keys, { token, args: {} }),
  };
}
