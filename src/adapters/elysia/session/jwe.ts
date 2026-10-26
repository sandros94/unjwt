import type { ExpiresIn } from "../../../core/types/index.ts";
import {
  type JWECodecConfig,
  type JWESessionConfig,
  type JWESessionHooks,
  createJWECodec,
} from "../../../session/_internal/codec-jwe.ts";
import type { SessionDefinition, SessionRecord, SessionState } from "../../../session/types.ts";
import { defineSession } from "../../../session/_internal/definition.ts";
import {
  type ContextKeyOption,
  type SessionPlugin,
  type SessionPluginDefinition,
  sessionPlugin,
} from "../_internal/plugin.ts";
import type { CookieAttributes } from "../_internal/cookie.ts";
import type { SessionClaims, SessionManager, SessionContext } from "./types.ts";
import { PREFIX, elysiaSessionDriver } from "../_internal/shared.ts";

export type { SessionContext };
export type {
  SessionDecryptOptions,
  SessionEncryptOptions,
} from "../../../session/_internal/codec-jwe.ts";

const codec = createJWECodec({ prefix: PREFIX, defaultName: "__Host-elysia-jwe" });

export interface SessionJWE<
  T extends SessionRecord = SessionClaims,
  MaxAge extends ExpiresIn | undefined = ExpiresIn | undefined,
> extends SessionState<T, MaxAge> {}

export interface SessionHooksJWE<
  T extends SessionRecord = SessionClaims,
  MaxAge extends ExpiresIn | undefined = ExpiresIn | undefined,
  TContext extends SessionContext = SessionContext,
> extends JWESessionHooks<
  SessionJWE<T, MaxAge>,
  SessionManager<T, MaxAge>,
  { context: TContext },
  SessionConfigJWE<T, MaxAge, TContext>
> {}

export interface SessionConfigJWE<
  T extends SessionRecord = SessionClaims,
  MaxAge extends ExpiresIn | undefined = ExpiresIn | undefined,
  TContext extends SessionContext = SessionContext,
> extends JWESessionConfig<MaxAge, CookieAttributes> {
  /** Context property the session is exposed under. Default `"session"`. */
  contextKey?: string;
  hooks?: SessionHooksJWE<T, MaxAge, TContext>;
}

/** Defines a JWE (encrypted) session once: `use`, `token`, `issue` and `open` serve every request, `plugin()` mounts it on an app. Throws at definition for a config it cannot use. */
export function defineJWESession<
  T extends SessionRecord = SessionClaims,
  MaxAge extends ExpiresIn | undefined = ExpiresIn | undefined,
  K extends string = "session",
>(
  config: SessionConfigJWE<T, MaxAge> & ContextKeyOption<K>,
): SessionPluginDefinition<T, MaxAge, K> {
  const definition = define<T, MaxAge>(config);
  return {
    ...definition,
    plugin: () =>
      sessionPlugin<SessionManager<T, MaxAge>, K>({
        name: "unjwt/elysia-jwe",
        sessionName: config.name || codec.defaultName,
        contextKey: config.contextKey,
        create: definition.use,
      }),
  };
}

/** The Elysia plugin of a JWE (encrypted) session: `defineJWESession(config).plugin()`; throws for a config it cannot use. */
export function jweSession<
  T extends SessionRecord = SessionClaims,
  MaxAge extends ExpiresIn | undefined = ExpiresIn | undefined,
  K extends string = "session",
>(
  config: SessionConfigJWE<T, MaxAge> & ContextKeyOption<K>,
): SessionPlugin<{ [P in K]: SessionManager<T, MaxAge> }, `require${Capitalize<K>}`> {
  return defineJWESession<T, MaxAge, K>(config).plugin();
}

function define<T extends SessionRecord, MaxAge extends ExpiresIn | undefined>(
  config: JWECodecConfig,
): SessionDefinition<T, MaxAge, SessionContext> {
  return defineSession<T, MaxAge, SessionContext, JWECodecConfig>(config, {
    driver: elysiaSessionDriver,
    hookArgs: (context) => ({ context }),
    codec,
  });
}
