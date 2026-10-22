import type { ExpiresIn } from "../../../core/types/index.ts";
import {
  type JWECodecConfig,
  type JWESessionConfig,
  type JWESessionHooks,
  createJWECodec,
} from "../../../session/_codec-jwe.ts";
import type { SessionDefinition, SessionRecord, SessionState } from "../../../session/types.ts";
import { defineSession } from "../../../session/_definition.ts";
import { type SessionPlugin, type SessionPluginDefinition, sessionPlugin } from "../_plugin.ts";
import type { CookieAttributes } from "../_cookie.ts";
import type { SessionClaims, SessionManager, SessionContext } from "./types.ts";
import { PREFIX, elysiaSessionDriver } from "./_shared.ts";

export type { SessionContext };
export type { SessionDecryptOptions, SessionEncryptOptions } from "../../../session/_codec-jwe.ts";

const codec = createJWECodec({ prefix: PREFIX, defaultName: "elysia-jwe" });

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

/** Defines a JWE (encrypted) session once: `use`, `token`, `issue` and `open` serve every request, `plugin()` mounts it on an app. */
export function defineJWESession<
  T extends SessionRecord = SessionClaims,
  MaxAge extends ExpiresIn | undefined = ExpiresIn | undefined,
  K extends string = "session",
>(
  config: SessionConfigJWE<T, MaxAge> &
    (K extends "session" ? { contextKey?: K } : { contextKey: K }),
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

/**
 * Create a JWE (encrypted) session manager for the request.
 * @deprecated Use `defineJWESession(config).use(context)`.
 */
export async function createJWESession<
  T extends SessionRecord = SessionClaims,
  MaxAge extends ExpiresIn | undefined = ExpiresIn | undefined,
  TContext extends SessionContext = SessionContext,
>(
  context: TContext,
  config: SessionConfigJWE<T, MaxAge, TContext>,
): Promise<SessionManager<T, MaxAge>> {
  return define<T, MaxAge>(config).use(context);
}

/** The Elysia plugin of a JWE (encrypted) session: `defineJWESession(config).plugin()`. */
export function jweSession<
  T extends SessionRecord = SessionClaims,
  MaxAge extends ExpiresIn | undefined = ExpiresIn | undefined,
  K extends string = "session",
>(
  config: SessionConfigJWE<T, MaxAge> &
    (K extends "session" ? { contextKey?: K } : { contextKey: K }),
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
