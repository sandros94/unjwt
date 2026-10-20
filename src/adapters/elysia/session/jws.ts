import type { ExpiresIn } from "../../../core/types/index.ts";
import {
  type JWSCodecConfig,
  type JWSSessionConfig,
  type JWSSessionHooks,
  createJWSCodec,
} from "../../../session/_codec-jws.ts";
export type { SessionSignOptions, SessionVerifyOptions } from "../../../session/_codec-jws.ts";
import type { SessionDefinition, SessionRecord, SessionState } from "../../../session/types.ts";
import { defineSession } from "../../../session/_definition.ts";
import { type SessionPlugin, type SessionPluginDefinition, sessionPlugin } from "../_plugin.ts";
import type { CookieAttributes } from "../_cookie.ts";
import type { SessionClaims, SessionManager, SessionContext } from "./types.ts";
import { PREFIX, elysiaSessionDriver } from "./_shared.ts";

export type { SessionContext };

const codec = createJWSCodec({ prefix: PREFIX, defaultName: "elysia-jws" });

export interface SessionJWS<
  T extends SessionRecord = SessionClaims,
  MaxAge extends ExpiresIn | undefined = ExpiresIn | undefined,
> extends SessionState<T, MaxAge> {}

export interface SessionHooksJWS<
  T extends SessionRecord = SessionClaims,
  MaxAge extends ExpiresIn | undefined = ExpiresIn | undefined,
  TContext extends SessionContext = SessionContext,
> extends JWSSessionHooks<
  SessionJWS<T, MaxAge>,
  SessionManager<T, MaxAge>,
  { context: TContext },
  SessionConfigJWS<T, MaxAge, TContext>
> {}

export interface SessionConfigJWS<
  T extends SessionRecord = SessionClaims,
  MaxAge extends ExpiresIn | undefined = ExpiresIn | undefined,
  TContext extends SessionContext = SessionContext,
> extends JWSSessionConfig<MaxAge, CookieAttributes> {
  /** Context property the session is exposed under. Default `"session"`. */
  contextKey?: string;
  hooks?: SessionHooksJWS<T, MaxAge, TContext>;
}

/** Defines a JWS (signed, not encrypted) session once: `use`, `token`, `issue` and `open` serve every request, `plugin()` mounts it on an app. */
export function defineJWSSession<
  T extends SessionRecord = SessionClaims,
  MaxAge extends ExpiresIn | undefined = ExpiresIn | undefined,
  K extends string = "session",
>(
  config: SessionConfigJWS<T, MaxAge> &
    (K extends "session" ? { contextKey?: K } : { contextKey: K }),
): SessionPluginDefinition<T, MaxAge, K> {
  const definition = define<T, MaxAge>(config);
  return {
    ...definition,
    plugin: () =>
      sessionPlugin<SessionManager<T, MaxAge>, K>({
        name: "unjwt/elysia-jws",
        sessionName: config.name || codec.defaultName,
        contextKey: config.contextKey,
        create: definition.use,
      }),
  };
}

/**
 * Create a JWS (signed, not encrypted) session manager for the request.
 * @deprecated Use `defineJWSSession(config).use(context)`.
 */
export async function createJWSSession<
  T extends SessionRecord = SessionClaims,
  MaxAge extends ExpiresIn | undefined = ExpiresIn | undefined,
  TContext extends SessionContext = SessionContext,
>(
  context: TContext,
  config: SessionConfigJWS<T, MaxAge, TContext>,
): Promise<SessionManager<T, MaxAge>> {
  return define<T, MaxAge>(config).use(context);
}

/** The Elysia plugin of a JWS (signed, not encrypted) session: `defineJWSSession(config).plugin()`. */
export function jwsSession<
  T extends SessionRecord = SessionClaims,
  MaxAge extends ExpiresIn | undefined = ExpiresIn | undefined,
  K extends string = "session",
>(
  config: SessionConfigJWS<T, MaxAge> &
    (K extends "session" ? { contextKey?: K } : { contextKey: K }),
): SessionPlugin<{ [P in K]: SessionManager<T, MaxAge> }, `require${Capitalize<K>}`> {
  return defineJWSSession<T, MaxAge, K>(config).plugin();
}

function define<T extends SessionRecord, MaxAge extends ExpiresIn | undefined>(
  config: JWSCodecConfig,
): SessionDefinition<SessionContext, T, MaxAge> {
  return defineSession<T, MaxAge, SessionContext, JWSCodecConfig>(config, {
    driver: elysiaSessionDriver,
    hookArgs: (context) => ({ context }),
    codec,
  });
}
