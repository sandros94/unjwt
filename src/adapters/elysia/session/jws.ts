import { Elysia } from "elysia";

import type { ExpiresIn, JWKSet, JWSVerifyJWK, JWKLookupFunctionHeader } from "../../../core/types";
import { type JWSCodecConfig, type JWSSessionConfig, createJWSCodec } from "../../_codec-jws";
export type { SessionVerifyOptions } from "../../_codec-jws";
import { type SessionBinding, type SessionState, bindSession } from "../../_session-core";
import { loadSession } from "../../_session-read";
import { sessionManager } from "../../_session-write";
import type { SessionHooks } from "../../_session-types";
import { guardName, type SessionPlugin } from "../_plugin";
import type { CookieAttributes } from "../_cookie";
import type { SessionClaims, SessionManager, SessionContext } from "./types";
import { PREFIX, elysiaSessionPort } from "./_shared";

export type { SessionContext };

const codec = createJWSCodec({ prefix: PREFIX, defaultName: "elysia-jws" });

export interface SessionJWS<
  T extends Record<string, any> = SessionClaims,
  MaxAge extends ExpiresIn | undefined = ExpiresIn | undefined,
> extends SessionState<T, MaxAge> {}

export interface SessionHooksJWS<
  T extends Record<string, any> = SessionClaims,
  MaxAge extends ExpiresIn | undefined = ExpiresIn | undefined,
  TContext extends SessionContext = SessionContext,
> extends SessionHooks<
  SessionJWS<T, MaxAge>,
  { context: TContext },
  SessionConfigJWS<T, MaxAge, TContext>
> {
  onVerifyKeyLookup?: (args: {
    header: JWKLookupFunctionHeader;
    context: TContext;
    config: SessionConfigJWS<T, MaxAge, TContext>;
  }) => JWKSet | JWSVerifyJWK | Promise<JWKSet | JWSVerifyJWK>;
}

export interface SessionConfigJWS<
  T extends Record<string, any> = SessionClaims,
  MaxAge extends ExpiresIn | undefined = ExpiresIn | undefined,
  TContext extends SessionContext = SessionContext,
> extends JWSSessionConfig<MaxAge, CookieAttributes> {
  /** Context property the session is exposed under. Default `"session"`. */
  contextKey?: string;
  hooks?: SessionHooksJWS<T, MaxAge, TContext>;
}

export async function createJWSSession<
  T extends Record<string, any> = SessionClaims,
  MaxAge extends ExpiresIn | undefined = ExpiresIn | undefined,
  TContext extends SessionContext = SessionContext,
>(
  context: TContext,
  config: SessionConfigJWS<T, MaxAge, TContext>,
): Promise<SessionManager<T, MaxAge>> {
  const binding = bind(context, config);
  await loadSession<T, MaxAge, SessionContext, JWSCodecConfig>(binding);
  return sessionManager<T, MaxAge, SessionContext, JWSCodecConfig>(binding);
}

export function jwsSession<
  T extends Record<string, any> = SessionClaims,
  MaxAge extends ExpiresIn | undefined = ExpiresIn | undefined,
  K extends string = "session",
>(
  config: SessionConfigJWS<T, MaxAge> &
    (K extends "session" ? { contextKey?: K } : { contextKey: K }),
): SessionPlugin<{ [P in K]: SessionManager<T, MaxAge> }, `require${Capitalize<K>}`> {
  const contextKey = (config.contextKey ?? "session") as K;
  // The seed carries the session name as well as the context key, so two
  // differently-named sessions register as two plugins rather than one.
  const seed = `${config.name || codec.defaultName}:${contextKey}`;
  return new Elysia({ name: "unjwt/elysia-jws", seed })
    .resolve({ as: "scoped" }, async ({ cookie, request }) => {
      const session = await createJWSSession<T, MaxAge, SessionContext>(
        { cookie, request },
        config,
      );
      return { [contextKey]: session } as { [P in K]: SessionManager<T, MaxAge> };
    })
    .macro({
      [guardName(contextKey)]: {
        resolve(ctx) {
          const session = (ctx as Record<string, unknown>)[contextKey] as
            | SessionManager<T, MaxAge>
            | undefined;
          if (!session?.id) return ctx.status(401, "Unauthorized");
          return {};
        },
      },
    }) as unknown as SessionPlugin<
    { [P in K]: SessionManager<T, MaxAge> },
    `require${Capitalize<K>}`
  >;
}

function bind<
  T extends Record<string, any>,
  MaxAge extends ExpiresIn | undefined,
  TContext extends SessionContext,
>(
  context: TContext,
  config: SessionConfigJWS<T, MaxAge, TContext>,
): SessionBinding<SessionContext, JWSCodecConfig> {
  return bindSession(context as SessionContext, config as unknown as JWSCodecConfig, {
    port: elysiaSessionPort,
    codec,
  });
}
