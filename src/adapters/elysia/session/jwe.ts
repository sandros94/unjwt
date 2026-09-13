import { Elysia } from "elysia";

import type { ExpiresIn, JWEDecryptJWK, JWEHeaderParameters } from "../../../core/types";
import { type JWECodecConfig, type JWESessionConfig, createJWECodec } from "../../_codec-jwe";
import { type SessionBinding, type SessionState, bindSession } from "../../_session-core";
import { loadSession } from "../../_session-read";
import { sessionManager } from "../../_session-write";
import type { SessionHooks } from "../../_session-types";
import { guardName, type SessionPlugin } from "../_plugin";
import type { CookieAttributes } from "../_cookie";
import type { SessionClaims, SessionManager, SessionContext } from "./types";
import { PREFIX, elysiaSessionPort } from "./_shared";

export type { SessionContext };
export type { SessionDecryptOptions } from "../../_codec-jwe";

const codec = createJWECodec({ prefix: PREFIX, defaultName: "elysia-jwe" });

export interface SessionJWE<
  T extends Record<string, any> = SessionClaims,
  MaxAge extends ExpiresIn | undefined = ExpiresIn | undefined,
> extends SessionState<T, MaxAge> {}

export interface SessionHooksJWE<
  T extends Record<string, any> = SessionClaims,
  MaxAge extends ExpiresIn | undefined = ExpiresIn | undefined,
  TContext extends SessionContext = SessionContext,
> extends SessionHooks<
  SessionJWE<T, MaxAge>,
  { context: TContext },
  SessionConfigJWE<T, MaxAge, TContext>
> {
  onUnsealKeyLookup?: (args: {
    header: JWEHeaderParameters;
    context: TContext;
    config: SessionConfigJWE<T, MaxAge, TContext>;
  }) => JWEDecryptJWK | Promise<JWEDecryptJWK>;
}

export interface SessionConfigJWE<
  T extends Record<string, any> = SessionClaims,
  MaxAge extends ExpiresIn | undefined = ExpiresIn | undefined,
  TContext extends SessionContext = SessionContext,
> extends JWESessionConfig<MaxAge, CookieAttributes> {
  /** Context property the session is exposed under. Default `"session"`. */
  contextKey?: string;
  hooks?: SessionHooksJWE<T, MaxAge, TContext>;
}

export async function createJWESession<
  T extends Record<string, any> = SessionClaims,
  MaxAge extends ExpiresIn | undefined = ExpiresIn | undefined,
  TContext extends SessionContext = SessionContext,
>(
  context: TContext,
  config: SessionConfigJWE<T, MaxAge, TContext>,
): Promise<SessionManager<T, MaxAge>> {
  const binding = bind(context, config);
  await loadSession<T, MaxAge, SessionContext, JWECodecConfig>(binding);
  return sessionManager<T, MaxAge, SessionContext, JWECodecConfig>(binding);
}

export function jweSession<
  T extends Record<string, any> = SessionClaims,
  MaxAge extends ExpiresIn | undefined = ExpiresIn | undefined,
  K extends string = "session",
>(
  config: SessionConfigJWE<T, MaxAge> &
    (K extends "session" ? { contextKey?: K } : { contextKey: K }),
): SessionPlugin<{ [P in K]: SessionManager<T, MaxAge> }, `require${Capitalize<K>}`> {
  const contextKey = (config.contextKey ?? "session") as K;
  // The seed carries the session name as well as the context key, so two
  // differently-named sessions register as two plugins rather than one.
  const seed = `${config.name || codec.defaultName}:${contextKey}`;
  return new Elysia({ name: "unjwt/elysia-jwe", seed })
    .resolve({ as: "scoped" }, async ({ cookie, request }) => {
      const session = await createJWESession<T, MaxAge, SessionContext>(
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
  config: SessionConfigJWE<T, MaxAge, TContext>,
): SessionBinding<SessionContext, JWECodecConfig> {
  return bindSession(context as SessionContext, config as unknown as JWECodecConfig, {
    port: elysiaSessionPort,
    codec,
  });
}
