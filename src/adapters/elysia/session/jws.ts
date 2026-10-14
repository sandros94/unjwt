import type { ExpiresIn } from "../../../core/types";
import {
  type JWSCodecConfig,
  type JWSSessionConfig,
  type JWSSessionHooks,
  createJWSCodec,
} from "../../_codec-jws";
export type { SessionSignOptions, SessionVerifyOptions } from "../../_codec-jws";
import { type SessionBinding, type SessionState, bindSession } from "../../_session-core";
import { loadSession } from "../../_session-read";
import { sessionManager } from "../../_session-write";
import type { SessionRecord } from "../../_session-types";
import { type SessionPlugin, sessionPlugin } from "../_plugin";
import type { CookieAttributes } from "../_cookie";
import type { SessionClaims, SessionManager, SessionContext } from "./types";
import { PREFIX, elysiaSessionPort } from "./_shared";

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

export async function createJWSSession<
  T extends SessionRecord = SessionClaims,
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
  T extends SessionRecord = SessionClaims,
  MaxAge extends ExpiresIn | undefined = ExpiresIn | undefined,
  K extends string = "session",
>(
  config: SessionConfigJWS<T, MaxAge> &
    (K extends "session" ? { contextKey?: K } : { contextKey: K }),
): SessionPlugin<{ [P in K]: SessionManager<T, MaxAge> }, `require${Capitalize<K>}`> {
  return sessionPlugin<SessionManager<T, MaxAge>, K>({
    name: "unjwt/elysia-jws",
    sessionName: config.name || codec.defaultName,
    contextKey: config.contextKey,
    create: (context) => createJWSSession<T, MaxAge>(context, config),
  });
}

function bind<
  T extends SessionRecord,
  MaxAge extends ExpiresIn | undefined,
  TContext extends SessionContext,
>(
  context: TContext,
  config: SessionConfigJWS<T, MaxAge, TContext>,
): SessionBinding<SessionContext, JWSCodecConfig> {
  return bindSession<SessionContext, JWSCodecConfig>(context, config, {
    port: elysiaSessionPort,
    codec,
  });
}
