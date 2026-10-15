import type { ExpiresIn } from "../../../core/types";
import {
  type JWECodecConfig,
  type JWESessionConfig,
  type JWESessionHooks,
  createJWECodec,
} from "../../_codec-jwe";
import { type SessionBinding, type SessionState, bindSession } from "../../_session-core";
import { loadSession } from "../../_session-read";
import { sessionManager, sessionActions } from "../../_session-write";
import type { SessionRecord } from "../../_session-types";
import { type SessionPlugin, sessionPlugin } from "../_plugin";
import type { CookieAttributes } from "../_cookie";
import type { SessionClaims, SessionManager, SessionContext } from "./types";
import { PREFIX, elysiaSessionPort } from "./_shared";

export type { SessionContext };
export type { SessionDecryptOptions, SessionEncryptOptions } from "../../_codec-jwe";

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

export async function createJWESession<
  T extends SessionRecord = SessionClaims,
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
  T extends SessionRecord = SessionClaims,
  MaxAge extends ExpiresIn | undefined = ExpiresIn | undefined,
  K extends string = "session",
>(
  config: SessionConfigJWE<T, MaxAge> &
    (K extends "session" ? { contextKey?: K } : { contextKey: K }),
): SessionPlugin<{ [P in K]: SessionManager<T, MaxAge> }, `require${Capitalize<K>}`> {
  return sessionPlugin<SessionManager<T, MaxAge>, K>({
    name: "unjwt/elysia-jwe",
    sessionName: config.name || codec.defaultName,
    contextKey: config.contextKey,
    create: (context) => createJWESession<T, MaxAge>(context, config),
  });
}

function bind<
  T extends SessionRecord,
  MaxAge extends ExpiresIn | undefined,
  TContext extends SessionContext,
>(
  context: TContext,
  config: SessionConfigJWE<T, MaxAge, TContext>,
): SessionBinding<SessionContext, JWECodecConfig> {
  return bindSession<SessionContext, JWECodecConfig>(context, config, {
    port: elysiaSessionPort,
    codec,
    actions: sessionActions(),
  });
}
