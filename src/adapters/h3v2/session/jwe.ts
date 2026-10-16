import type { HTTPEvent } from "h3v2";

import type { ExpiresIn } from "../../../core/types";
import type { SessionIssueOptions } from "../../_session";
import {
  type JWECodecConfig,
  type JWESessionConfig,
  type JWESessionHooks,
  createJWECodec,
} from "../../_codec-jwe";
import {
  type SessionBinding,
  type SessionState,
  bindSession,
  openSessionToken,
  sessionToken,
} from "../../_session-core";
import { loadSession } from "../../_session-read";
import {
  dropSession,
  encodeSession,
  issueSession,
  sessionManager,
  sessionActions,
} from "../../_session-write";
import type { SessionRecord } from "../../_session-types";
import type { CookieSerializeOptions } from "../_cookie";
import type { SessionClaims, SessionUpdate, SessionManager } from "./types";
import { PREFIX, h3SessionPort } from "./_shared";

export type { SessionDecryptOptions, SessionEncryptOptions } from "../../_codec-jwe";

const codec = createJWECodec({ prefix: PREFIX, defaultName: "h3-jwe" });

/** Session state for the current request, mirroring the claims of its JWE token. */
export interface SessionJWE<
  T extends SessionRecord = SessionClaims,
  MaxAge extends ExpiresIn | undefined = ExpiresIn | undefined,
> extends SessionState<T, MaxAge> {}

/** JWE session hooks; `onRead`, `onExpire` and `onError` are mutually exclusive per token. */
export interface SessionHooksJWE<
  T extends SessionRecord = SessionClaims,
  MaxAge extends ExpiresIn | undefined = ExpiresIn | undefined,
  TEvent extends HTTPEvent = HTTPEvent,
> extends JWESessionHooks<
  SessionJWE<T, MaxAge>,
  SessionManager<T, MaxAge>,
  { event: TEvent },
  SessionConfigJWE<T, MaxAge, TEvent>
> {}

/** Configuration for a JWE-backed (encrypted) session. */
export interface SessionConfigJWE<
  T extends SessionRecord = SessionClaims,
  MaxAge extends ExpiresIn | undefined = ExpiresIn | undefined,
  TEvent extends HTTPEvent = HTTPEvent,
> extends JWESessionConfig<MaxAge, CookieSerializeOptions> {
  /** Cookie and session-header name. Default `"h3-jwe"`; a `.<digits>` suffix throws `ERR_SESSION_CONFIG_INVALID`. */
  name?: string;
  hooks?: SessionHooksJWE<T, MaxAge, TEvent>;
}

/** Create a JWE (encrypted) session manager for the request. */
export async function useJWESession<
  T extends SessionRecord = SessionClaims,
  MaxAge extends ExpiresIn | undefined = ExpiresIn | undefined,
  TEvent extends HTTPEvent = HTTPEvent,
>(event: TEvent, config: SessionConfigJWE<T, MaxAge, TEvent>): Promise<SessionManager<T, MaxAge>> {
  const binding = bind(event, config);
  await loadSession<T, MaxAge, HTTPEvent, JWECodecConfig>(binding);
  return sessionManager<T, MaxAge, HTTPEvent, JWECodecConfig>(binding);
}

/** Get (and lazily initialize) the session for the current request. */
export async function getJWESession<
  T extends SessionRecord = SessionClaims,
  MaxAge extends ExpiresIn | undefined = ExpiresIn | undefined,
  TEvent extends HTTPEvent = HTTPEvent,
>(event: TEvent, config: SessionConfigJWE<T, MaxAge, TEvent>): Promise<SessionJWE<T, MaxAge>> {
  return loadSession<T, MaxAge, HTTPEvent, JWECodecConfig>(bind(event, config));
}

/** Read the raw session token: cookie first, then the session header (default `x-<name>-session`, optional `Bearer`). */
export function getJWESessionToken<
  T extends SessionRecord = SessionClaims,
  MaxAge extends ExpiresIn | undefined = ExpiresIn | undefined,
  TEvent extends HTTPEvent = HTTPEvent,
>(event: TEvent, config: SessionConfigJWE<T, MaxAge, TEvent>): string | undefined {
  return sessionToken(bind(event, config));
}

/** Update the session data (if provided) and reissue the JWE; `options.maxAge` overrides this token's lifetime. */
export async function updateJWESession<
  T extends SessionRecord = SessionClaims,
  MaxAge extends ExpiresIn | undefined = ExpiresIn | undefined,
  TEvent extends HTTPEvent = HTTPEvent,
>(
  event: TEvent,
  config: SessionConfigJWE<T, MaxAge, TEvent>,
  update?: SessionUpdate<T>,
  options?: SessionIssueOptions,
): Promise<SessionJWE<T, MaxAge> & { id: string; token: string }> {
  return issueSession<T, MaxAge, HTTPEvent, JWECodecConfig>(bind(event, config), update, options);
}

/** Seal the session as a compact JWE without writing a cookie; fresh `jti` if no ID, no token source needed. */
export async function sealJWESession<
  T extends SessionRecord = SessionClaims,
  MaxAge extends ExpiresIn | undefined = ExpiresIn | undefined,
  TEvent extends HTTPEvent = HTTPEvent,
>(event: TEvent, config: SessionConfigJWE<T, MaxAge, TEvent>): Promise<string> {
  return encodeSession(bind(event, config));
}

/** Decrypt a compact JWE into a session, checking `typ`, pinned `alg`/`enc`, `jti`/`iat` and `exp` (required with `maxAge`). */
export async function unsealJWESession<
  T extends SessionRecord = SessionClaims,
  MaxAge extends ExpiresIn | undefined = ExpiresIn | undefined,
  TEvent extends HTTPEvent = HTTPEvent,
>(
  event: TEvent,
  config: SessionConfigJWE<T, MaxAge, TEvent>,
  sealed: string,
): Promise<Partial<SessionJWE<T, MaxAge>>> {
  return openSessionToken<T, MaxAge, JWECodecConfig>(codec, config, {
    token: sealed,
    carrier: { event },
  });
}

/** Drop the session cookie and leave an empty session for the rest of the request. */
export async function clearJWESession<
  T extends SessionRecord = SessionClaims,
  MaxAge extends ExpiresIn | undefined = ExpiresIn | undefined,
  TEvent extends HTTPEvent = HTTPEvent,
>(event: TEvent, config: SessionConfigJWE<T, MaxAge, TEvent>): Promise<void> {
  return dropSession(bind(event, config));
}

function bind<
  T extends SessionRecord,
  MaxAge extends ExpiresIn | undefined,
  TEvent extends HTTPEvent,
>(
  event: TEvent,
  config: SessionConfigJWE<T, MaxAge, TEvent>,
): SessionBinding<HTTPEvent, JWECodecConfig> {
  return bindSession<HTTPEvent, JWECodecConfig>(event, config, {
    port: h3SessionPort,
    codec,
    actions: sessionActions(),
  });
}
