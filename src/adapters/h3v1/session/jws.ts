import type { H3Event } from "h3v1";

import type { ExpiresIn } from "../../../core/types";
import type { SessionIssueOptions } from "../../_session";
import {
  type JWSCodecConfig,
  type JWSSessionConfig,
  type JWSSessionHooks,
  createJWSCodec,
} from "../../_codec-jws";
export type { SessionSignOptions, SessionVerifyOptions } from "../../_codec-jws";
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
import { type CompatEvent, PREFIX, h3SessionPort } from "./_shared";

const codec = createJWSCodec({ prefix: PREFIX, defaultName: "h3-jws" });

/** Session state for the current request, mirroring the claims of its JWS token. */
export interface SessionJWS<
  T extends SessionRecord = SessionClaims,
  MaxAge extends ExpiresIn | undefined = ExpiresIn | undefined,
> extends SessionState<T, MaxAge> {}

/** JWS session hooks; `onRead`, `onExpire` and `onError` are mutually exclusive per token. */
export interface SessionHooksJWS<
  T extends SessionRecord = SessionClaims,
  MaxAge extends ExpiresIn | undefined = ExpiresIn | undefined,
  TEvent extends CompatEvent | H3Event = CompatEvent | H3Event,
> extends JWSSessionHooks<
  SessionJWS<T, MaxAge>,
  SessionManager<T, MaxAge>,
  { event: TEvent },
  SessionConfigJWS<T, MaxAge, TEvent>
> {}

/** Configuration for a JWS-backed (signed, not encrypted) session. */
export interface SessionConfigJWS<
  T extends SessionRecord = SessionClaims,
  MaxAge extends ExpiresIn | undefined = ExpiresIn | undefined,
  TEvent extends CompatEvent | H3Event = CompatEvent | H3Event,
> extends JWSSessionConfig<MaxAge, CookieSerializeOptions> {
  /** Cookie and session-header name. Default `"h3-jws"`; a `.<digits>` suffix throws `ERR_SESSION_CONFIG_INVALID`. */
  name?: string;
  hooks?: SessionHooksJWS<T, MaxAge, TEvent>;
}

/** Create a JWS (signed, not encrypted) session manager for the request; clients can read its data. */
export async function useJWSSession<
  T extends SessionRecord = SessionClaims,
  MaxAge extends ExpiresIn | undefined = ExpiresIn | undefined,
  TEvent extends CompatEvent | H3Event = CompatEvent | H3Event,
>(event: TEvent, config: SessionConfigJWS<T, MaxAge, TEvent>): Promise<SessionManager<T, MaxAge>> {
  const binding = bind(event, config);
  await loadSession<T, MaxAge, CompatEvent | H3Event, JWSCodecConfig>(binding);
  return sessionManager<T, MaxAge, CompatEvent | H3Event, JWSCodecConfig>(binding);
}

/** Get (and lazily initialize) the session for the current request. */
export async function getJWSSession<
  T extends SessionRecord = SessionClaims,
  MaxAge extends ExpiresIn | undefined = ExpiresIn | undefined,
  TEvent extends CompatEvent | H3Event = CompatEvent | H3Event,
>(event: TEvent, config: SessionConfigJWS<T, MaxAge, TEvent>): Promise<SessionJWS<T, MaxAge>> {
  return loadSession<T, MaxAge, CompatEvent | H3Event, JWSCodecConfig>(bind(event, config));
}

/** Read the raw session token: cookie first, then the session header (default `x-<name>-session`, optional `Bearer`). */
export function getJWSSessionToken<
  T extends SessionRecord = SessionClaims,
  MaxAge extends ExpiresIn | undefined = ExpiresIn | undefined,
  TEvent extends CompatEvent | H3Event = CompatEvent | H3Event,
>(event: TEvent, config: SessionConfigJWS<T, MaxAge, TEvent>): string | undefined {
  return sessionToken(bind(event, config));
}

/** Update the session data (if provided) and reissue the JWS; `options.maxAge` overrides this token's lifetime. */
export async function updateJWSSession<
  T extends SessionRecord = SessionClaims,
  MaxAge extends ExpiresIn | undefined = ExpiresIn | undefined,
  TEvent extends CompatEvent | H3Event = CompatEvent | H3Event,
>(
  event: TEvent,
  config: SessionConfigJWS<T, MaxAge, TEvent>,
  update?: SessionUpdate<T>,
  options?: SessionIssueOptions,
): Promise<SessionJWS<T, MaxAge> & { id: string; token: string }> {
  return issueSession<T, MaxAge, CompatEvent | H3Event, JWSCodecConfig>(
    bind(event, config),
    update,
    options,
  );
}

/** Sign the session as a compact JWS without writing a cookie; fresh `jti` if no ID, no token source needed. */
export async function signJWSSession<
  T extends SessionRecord = SessionClaims,
  MaxAge extends ExpiresIn | undefined = ExpiresIn | undefined,
  TEvent extends CompatEvent | H3Event = CompatEvent | H3Event,
>(event: TEvent, config: SessionConfigJWS<T, MaxAge, TEvent>): Promise<string> {
  return encodeSession(bind(event, config));
}

/** Verify a compact JWS into a session, checking `typ`, pinned `alg`, `jti`/`iat` and `exp` (required with `maxAge`). */
export async function verifyJWSSession<
  T extends SessionRecord = SessionClaims,
  MaxAge extends ExpiresIn | undefined = ExpiresIn | undefined,
  TEvent extends CompatEvent | H3Event = CompatEvent | H3Event,
>(
  event: TEvent,
  config: SessionConfigJWS<T, MaxAge, TEvent>,
  token: string,
): Promise<Partial<SessionJWS<T, MaxAge>>> {
  return openSessionToken<T, MaxAge, JWSCodecConfig>(codec, config, {
    token,
    carrier: { event },
  });
}

/** Drop the session cookie and leave an empty session for the rest of the request. */
export async function clearJWSSession<
  T extends SessionRecord = SessionClaims,
  MaxAge extends ExpiresIn | undefined = ExpiresIn | undefined,
  TEvent extends CompatEvent | H3Event = CompatEvent | H3Event,
>(event: TEvent, config: SessionConfigJWS<T, MaxAge, TEvent>): Promise<void> {
  return dropSession(bind(event, config));
}

function bind<
  T extends SessionRecord,
  MaxAge extends ExpiresIn | undefined,
  TEvent extends CompatEvent | H3Event,
>(
  event: TEvent,
  config: SessionConfigJWS<T, MaxAge, TEvent>,
): SessionBinding<CompatEvent | H3Event, JWSCodecConfig> {
  return bindSession<CompatEvent | H3Event, JWSCodecConfig>(event, config, {
    port: h3SessionPort,
    codec,
    actions: sessionActions(),
  });
}
