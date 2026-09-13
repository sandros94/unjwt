import type { HTTPEvent } from "h3v2";

import type { CookieSerializeOptions } from "cookie-esv3";

import type { ExpiresIn, JWKSet, JWSVerifyJWK, JWKLookupFunctionHeader } from "../../../core/types";
import type { SessionIssueOptions } from "../../_session";
import { type JWSCodecConfig, type JWSSessionConfig, createJWSCodec } from "../../_codec-jws";
import {
  type SessionBinding,
  type SessionState,
  bindSession,
  sessionToken,
} from "../../_session-core";
import { loadSession } from "../../_session-read";
import { dropSession, encodeSession, issueSession, sessionManager } from "../../_session-write";
import type { SessionHooks } from "../../_session-types";
import type { SessionClaims, SessionUpdate, SessionManager } from "./types";
import { PREFIX, h3SessionPort } from "./_shared";

const codec = createJWSCodec({ prefix: PREFIX, defaultName: "h3-jws" });

/**
 * In-memory session state for the current request, mirroring the claims of
 * the underlying compact JWS token.
 */
export interface SessionJWS<
  T extends Record<string, any> = SessionClaims,
  MaxAge extends ExpiresIn | undefined = ExpiresIn | undefined,
> extends SessionState<T, MaxAge> {}

/**
 * Lifecycle hooks for JWS sessions. `onRead`, `onExpire`, and `onError` are
 * mutually exclusive per incoming token — `onRead` fires only when a session
 * was successfully established from it.
 */
export interface SessionHooksJWS<
  T extends Record<string, any> = SessionClaims,
  MaxAge extends ExpiresIn | undefined = ExpiresIn | undefined,
  TEvent extends HTTPEvent = HTTPEvent,
> extends SessionHooks<
  SessionJWS<T, MaxAge>,
  { event: TEvent },
  SessionConfigJWS<T, MaxAge, TEvent>
> {
  /** Resolve the verification key(s) for the incoming token from its protected header (e.g. by `kid`). */
  onVerifyKeyLookup?: (args: {
    header: JWKLookupFunctionHeader;
    event: TEvent;
    config: SessionConfigJWS<T, MaxAge, TEvent>;
  }) => JWKSet | JWSVerifyJWK | Promise<JWKSet | JWSVerifyJWK>;
}

/**
 * Configuration for a JWS-backed (signed, not encrypted) session.
 */
export interface SessionConfigJWS<
  T extends Record<string, any> = SessionClaims,
  MaxAge extends ExpiresIn | undefined = ExpiresIn | undefined,
  TEvent extends HTTPEvent = HTTPEvent,
> extends JWSSessionConfig<MaxAge, CookieSerializeOptions> {
  /** Session name — drives the cookie name and the default session header. Default `"h3-jws"`. */
  name?: string;
  /** Lifecycle hooks — see {@link SessionHooksJWS}. */
  hooks?: SessionHooksJWS<T, MaxAge, TEvent>;
}

/**
 * Create a session manager for the current request using JWS (signed only, not encrypted).
 * NOTE: Contents are visible to clients (Base64URL-decoded JSON). Do not store secrets in session data.
 */
export async function useJWSSession<
  T extends Record<string, any> = SessionClaims,
  MaxAge extends ExpiresIn | undefined = ExpiresIn | undefined,
  TEvent extends HTTPEvent = HTTPEvent,
>(event: TEvent, config: SessionConfigJWS<T, MaxAge, TEvent>): Promise<SessionManager<T, MaxAge>> {
  const binding = bind(event, config);
  await loadSession<T, MaxAge, HTTPEvent, JWSCodecConfig>(binding);
  return sessionManager<T, MaxAge, HTTPEvent, JWSCodecConfig>(binding);
}

/**
 * Get (and lazily initialize) the session for the current request.
 */
export async function getJWSSession<
  T extends Record<string, any> = SessionClaims,
  MaxAge extends ExpiresIn | undefined = ExpiresIn | undefined,
  TEvent extends HTTPEvent = HTTPEvent,
>(event: TEvent, config: SessionConfigJWS<T, MaxAge, TEvent>): Promise<SessionJWS<T, MaxAge>> {
  return loadSession<T, MaxAge, HTTPEvent, JWSCodecConfig>(bind(event, config));
}

/**
 * Read the raw session token for the request. The cookie is consulted first,
 * and the session header (default `x-<name>-session`, optional case-insensitive
 * `Bearer` prefix) only when the cookie carries none.
 */
export function getJWSSessionToken<
  T extends Record<string, any> = SessionClaims,
  MaxAge extends ExpiresIn | undefined = ExpiresIn | undefined,
  TEvent extends HTTPEvent = HTTPEvent,
>(event: TEvent, config: SessionConfigJWS<T, MaxAge, TEvent>): string | undefined {
  return sessionToken(bind(event, config));
}

/**
 * Update the session data (if provided) and reissue the JWS token.
 * Pass `options.maxAge` to give this one token a lifetime of its own.
 */
export async function updateJWSSession<
  T extends Record<string, any> = SessionClaims,
  MaxAge extends ExpiresIn | undefined = ExpiresIn | undefined,
  TEvent extends HTTPEvent = HTTPEvent,
>(
  event: TEvent,
  config: SessionConfigJWS<T, MaxAge, TEvent>,
  update?: SessionUpdate<T>,
  options?: SessionIssueOptions,
): Promise<SessionJWS<T, MaxAge>> {
  return issueSession<T, MaxAge, HTTPEvent, JWSCodecConfig>(bind(event, config), update, options);
}

/**
 * Sign the current session as a compact JWS.
 * Payload: `session.data` spread at the top level, plus the reserved claims
 * `jti`, `iat`, and `exp` (when the session has a lifetime).
 */
export async function signJWSSession<
  T extends Record<string, any> = SessionClaims,
  MaxAge extends ExpiresIn | undefined = ExpiresIn | undefined,
  TEvent extends HTTPEvent = HTTPEvent,
>(event: TEvent, config: SessionConfigJWS<T, MaxAge, TEvent>): Promise<string> {
  return encodeSession(bind(event, config));
}

/**
 * Verify and parse a compact JWS into a Session structure.
 * Performs:
 *  - cryptographic signature verification
 *  - claim validation (always on): `jti` & `iat` required, `exp` honoured
 *  - `typ` and `cty` header checks, and algorithm pinning when configured
 *  - `maxAge` enforced as `maxTokenAge`, and `exp` required alongside it
 */
export async function verifyJWSSession<
  T extends Record<string, any> = SessionClaims,
  MaxAge extends ExpiresIn | undefined = ExpiresIn | undefined,
  TEvent extends HTTPEvent = HTTPEvent,
>(
  event: TEvent,
  config: SessionConfigJWS<T, MaxAge, TEvent>,
  token: string,
): Promise<Partial<SessionJWS<T, MaxAge>>> {
  return codec.open(config as unknown as JWSCodecConfig, token, { event }) as Promise<
    Partial<SessionJWS<T, MaxAge>>
  >;
}

/**
 * Clear the session: drop the cookie and leave an empty session behind, so a
 * later read in the same request sees no session rather than the request cookie.
 */
export async function clearJWSSession<
  T extends Record<string, any> = SessionClaims,
  MaxAge extends ExpiresIn | undefined = ExpiresIn | undefined,
  TEvent extends HTTPEvent = HTTPEvent,
>(event: TEvent, config: SessionConfigJWS<T, MaxAge, TEvent>): Promise<void> {
  return dropSession<T, MaxAge, HTTPEvent, JWSCodecConfig>(bind(event, config));
}

function bind<
  T extends Record<string, any>,
  MaxAge extends ExpiresIn | undefined,
  TEvent extends HTTPEvent,
>(
  event: TEvent,
  config: SessionConfigJWS<T, MaxAge, TEvent>,
): SessionBinding<HTTPEvent, JWSCodecConfig> {
  return bindSession(event as HTTPEvent, config as unknown as JWSCodecConfig, {
    port: h3SessionPort,
    codec,
  });
}
