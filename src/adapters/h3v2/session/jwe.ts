import type { H3Event, HTTPEvent } from "h3v2";

import type { CookieSerializeOptions } from "cookie-esv3";

import type { ExpiresIn, JWEDecryptJWK, JWEHeaderParameters } from "../../../core/types";
import type { SessionIssueOptions } from "../../_session";
import { type JWECodecConfig, type JWESessionConfig, createJWECodec } from "../../_codec-jwe";
import {
  type SessionBinding,
  type SessionState,
  bindSession,
  openSessionToken,
  sessionToken,
} from "../../_session-core";
import { loadSession } from "../../_session-read";
import { dropSession, encodeSession, issueSession, sessionManager } from "../../_session-write";
import type { SessionHooks, SessionRecord } from "../../_session-types";
import type { SessionClaims, SessionUpdate, SessionManager } from "./types";
import { PREFIX, h3SessionPort } from "./_shared";

export type { SessionDecryptOptions, SessionEncryptOptions } from "../../_codec-jwe";

const codec = createJWECodec({ prefix: PREFIX, defaultName: "h3-jwe" });

/**
 * In-memory session state for the current request, mirroring the claims of
 * the underlying compact JWE token.
 */
export interface SessionJWE<
  T extends SessionRecord = SessionClaims,
  MaxAge extends ExpiresIn | undefined = ExpiresIn | undefined,
> extends SessionState<T, MaxAge> {}

/**
 * Lifecycle hooks for JWE sessions. `onRead`, `onExpire`, and `onError` are
 * mutually exclusive per incoming token — `onRead` fires only when a session
 * was successfully established from it.
 */
export interface SessionHooksJWE<
  T extends SessionRecord = SessionClaims,
  MaxAge extends ExpiresIn | undefined = ExpiresIn | undefined,
  TEvent extends HTTPEvent | H3Event = HTTPEvent | H3Event,
> extends SessionHooks<
  SessionJWE<T, MaxAge>,
  { event: TEvent },
  SessionConfigJWE<T, MaxAge, TEvent>
> {
  /** Resolve the decryption key for the incoming token from its protected header (e.g. by `kid`). */
  onUnsealKeyLookup?: (args: {
    header: JWEHeaderParameters;
    event: TEvent;
    config: SessionConfigJWE<T, MaxAge, TEvent>;
  }) => JWEDecryptJWK | Promise<JWEDecryptJWK>;
}

/**
 * Configuration for a JWE-backed (encrypted) session.
 */
export interface SessionConfigJWE<
  T extends SessionRecord = SessionClaims,
  MaxAge extends ExpiresIn | undefined = ExpiresIn | undefined,
  TEvent extends HTTPEvent | H3Event = HTTPEvent | H3Event,
> extends JWESessionConfig<MaxAge, CookieSerializeOptions> {
  /**
   * Session name — drives the cookie name and the default session header. Default `"h3-jwe"`.
   * Prefer a `__Host-` prefix; a name ending in a dot and digits is refused.
   */
  name?: string;
  /** Lifecycle hooks — see {@link SessionHooksJWE}. */
  hooks?: SessionHooksJWE<T, MaxAge, TEvent>;
}

/**
 * Create a session manager for the current request using JWE (encrypted).
 */
export async function useJWESession<
  T extends SessionRecord = SessionClaims,
  MaxAge extends ExpiresIn | undefined = ExpiresIn | undefined,
  TEvent extends HTTPEvent = HTTPEvent,
>(event: TEvent, config: SessionConfigJWE<T, MaxAge, TEvent>): Promise<SessionManager<T, MaxAge>> {
  const binding = bind(event, config);
  await loadSession<T, MaxAge, HTTPEvent, JWECodecConfig>(binding);
  return sessionManager<T, MaxAge, HTTPEvent, JWECodecConfig>(binding);
}

/**
 * Get (and lazily initialize) the session for the current request.
 */
export async function getJWESession<
  T extends SessionRecord = SessionClaims,
  MaxAge extends ExpiresIn | undefined = ExpiresIn | undefined,
  TEvent extends HTTPEvent = HTTPEvent,
>(event: TEvent, config: SessionConfigJWE<T, MaxAge, TEvent>): Promise<SessionJWE<T, MaxAge>> {
  return loadSession<T, MaxAge, HTTPEvent, JWECodecConfig>(bind(event, config));
}

/**
 * Read the raw session token for the request. The cookie is consulted first,
 * and the session header (default `x-<name>-session`, optional case-insensitive
 * `Bearer` prefix) only when the cookie carries none.
 */
export function getJWESessionToken<
  T extends SessionRecord = SessionClaims,
  MaxAge extends ExpiresIn | undefined = ExpiresIn | undefined,
  TEvent extends HTTPEvent = HTTPEvent,
>(event: TEvent, config: SessionConfigJWE<T, MaxAge, TEvent>): string | undefined {
  return sessionToken(bind(event, config));
}

/**
 * Update the session data (if provided) and reissue the JWE token.
 * Pass `options.maxAge` to give this one token a lifetime of its own.
 */
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

/**
 * Seal the current session as a compact JWE and return it — no cookie is
 * written. A session with no ID yet is sealed under a fresh `jti`, and a
 * config with neither a cookie nor a session header seals an empty session,
 * so one-off tokens (magic links, password resets) need no token source.
 * Payload: `session.data` spread at the top level, plus the reserved claims
 * `jti`, `iat`, and `exp` (when the session has a lifetime).
 */
export async function sealJWESession<
  T extends SessionRecord = SessionClaims,
  MaxAge extends ExpiresIn | undefined = ExpiresIn | undefined,
  TEvent extends HTTPEvent = HTTPEvent,
>(event: TEvent, config: SessionConfigJWE<T, MaxAge, TEvent>): Promise<string> {
  return encodeSession(bind(event, config));
}

/**
 * Decrypt and parse a compact JWE into a Session structure.
 * Performs:
 *  - authenticated decryption
 *  - claim validation (always on): `jti` & `iat` required, `exp` honoured
 *  - `typ` and `cty` header checks, and alg/enc pinning when configured
 *  - `exp` required when the session has a `maxAge`
 */
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

/**
 * Clear the session: drop the cookie and leave an empty session behind, so a
 * later read in the same request sees no session rather than the request cookie.
 */
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
  });
}
