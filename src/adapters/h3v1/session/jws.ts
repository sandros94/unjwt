import type { H3Event } from "h3v1";

import type { ExpiresIn } from "../../../core/types/index.ts";
import type { SessionIssueOptions } from "../../_session.ts";
import {
  type JWSCodecConfig,
  type JWSSessionConfig,
  type JWSSessionHooks,
  createJWSCodec,
} from "../../_codec-jws.ts";
export type { SessionSignOptions, SessionVerifyOptions } from "../../_codec-jws.ts";
import { bindSession } from "../../_session-bind.ts";
import { type SessionBinding, type SessionState, openSessionToken } from "../../_session-core.ts";
import { type SessionDefinition, defineSession } from "../../_session-definition.ts";
import { loadSession } from "../../_session-read.ts";
import { dropSession, encodeSession, issueSession, sessionActions } from "../../_session-write.ts";
import type { SessionRecord } from "../../_session-types.ts";
import type { CookieSerializeOptions } from "../_cookie.ts";
import type { SessionClaims, SessionUpdate, SessionManager } from "./types.ts";
import { type CompatEvent, PREFIX, h3SessionDriver } from "./_shared.ts";

const codec = createJWSCodec({ prefix: PREFIX, defaultName: "h3-jws" });
const hookArgs = (event: CompatEvent | H3Event) => ({ event });

/**
 * Session state for the current request, mirroring the claims of its JWS token.
 * @deprecated `unjwt/adapters/h3v1` is removed in 0.9.0. Nuxt 4.6+ runs sessions through `unjwt/session` with handlers from `nuxt/server`; h3 v2, Nuxt 5 and Nitro 3 through `unjwt/adapters/h3`.
 */
export interface SessionJWS<
  T extends SessionRecord = SessionClaims,
  MaxAge extends ExpiresIn | undefined = ExpiresIn | undefined,
> extends SessionState<T, MaxAge> {}

/**
 * JWS session hooks; `onRead`, `onExpire` and `onError` are mutually exclusive per token.
 * @deprecated `unjwt/adapters/h3v1` is removed in 0.9.0. Nuxt 4.6+ runs sessions through `unjwt/session` with handlers from `nuxt/server`; h3 v2, Nuxt 5 and Nitro 3 through `unjwt/adapters/h3`.
 */
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

/**
 * Configuration for a JWS-backed (signed, not encrypted) session.
 * @deprecated `unjwt/adapters/h3v1` is removed in 0.9.0. Nuxt 4.6+ runs sessions through `unjwt/session` with handlers from `nuxt/server`; h3 v2, Nuxt 5 and Nitro 3 through `unjwt/adapters/h3`.
 */
export interface SessionConfigJWS<
  T extends SessionRecord = SessionClaims,
  MaxAge extends ExpiresIn | undefined = ExpiresIn | undefined,
  TEvent extends CompatEvent | H3Event = CompatEvent | H3Event,
> extends JWSSessionConfig<MaxAge, CookieSerializeOptions> {
  /** Cookie and session-header name. Default `"h3-jws"`; a `.<digits>` suffix throws `ERR_SESSION_CONFIG_INVALID`. */
  name?: string;
  hooks?: SessionHooksJWS<T, MaxAge, TEvent>;
}

/**
 * Defines a JWS (signed, not encrypted) session once, its data readable by clients; `use`, `token`, `issue` and `open` serve every request.
 * @deprecated `unjwt/adapters/h3v1` is removed in 0.9.0. Nuxt 4.6+ runs sessions through `unjwt/session` with handlers from `nuxt/server`; h3 v2, Nuxt 5 and Nitro 3 through `unjwt/adapters/h3`.
 */
export function defineJWSSession<
  T extends SessionRecord = SessionClaims,
  MaxAge extends ExpiresIn | undefined = ExpiresIn | undefined,
  TEvent extends CompatEvent | H3Event = CompatEvent | H3Event,
>(config: SessionConfigJWS<T, MaxAge, TEvent>): SessionDefinition<TEvent, T, MaxAge> {
  return defineSession<T, MaxAge, CompatEvent | H3Event, JWSCodecConfig>(config, {
    driver: h3SessionDriver,
    hookArgs,
    codec,
  });
}

/**
 * Create a JWS (signed, not encrypted) session manager for the request.
 * @deprecated Use `defineJWSSession(config).use(event)`.
 */
export async function useJWSSession<
  T extends SessionRecord = SessionClaims,
  MaxAge extends ExpiresIn | undefined = ExpiresIn | undefined,
  TEvent extends CompatEvent | H3Event = CompatEvent | H3Event,
>(event: TEvent, config: SessionConfigJWS<T, MaxAge, TEvent>): Promise<SessionManager<T, MaxAge>> {
  return defineJWSSession(config).use(event);
}

/**
 * Get (and lazily initialize) the session for the current request.
 * @deprecated Use `defineJWSSession(config).use(event)`; the manager exposes the same state.
 */
export async function getJWSSession<
  T extends SessionRecord = SessionClaims,
  MaxAge extends ExpiresIn | undefined = ExpiresIn | undefined,
  TEvent extends CompatEvent | H3Event = CompatEvent | H3Event,
>(event: TEvent, config: SessionConfigJWS<T, MaxAge, TEvent>): Promise<SessionJWS<T, MaxAge>> {
  return loadSession<T, MaxAge, CompatEvent | H3Event, JWSCodecConfig>(bind(event, config));
}

/**
 * Read the raw session token: cookie first, then the session header (default `x-<name>-session`, optional `Bearer`).
 * @deprecated Use `defineJWSSession(config).token(event)`.
 */
export function getJWSSessionToken<
  T extends SessionRecord = SessionClaims,
  MaxAge extends ExpiresIn | undefined = ExpiresIn | undefined,
  TEvent extends CompatEvent | H3Event = CompatEvent | H3Event,
>(event: TEvent, config: SessionConfigJWS<T, MaxAge, TEvent>): string | undefined {
  return defineJWSSession(config).token(event);
}

/**
 * Update the session data (if provided) and reissue the JWS; `options.maxAge` overrides this token's lifetime.
 * @deprecated Use `(await defineJWSSession(config).use(event)).update(update, options)`.
 */
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

/**
 * Sign the session as a compact JWS without writing a cookie; fresh `jti` if no ID, no token source needed.
 * @deprecated Use `defineJWSSession(config).issue(data)` to mint a token, or `(await defineJWSSession(config).use(event)).token` for the current one.
 */
export async function signJWSSession<
  T extends SessionRecord = SessionClaims,
  MaxAge extends ExpiresIn | undefined = ExpiresIn | undefined,
  TEvent extends CompatEvent | H3Event = CompatEvent | H3Event,
>(event: TEvent, config: SessionConfigJWS<T, MaxAge, TEvent>): Promise<string> {
  return encodeSession(bind(event, config));
}

/**
 * Verify a compact JWS into a session, checking `typ`, pinned `alg`, `jti`/`iat` and `exp` (required with `maxAge`).
 * @deprecated Use `defineJWSSession(config).open(token)`.
 */
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
    token: token,
    args: { event },
  });
}

/**
 * Drop the session cookie and leave an empty session for the rest of the request.
 * @deprecated Use `(await defineJWSSession(config).use(event)).clear()`.
 */
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
    driver: h3SessionDriver,
    hookArgs,
    codec,
    actions: sessionActions(),
  });
}
