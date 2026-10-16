import type { H3Event } from "h3v1";

import type { ExpiresIn } from "../../../core/types";
import type { SessionIssueOptions } from "../../_session";
import {
  type JWECodecConfig,
  type JWESessionConfig,
  type JWESessionHooks,
  createJWECodec,
} from "../../_codec-jwe";
import { bindSession } from "../../_session-bind";
import { type SessionBinding, type SessionState, openSessionToken } from "../../_session-core";
import { type SessionDefinition, defineSession } from "../../_session-definition";
import { loadSession } from "../../_session-read";
import { dropSession, encodeSession, issueSession, sessionActions } from "../../_session-write";
import type { SessionRecord } from "../../_session-types";
import type { CookieSerializeOptions } from "../_cookie";
import type { SessionClaims, SessionUpdate, SessionManager } from "./types";
import { type CompatEvent, PREFIX, h3SessionDriver } from "./_shared";

export type { SessionDecryptOptions, SessionEncryptOptions } from "../../_codec-jwe";

const codec = createJWECodec({ prefix: PREFIX, defaultName: "h3-jwe" });
const hookArgs = (event: CompatEvent | H3Event) => ({ event });

/** Session state for the current request, mirroring the claims of its JWE token. */
export interface SessionJWE<
  T extends SessionRecord = SessionClaims,
  MaxAge extends ExpiresIn | undefined = ExpiresIn | undefined,
> extends SessionState<T, MaxAge> {}

/** JWE session hooks; `onRead`, `onExpire` and `onError` are mutually exclusive per token. */
export interface SessionHooksJWE<
  T extends SessionRecord = SessionClaims,
  MaxAge extends ExpiresIn | undefined = ExpiresIn | undefined,
  TEvent extends CompatEvent | H3Event = CompatEvent | H3Event,
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
  TEvent extends CompatEvent | H3Event = CompatEvent | H3Event,
> extends JWESessionConfig<MaxAge, CookieSerializeOptions> {
  /** Cookie and session-header name. Default `"h3-jwe"`; a `.<digits>` suffix throws `ERR_SESSION_CONFIG_INVALID`. */
  name?: string;
  hooks?: SessionHooksJWE<T, MaxAge, TEvent>;
}

/** Defines a JWE (encrypted) session once; its `use`, `token`, `issue` and `open` serve every request. */
export function defineJWESession<
  T extends SessionRecord = SessionClaims,
  MaxAge extends ExpiresIn | undefined = ExpiresIn | undefined,
  TEvent extends CompatEvent | H3Event = CompatEvent | H3Event,
>(config: SessionConfigJWE<T, MaxAge, TEvent>): SessionDefinition<TEvent, T, MaxAge> {
  return defineSession<T, MaxAge, CompatEvent | H3Event, JWECodecConfig>(config, {
    driver: h3SessionDriver,
    hookArgs,
    codec,
  });
}

/**
 * Create a JWE (encrypted) session manager for the request.
 * @deprecated Use `defineJWESession(config).use(event)`.
 */
export async function useJWESession<
  T extends SessionRecord = SessionClaims,
  MaxAge extends ExpiresIn | undefined = ExpiresIn | undefined,
  TEvent extends CompatEvent | H3Event = CompatEvent | H3Event,
>(event: TEvent, config: SessionConfigJWE<T, MaxAge, TEvent>): Promise<SessionManager<T, MaxAge>> {
  return defineJWESession(config).use(event);
}

/**
 * Get (and lazily initialize) the session for the current request.
 * @deprecated Use `defineJWESession(config).use(event)`; the manager exposes the same state.
 */
export async function getJWESession<
  T extends SessionRecord = SessionClaims,
  MaxAge extends ExpiresIn | undefined = ExpiresIn | undefined,
  TEvent extends CompatEvent | H3Event = CompatEvent | H3Event,
>(event: TEvent, config: SessionConfigJWE<T, MaxAge, TEvent>): Promise<SessionJWE<T, MaxAge>> {
  return loadSession<T, MaxAge, CompatEvent | H3Event, JWECodecConfig>(bind(event, config));
}

/**
 * Read the raw session token: cookie first, then the session header (default `x-<name>-session`, optional `Bearer`).
 * @deprecated Use `defineJWESession(config).token(event)`.
 */
export function getJWESessionToken<
  T extends SessionRecord = SessionClaims,
  MaxAge extends ExpiresIn | undefined = ExpiresIn | undefined,
  TEvent extends CompatEvent | H3Event = CompatEvent | H3Event,
>(event: TEvent, config: SessionConfigJWE<T, MaxAge, TEvent>): string | undefined {
  return defineJWESession(config).token(event);
}

/**
 * Update the session data (if provided) and reissue the JWE; `options.maxAge` overrides this token's lifetime.
 * @deprecated Use `(await defineJWESession(config).use(event)).update(update, options)`.
 */
export async function updateJWESession<
  T extends SessionRecord = SessionClaims,
  MaxAge extends ExpiresIn | undefined = ExpiresIn | undefined,
  TEvent extends CompatEvent | H3Event = CompatEvent | H3Event,
>(
  event: TEvent,
  config: SessionConfigJWE<T, MaxAge, TEvent>,
  update?: SessionUpdate<T>,
  options?: SessionIssueOptions,
): Promise<SessionJWE<T, MaxAge> & { id: string; token: string }> {
  return issueSession<T, MaxAge, CompatEvent | H3Event, JWECodecConfig>(
    bind(event, config),
    update,
    options,
  );
}

/**
 * Seal the session as a compact JWE without writing a cookie; fresh `jti` if no ID, no token source needed.
 * @deprecated Use `defineJWESession(config).issue(data)` to mint a token, or `(await defineJWESession(config).use(event)).token` for the current one.
 */
export async function sealJWESession<
  T extends SessionRecord = SessionClaims,
  MaxAge extends ExpiresIn | undefined = ExpiresIn | undefined,
  TEvent extends CompatEvent | H3Event = CompatEvent | H3Event,
>(event: TEvent, config: SessionConfigJWE<T, MaxAge, TEvent>): Promise<string> {
  return encodeSession(bind(event, config));
}

/**
 * Decrypt a compact JWE into a session, checking `typ`, pinned `alg`/`enc`, `jti`/`iat` and `exp` (required with `maxAge`).
 * @deprecated Use `defineJWESession(config).open(sealed)`.
 */
export async function unsealJWESession<
  T extends SessionRecord = SessionClaims,
  MaxAge extends ExpiresIn | undefined = ExpiresIn | undefined,
  TEvent extends CompatEvent | H3Event = CompatEvent | H3Event,
>(
  event: TEvent,
  config: SessionConfigJWE<T, MaxAge, TEvent>,
  sealed: string,
): Promise<Partial<SessionJWE<T, MaxAge>>> {
  return openSessionToken<T, MaxAge, JWECodecConfig>(codec, config, {
    token: sealed,
    args: { event },
  });
}

/**
 * Drop the session cookie and leave an empty session for the rest of the request.
 * @deprecated Use `(await defineJWESession(config).use(event)).clear()`.
 */
export async function clearJWESession<
  T extends SessionRecord = SessionClaims,
  MaxAge extends ExpiresIn | undefined = ExpiresIn | undefined,
  TEvent extends CompatEvent | H3Event = CompatEvent | H3Event,
>(event: TEvent, config: SessionConfigJWE<T, MaxAge, TEvent>): Promise<void> {
  return dropSession(bind(event, config));
}

function bind<
  T extends SessionRecord,
  MaxAge extends ExpiresIn | undefined,
  TEvent extends CompatEvent | H3Event,
>(
  event: TEvent,
  config: SessionConfigJWE<T, MaxAge, TEvent>,
): SessionBinding<CompatEvent | H3Event, JWECodecConfig> {
  return bindSession<CompatEvent | H3Event, JWECodecConfig>(event, config, {
    driver: h3SessionDriver,
    hookArgs,
    codec,
    actions: sessionActions(),
  });
}
