import type { ExpiresIn } from "../core/types/index.ts";
import {
  type JWSCodecConfig,
  type JWSSessionConfig,
  type JWSSessionHooks,
  createJWSCodec,
} from "./_internal/codec-jws.ts";
import type { CookieAttributes } from "./_internal/cookie-attributes.ts";
import type { SessionDriver } from "./_internal/driver.ts";
import type {
  SessionClaims,
  SessionDefinition,
  SessionManager,
  SessionRecord,
  SessionState,
  WebSessionEvent,
} from "./types.ts";
import { defineSession } from "./_internal/definition.ts";
import { webSessionDriver } from "./_internal/web-driver.ts";

export type { SessionSignOptions, SessionVerifyOptions } from "./_internal/codec-jws.ts";

/** Session state for the current request, mirroring the claims of its JWS token. */
export interface SessionJWS<
  T extends SessionRecord = SessionClaims,
  MaxAge extends ExpiresIn | undefined = ExpiresIn | undefined,
> extends SessionState<T, MaxAge> {}

/** JWS session hooks; `onRead`, `onExpire` and `onError` are mutually exclusive per token. */
export interface SessionHooksJWS<
  T extends SessionRecord = SessionClaims,
  MaxAge extends ExpiresIn | undefined = ExpiresIn | undefined,
  TEvent = WebSessionEvent,
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
  TEvent = WebSessionEvent,
> extends JWSSessionConfig<MaxAge, CookieAttributes> {
  /** Cookie and session-header name. Default `"__Host-unjwt-jws"` (header `x-unjwt-jws-session`); a `.<digits>` suffix throws `ERR_SESSION_CONFIG_INVALID`. */
  name?: string;
  hooks?: SessionHooksJWS<T, MaxAge, TEvent>;
}

/** Defines a JWS (signed, not encrypted) session once, its data readable by clients; `use`, `token`, `issue` and `open` serve every request. Throws at definition for a config it cannot use. */
export function defineJWSSession<
  T extends SessionRecord = SessionClaims,
  MaxAge extends ExpiresIn | undefined = ExpiresIn | undefined,
  TEvent extends WebSessionEvent = WebSessionEvent,
>(config: SessionConfigJWS<T, MaxAge, TEvent>): SessionDefinition<T, MaxAge, TEvent>;
/** Defines a JWS (signed, not encrypted) session over a framework driver of your own. Throws at definition for a config it cannot use. */
export function defineJWSSession<
  T extends SessionRecord = SessionClaims,
  MaxAge extends ExpiresIn | undefined = ExpiresIn | undefined,
  TEvent = WebSessionEvent,
>(
  config: SessionConfigJWS<T, MaxAge, TEvent>,
  options: { driver: SessionDriver<TEvent> },
): SessionDefinition<T, MaxAge, TEvent>;
export function defineJWSSession<T extends SessionRecord, MaxAge extends ExpiresIn | undefined>(
  config: JWSCodecConfig,
  options?: { driver?: SessionDriver<unknown> },
): SessionDefinition<T, MaxAge> {
  const driver = options?.driver ?? webSessionDriver;
  return defineSession<T, MaxAge, unknown, JWSCodecConfig>(config, {
    driver,
    hookArgs: (event) => ({ event }),
    codec: createJWSCodec({ prefix: driver.prefix, defaultName: "__Host-unjwt-jws" }),
  });
}
