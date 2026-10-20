import type { ExpiresIn } from "../core/types/index.ts";
import {
  type JWSCodecConfig,
  type JWSSessionConfig,
  type JWSSessionHooks,
  createJWSCodec,
} from "./_codec-jws.ts";
import type { CookieAttributes } from "./_cookie-attributes.ts";
import type { SessionDriver } from "./_driver.ts";
import type {
  SessionClaims,
  SessionContext,
  SessionDefinition,
  SessionManager,
  SessionRecord,
  SessionState,
} from "./types.ts";
import { defineSession } from "./_definition.ts";
import { webSessionDriver } from "./_web-driver.ts";

export type { SessionSignOptions, SessionVerifyOptions } from "./_codec-jws.ts";

/** Session state for the current request, mirroring the claims of its JWS token. */
export interface SessionJWS<
  T extends SessionRecord = SessionClaims,
  MaxAge extends ExpiresIn | undefined = ExpiresIn | undefined,
> extends SessionState<T, MaxAge> {}

/** JWS session hooks; `onRead`, `onExpire` and `onError` are mutually exclusive per token. */
export interface SessionHooksJWS<
  T extends SessionRecord = SessionClaims,
  MaxAge extends ExpiresIn | undefined = ExpiresIn | undefined,
  TContext = SessionContext,
> extends JWSSessionHooks<
  SessionJWS<T, MaxAge>,
  SessionManager<T, MaxAge>,
  { context: TContext },
  SessionConfigJWS<T, MaxAge, TContext>
> {}

/** Configuration for a JWS-backed (signed, not encrypted) session. */
export interface SessionConfigJWS<
  T extends SessionRecord = SessionClaims,
  MaxAge extends ExpiresIn | undefined = ExpiresIn | undefined,
  TContext = SessionContext,
> extends JWSSessionConfig<MaxAge, CookieAttributes> {
  /** Cookie and session-header name. Default `"unjwt-jws"`; a `.<digits>` suffix throws `ERR_SESSION_CONFIG_INVALID`. */
  name?: string;
  hooks?: SessionHooksJWS<T, MaxAge, TContext>;
}

/** Defines a JWS (signed, not encrypted) session once, its data readable by clients; `use`, `token`, `issue` and `open` serve every request. */
export function defineJWSSession<
  T extends SessionRecord = SessionClaims,
  MaxAge extends ExpiresIn | undefined = ExpiresIn | undefined,
>(config: SessionConfigJWS<T, MaxAge>): SessionDefinition<SessionContext, T, MaxAge>;
/** Defines a JWS (signed, not encrypted) session over a framework driver of your own. */
export function defineJWSSession<
  T extends SessionRecord = SessionClaims,
  MaxAge extends ExpiresIn | undefined = ExpiresIn | undefined,
  TContext = SessionContext,
>(
  config: SessionConfigJWS<T, MaxAge, TContext>,
  options: { driver: SessionDriver<TContext> },
): SessionDefinition<TContext, T, MaxAge>;
export function defineJWSSession<T extends SessionRecord, MaxAge extends ExpiresIn | undefined>(
  config: JWSCodecConfig,
  options?: { driver?: SessionDriver<unknown> },
): SessionDefinition<unknown, T, MaxAge> {
  const driver = options?.driver ?? webSessionDriver;
  return defineSession<T, MaxAge, unknown, JWSCodecConfig>(config, {
    driver,
    hookArgs: (context) => ({ context }),
    codec: createJWSCodec({ prefix: driver.prefix, defaultName: "unjwt-jws" }),
  });
}
