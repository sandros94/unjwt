import type { ExpiresIn } from "../core/types/index.ts";
import {
  type JWECodecConfig,
  type JWESessionConfig,
  type JWESessionHooks,
  createJWECodec,
} from "./_codec-jwe.ts";
import type { CookieAttributes } from "./_cookie-attributes.ts";
import type { SessionDriver } from "./_driver.ts";
import type {
  SessionClaims,
  SessionDefinition,
  SessionManager,
  SessionRecord,
  SessionState,
  WebSessionEvent,
} from "./types.ts";
import { defineSession } from "./_definition.ts";
import { webSessionDriver } from "./_web-driver.ts";

export type { SessionDecryptOptions, SessionEncryptOptions } from "./_codec-jwe.ts";

/** Session state for the current request, mirroring the claims of its JWE token. */
export interface SessionJWE<
  T extends SessionRecord = SessionClaims,
  MaxAge extends ExpiresIn | undefined = ExpiresIn | undefined,
> extends SessionState<T, MaxAge> {}

/** JWE session hooks; `onRead`, `onExpire` and `onError` are mutually exclusive per token. */
export interface SessionHooksJWE<
  T extends SessionRecord = SessionClaims,
  MaxAge extends ExpiresIn | undefined = ExpiresIn | undefined,
  TEvent = WebSessionEvent,
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
  TEvent = WebSessionEvent,
> extends JWESessionConfig<MaxAge, CookieAttributes> {
  /** Cookie and session-header name. Default `"unjwt-jwe"`; a `.<digits>` suffix throws `ERR_SESSION_CONFIG_INVALID`. */
  name?: string;
  hooks?: SessionHooksJWE<T, MaxAge, TEvent>;
}

/** Defines a JWE (encrypted) session once; `use`, `token`, `issue` and `open` serve every request. */
export function defineJWESession<
  T extends SessionRecord = SessionClaims,
  MaxAge extends ExpiresIn | undefined = ExpiresIn | undefined,
  TEvent extends WebSessionEvent = WebSessionEvent,
>(config: SessionConfigJWE<T, MaxAge, TEvent>): SessionDefinition<T, MaxAge, TEvent>;
/** Defines a JWE (encrypted) session over a framework driver of your own. */
export function defineJWESession<
  T extends SessionRecord = SessionClaims,
  MaxAge extends ExpiresIn | undefined = ExpiresIn | undefined,
  TEvent = WebSessionEvent,
>(
  config: SessionConfigJWE<T, MaxAge, TEvent>,
  options: { driver: SessionDriver<TEvent> },
): SessionDefinition<T, MaxAge, TEvent>;
export function defineJWESession<T extends SessionRecord, MaxAge extends ExpiresIn | undefined>(
  config: JWECodecConfig,
  options?: { driver?: SessionDriver<unknown> },
): SessionDefinition<T, MaxAge> {
  const driver = options?.driver ?? webSessionDriver;
  return defineSession<T, MaxAge, unknown, JWECodecConfig>(config, {
    driver,
    hookArgs: (event) => ({ event }),
    codec: createJWECodec({ prefix: driver.prefix, defaultName: "unjwt-jwe" }),
  });
}
