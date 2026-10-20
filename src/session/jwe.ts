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
  SessionContext,
  SessionDefinition,
  SessionManager,
  SessionRecord,
  SessionState,
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
  TContext = SessionContext,
> extends JWESessionHooks<
  SessionJWE<T, MaxAge>,
  SessionManager<T, MaxAge>,
  { context: TContext },
  SessionConfigJWE<T, MaxAge, TContext>
> {}

/** Configuration for a JWE-backed (encrypted) session. */
export interface SessionConfigJWE<
  T extends SessionRecord = SessionClaims,
  MaxAge extends ExpiresIn | undefined = ExpiresIn | undefined,
  TContext = SessionContext,
> extends JWESessionConfig<MaxAge, CookieAttributes> {
  /** Cookie and session-header name. Default `"unjwt-jwe"`; a `.<digits>` suffix throws `ERR_SESSION_CONFIG_INVALID`. */
  name?: string;
  hooks?: SessionHooksJWE<T, MaxAge, TContext>;
}

/** Defines a JWE (encrypted) session once; `use`, `token`, `issue` and `open` serve every request. */
export function defineJWESession<
  T extends SessionRecord = SessionClaims,
  MaxAge extends ExpiresIn | undefined = ExpiresIn | undefined,
>(config: SessionConfigJWE<T, MaxAge>): SessionDefinition<SessionContext, T, MaxAge>;
/** Defines a JWE (encrypted) session over a framework driver of your own. */
export function defineJWESession<
  T extends SessionRecord = SessionClaims,
  MaxAge extends ExpiresIn | undefined = ExpiresIn | undefined,
  TContext = SessionContext,
>(
  config: SessionConfigJWE<T, MaxAge, TContext>,
  options: { driver: SessionDriver<TContext> },
): SessionDefinition<TContext, T, MaxAge>;
export function defineJWESession<T extends SessionRecord, MaxAge extends ExpiresIn | undefined>(
  config: JWECodecConfig,
  options?: { driver?: SessionDriver<unknown> },
): SessionDefinition<unknown, T, MaxAge> {
  const driver = options?.driver ?? webSessionDriver;
  return defineSession<T, MaxAge, unknown, JWECodecConfig>(config, {
    driver,
    hookArgs: (context) => ({ context }),
    codec: createJWECodec({ prefix: driver.prefix, defaultName: "unjwt-jwe" }),
  });
}
