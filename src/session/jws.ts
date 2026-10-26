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

export type { JWSSessionKey } from "./_internal/codec-jws-keys.ts";
export type { SessionSignOptions, SessionVerifyOptions } from "./_internal/codec-jws.ts";

/** Session state for the current request, from the claims of its JWS token. */
export interface SessionJWS<
  T extends SessionRecord = SessionClaims,
  MaxAge extends ExpiresIn | undefined = ExpiresIn | undefined,
> extends SessionState<T, MaxAge> {}

/** JWS session hooks. `onRead`, `onExpire` and `onError` are mutually exclusive per token. */
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

/** Configuration of a JWS session, signed but not encrypted. */
export interface SessionConfigJWS<
  T extends SessionRecord = SessionClaims,
  MaxAge extends ExpiresIn | undefined = ExpiresIn | undefined,
  TEvent = WebSessionEvent,
> extends JWSSessionConfig<MaxAge, CookieAttributes> {
  /** Cookie name, also the base of the default session header `x-unjwt-jws-session`. A trailing `.<digits>` throws `ERR_SESSION_CONFIG_INVALID`. @default "__Host-unjwt-jws" */
  name?: string;
  /** Lifecycle hooks and `onVerifyKeyLookup`. */
  hooks?: SessionHooksJWS<T, MaxAge, TEvent>;
}

/**
 * Defines a JWS session once: signed, not encrypted, so clients can read its data. `use`, `token`, `issue` and `open` serve every request.
 * @throws `ERR_SESSION_CONFIG_INVALID` if `name`, `sessionHeader`, a `__Host-` or `__Secure-` cookie's attributes or `rolling` is invalid, or a key that names no algorithm (a `CryptoKey`, an `oct` JWK without `alg`) lacks a pinned `jws.signOptions.alg`, or `jws.verifyOptions.algorithms` is empty, lists one no key serves, or names none a key without `alg` serves.
 * @throws `ERR_SESSION_KEY_INVALID` if `key` is missing, a string, not a symmetric JWK, a key pair or a `CryptoKey`, or cannot serve the pinned `alg`.
 * @throws `ERR_INVALID_OPTION` if `rolling` is neither `true` nor a duration.
 */
export function defineJWSSession<
  T extends SessionRecord = SessionClaims,
  MaxAge extends ExpiresIn | undefined = ExpiresIn | undefined,
  TEvent extends WebSessionEvent = WebSessionEvent,
>(config: SessionConfigJWS<T, MaxAge, TEvent>): SessionDefinition<T, MaxAge, TEvent>;
/**
 * Defines a JWS session over a framework driver of your own, passed as `{ driver }`.
 * @throws `ERR_SESSION_CONFIG_INVALID` if `name`, `sessionHeader`, a `__Host-` or `__Secure-` cookie's attributes or `rolling` is invalid, or a key that names no algorithm (a `CryptoKey`, an `oct` JWK without `alg`) lacks a pinned `jws.signOptions.alg`, or `jws.verifyOptions.algorithms` is empty, lists one no key serves, or names none a key without `alg` serves.
 * @throws `ERR_SESSION_KEY_INVALID` if `key` is missing, a string, not a symmetric JWK, a key pair or a `CryptoKey`, or cannot serve the pinned `alg`.
 * @throws `ERR_INVALID_OPTION` if `rolling` is neither `true` nor a duration.
 */
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
    codec: createJWSCodec({ prefix: driver.prefix, defaultName: "__Host-unjwt-jws" }),
  });
}
