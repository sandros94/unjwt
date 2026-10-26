import type { ExpiresIn } from "../core/types/index.ts";
import {
  type JWECodecConfig,
  type JWESessionConfig,
  type JWESessionHooks,
  createJWECodec,
} from "./_internal/codec-jwe.ts";
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

export type {
  JWESessionKey,
  JWESessionOctJWK,
  JWESessionSecret,
} from "./_internal/codec-jwe-keys.ts";
export type { SessionDecryptOptions, SessionEncryptOptions } from "./_internal/codec-jwe.ts";

/** Session state for the current request, from the claims of its JWE token. */
export interface SessionJWE<
  T extends SessionRecord = SessionClaims,
  MaxAge extends ExpiresIn | undefined = ExpiresIn | undefined,
> extends SessionState<T, MaxAge> {}

/** JWE session hooks. `onRead`, `onExpire` and `onError` are mutually exclusive per token. */
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

/** Configuration of an encrypted JWE session. */
export interface SessionConfigJWE<
  T extends SessionRecord = SessionClaims,
  MaxAge extends ExpiresIn | undefined = ExpiresIn | undefined,
  TEvent = WebSessionEvent,
> extends JWESessionConfig<MaxAge, CookieAttributes> {
  /** Cookie name, also the base of the default session header `x-unjwt-jwe-session`. A trailing `.<digits>` throws `ERR_SESSION_CONFIG_INVALID`. @default "__Host-unjwt-jwe" */
  name?: string;
  /** Lifecycle hooks and `onKeyLookup`. */
  hooks?: SessionHooksJWE<T, MaxAge, TEvent>;
}

/**
 * Defines a JWE session once: encrypted, so clients cannot read its data. `use`, `token`, `issue` and `open` serve every request.
 * @throws `ERR_SESSION_CONFIG_INVALID` if `name`, `sessionHeader`, a `__Host-` or `__Secure-` cookie's attributes or `rolling` is invalid, or a key that names no algorithm (a `CryptoKey`, an `oct` JWK without `alg`) lacks a pinned `jwe.encryptOptions.alg` and `enc`, or `jwe.decryptOptions.algorithms` is empty, lists one no key serves, or names none a key without `alg` serves, or more keys without `kid` than `jwe.decryptOptions.limits.keyCandidates` decrypt.
 * @throws `ERR_SESSION_KEY_INVALID` if `key` is missing, a string, asymmetric, not an `oct` JWK, a secret `CryptoKey` or a `{ current, keys }` set, or cannot serve the pinned `alg` or `enc`.
 * @throws `ERR_INVALID_OPTION` if `rolling` is neither `true` nor a duration.
 */
export function defineJWESession<
  T extends SessionRecord = SessionClaims,
  MaxAge extends ExpiresIn | undefined = ExpiresIn | undefined,
  TEvent extends WebSessionEvent = WebSessionEvent,
>(config: SessionConfigJWE<T, MaxAge, TEvent>): SessionDefinition<T, MaxAge, TEvent>;
/**
 * Defines a JWE session over a framework driver of your own, passed as `{ driver }`.
 * @throws `ERR_SESSION_CONFIG_INVALID` if `name`, `sessionHeader`, a `__Host-` or `__Secure-` cookie's attributes or `rolling` is invalid, or a key that names no algorithm (a `CryptoKey`, an `oct` JWK without `alg`) lacks a pinned `jwe.encryptOptions.alg` and `enc`, or `jwe.decryptOptions.algorithms` is empty, lists one no key serves, or names none a key without `alg` serves, or more keys without `kid` than `jwe.decryptOptions.limits.keyCandidates` decrypt.
 * @throws `ERR_SESSION_KEY_INVALID` if `key` is missing, a string, asymmetric, not an `oct` JWK, a secret `CryptoKey` or a `{ current, keys }` set, or cannot serve the pinned `alg` or `enc`.
 * @throws `ERR_INVALID_OPTION` if `rolling` is neither `true` nor a duration.
 */
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
    codec: createJWECodec({ prefix: driver.prefix, defaultName: "__Host-unjwt-jwe" }),
  });
}
