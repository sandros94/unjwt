import type { ExpiresIn, JWEDecryptJWK, JWEHeaderParameters, JWKSet } from "../core/types/index.ts";
import {
  type JWECodecConfig,
  type JWESessionConfig,
  createJWECodec,
} from "./_internal/codec-jwe.ts";
import type { CookieAttributes } from "./_internal/cookie-attributes.ts";
import type { SessionDriver } from "./_internal/driver.ts";
import type {
  SessionClaims,
  SessionDefinition,
  SessionHooks,
  SessionManager,
  SessionRecord,
  SessionState,
  WebSessionEvent,
} from "./types.ts";
import { defineSession } from "./_internal/definition.ts";
import { webSessionDriver } from "./_internal/web-driver.ts";

export type { JWESessionKey, JWESessionOctJWK } from "./_internal/codec-jwe-keys.ts";
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
> extends SessionHooks<
  SessionJWE<T, MaxAge>,
  SessionManager<T, MaxAge>,
  { event: TEvent },
  SessionConfigJWE<T, MaxAge, TEvent>
> {
  /** Returns the key that decrypts an incoming token. See {@link JWESessionKeyLookup}. */
  onKeyLookup?: JWESessionKeyLookup<T, MaxAge, TEvent>;
}

/**
 * Returns the key that decrypts an incoming token, picked from its protected header, by `kid` when keys rotate: an `oct` JWK, a
 * `CryptoKey` or a JWK Set, the shapes `key` takes for decryption. Set, it replaces `key` for decryption: the token's `alg` is still one
 * `key` serves or `decryptOptions.algorithms` lists. A `CryptoKey` it returns names no algorithm of its own: as for a lone `CryptoKey` key,
 * `decryptOptions.algorithms` or the pin names what it serves. A JWK Set offers the token its keys of the token's `kid` (all of them when it
 * names none) that serve its `alg`, in order, and a token offered more than `decryptOptions.limits.keyCandidates` keys is refused. Nothing
 * it returns is checked when the session is defined. `undefined` means no key for this token: the token fails with
 * `ERR_SESSION_TOKEN_INVALID`, an `ERR_JWK_KEY_NOT_FOUND` as its `cause`, and its cookie is expired. Any throw, a `JWTError` or not, means
 * the token could not be read: `ERR_SESSION_READ_FAILED`, the thrown error as its `cause`, and the cookie is kept. A key it returns that cannot
 * be used for the token's `alg` is the same read failure, an `ERR_JWK_INVALID` as its `cause`. `open()` passes it no event.
 */
export type JWESessionKeyLookup<
  T extends SessionRecord = SessionClaims,
  MaxAge extends ExpiresIn | undefined = ExpiresIn | undefined,
  TEvent = WebSessionEvent,
> = (lookup: {
  header: JWEHeaderParameters;
  config: SessionConfigJWE<T, MaxAge, TEvent>;
  event?: TEvent;
}) =>
  | JWEDecryptJWK
  | CryptoKey
  | JWKSet
  | undefined
  | Promise<JWEDecryptJWK | CryptoKey | JWKSet | undefined>;

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
 * @throws `ERR_SESSION_CONFIG_INVALID` if `name`, `sessionHeader`, a `__Host-` or `__Secure-` cookie's attributes or `rolling` is invalid, or a key that names no algorithm (a `CryptoKey`, an `oct` JWK without `alg`) lacks a pinned `jwe.encryptOptions.alg` and `enc`, or `jwe.decryptOptions.algorithms` is empty or lists one no key serves without `onKeyLookup`, or a token of a JWK Set `key` entry without `kid` meets more than `jwe.decryptOptions.limits.keyCandidates` entries.
 * @throws `ERR_SESSION_KEY_INVALID` if `key` is missing, a string, asymmetric, not an `oct` JWK, a JWK Set of them or a secret `CryptoKey`, an empty JWK Set or one holding a key that is not an `oct` JWK, serves no JWE algorithm, or cannot serve the pinned `alg` or `enc`.
 * @throws `ERR_INVALID_OPTION` if `rolling` is neither `true` nor a duration.
 */
export function defineJWESession<
  T extends SessionRecord = SessionClaims,
  MaxAge extends ExpiresIn | undefined = ExpiresIn | undefined,
  TEvent extends WebSessionEvent = WebSessionEvent,
>(config: SessionConfigJWE<T, MaxAge, TEvent>): SessionDefinition<T, MaxAge, TEvent>;
/**
 * Defines a JWE session over a framework driver of your own, passed as `{ driver }`.
 * @throws `ERR_SESSION_CONFIG_INVALID` if `name`, `sessionHeader`, a `__Host-` or `__Secure-` cookie's attributes or `rolling` is invalid, or a key that names no algorithm (a `CryptoKey`, an `oct` JWK without `alg`) lacks a pinned `jwe.encryptOptions.alg` and `enc`, or `jwe.decryptOptions.algorithms` is empty or lists one no key serves without `onKeyLookup`, or a token of a JWK Set `key` entry without `kid` meets more than `jwe.decryptOptions.limits.keyCandidates` entries.
 * @throws `ERR_SESSION_KEY_INVALID` if `key` is missing, a string, asymmetric, not an `oct` JWK, a JWK Set of them or a secret `CryptoKey`, an empty JWK Set or one holding a key that is not an `oct` JWK, serves no JWE algorithm, or cannot serve the pinned `alg` or `enc`.
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
