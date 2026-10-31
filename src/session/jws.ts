import type { ExpiresIn, JWKSet, JWSHeaderParameters, JWSVerifyJWK } from "../core/types/index.ts";
import {
  type JWSCodecConfig,
  type JWSSessionConfig,
  createJWSCodec,
} from "./_internal/codec-jws.ts";
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
> extends SessionHooks<
  SessionJWS<T, MaxAge>,
  SessionManager<T, MaxAge>,
  { event: TEvent },
  SessionConfigJWS<T, MaxAge, TEvent>
> {
  /** Returns the key that verifies an incoming token. See {@link JWSSessionKeyLookup}. */
  onKeyLookup?: JWSSessionKeyLookup<T, MaxAge, TEvent>;
}

/**
 * Returns the key that verifies an incoming token, picked from its protected header, by `kid` when keys rotate: an HMAC or public JWK, a
 * `CryptoKey` or a JWK Set, the shapes `key` takes for verification. Set, it replaces `key` for verification: the token's `alg` is still one
 * `key` serves or `verifyOptions.algorithms` lists. A `CryptoKey` it returns names no algorithm of its own: as for a lone `CryptoKey` key,
 * `verifyOptions.algorithms` or the pin names what it serves. A JWK Set offers the token its keys of the token's `kid` (all of them when it
 * names none) that serve its `alg`, in order, and a token offered more than `verifyOptions.limits.keyCandidates` keys is refused. Nothing
 * it returns is checked when the session is defined. `undefined` means no key for this token: the token fails with
 * `ERR_SESSION_TOKEN_INVALID`, an `ERR_JWK_KEY_NOT_FOUND` as its `cause`, and its cookie is expired. Any throw, a `JWTError` or not, means
 * the token could not be read: `ERR_SESSION_READ_FAILED`, the thrown error as its `cause`, and the cookie is kept. `open()` passes it no event.
 */
export type JWSSessionKeyLookup<
  T extends SessionRecord = SessionClaims,
  MaxAge extends ExpiresIn | undefined = ExpiresIn | undefined,
  TEvent = WebSessionEvent,
> = (lookup: {
  header: JWSHeaderParameters;
  config: SessionConfigJWS<T, MaxAge, TEvent>;
  event?: TEvent;
}) =>
  | JWSVerifyJWK
  | CryptoKey
  | JWKSet
  | undefined
  | Promise<JWSVerifyJWK | CryptoKey | JWKSet | undefined>;

/** Configuration of a JWS session, signed but not encrypted. */
export interface SessionConfigJWS<
  T extends SessionRecord = SessionClaims,
  MaxAge extends ExpiresIn | undefined = ExpiresIn | undefined,
  TEvent = WebSessionEvent,
> extends JWSSessionConfig<MaxAge, CookieAttributes> {
  /** Cookie name, also the base of the default session header `x-unjwt-jws-session`. A trailing `.<digits>` throws `ERR_SESSION_CONFIG_INVALID`. @default "__Host-unjwt-jws" */
  name?: string;
  /** Lifecycle hooks and `onKeyLookup`. */
  hooks?: SessionHooksJWS<T, MaxAge, TEvent>;
}

/**
 * Defines a JWS session once: signed, not encrypted, so clients can read its data. `use`, `token`, `issue` and `open` serve every request.
 * @throws `ERR_SESSION_CONFIG_INVALID` if `name`, `sessionHeader`, a `__Host-` or `__Secure-` cookie's attributes or `rolling` is invalid, or a key that names no algorithm (a `CryptoKey`, an `oct` JWK without `alg`, a pair when neither half names one) lacks a pinned `jws.signOptions.alg`, or `jws.verifyOptions.algorithms` is empty or lists one no key serves without `onKeyLookup`, or names none of those a `publicKey` entry without `alg` carries, or a token of a JWK Set `key` entry without `kid` meets more than `jws.verifyOptions.limits.keyCandidates` entries.
 * @throws `ERR_SESSION_KEY_INVALID` if `key` is missing, a string, a lone asymmetric key, not an HMAC `oct` JWK, a JWK Set of them, a secret `CryptoKey` or a key pair, an empty JWK Set or one holding a key that is not an `oct` JWK, a pair with a half that is not what it is named, serves no JWS algorithm, or cannot serve the pinned `alg` or, for a pair's half that names none, the one its other half names, or a pair whose single `publicKey` names another algorithm than the one it issues under, or whose `publicKey` list or JWK Set holds no key that serves it.
 * @throws `ERR_INVALID_OPTION` if `rolling` is neither `true` nor a duration.
 */
export function defineJWSSession<
  T extends SessionRecord = SessionClaims,
  MaxAge extends ExpiresIn | undefined = ExpiresIn | undefined,
  TEvent extends WebSessionEvent = WebSessionEvent,
>(config: SessionConfigJWS<T, MaxAge, TEvent>): SessionDefinition<T, MaxAge, TEvent>;
/**
 * Defines a JWS session over a framework driver of your own, passed as `{ driver }`.
 * @throws `ERR_SESSION_CONFIG_INVALID` if `name`, `sessionHeader`, a `__Host-` or `__Secure-` cookie's attributes or `rolling` is invalid, or a key that names no algorithm (a `CryptoKey`, an `oct` JWK without `alg`, a pair when neither half names one) lacks a pinned `jws.signOptions.alg`, or `jws.verifyOptions.algorithms` is empty or lists one no key serves without `onKeyLookup`, or names none of those a `publicKey` entry without `alg` carries, or a token of a JWK Set `key` entry without `kid` meets more than `jws.verifyOptions.limits.keyCandidates` entries.
 * @throws `ERR_SESSION_KEY_INVALID` if `key` is missing, a string, a lone asymmetric key, not an HMAC `oct` JWK, a JWK Set of them, a secret `CryptoKey` or a key pair, an empty JWK Set or one holding a key that is not an `oct` JWK, a pair with a half that is not what it is named, serves no JWS algorithm, or cannot serve the pinned `alg` or, for a pair's half that names none, the one its other half names, or a pair whose single `publicKey` names another algorithm than the one it issues under, or whose `publicKey` list or JWK Set holds no key that serves it.
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
