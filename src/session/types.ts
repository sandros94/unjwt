import type { ExpiresIn, JWTClaims } from "../core/types/index.ts";
import type { StrictOmit } from "../utils/types.ts";
import type { JWTError } from "../error.ts";

/** The shape session data must match. Its `any` values let an `interface` without an index signature match it. */
// oxlint-disable-next-line typescript/no-explicit-any -- an interface has no implicit index signature
export type SessionRecord = Record<string, any>;

/** The default session data: JWT claims, with `jti` and `iat` always set. */
export interface SessionClaims
  extends Required<Pick<JWTClaims, "jti" | "iat">>, StrictOmit<JWTClaims, "jti" | "iat"> {}

/** Session data without `jti`, `iat`, `exp` and `nbf`, which the session sets on every issue. */
export type SessionData<T extends SessionRecord = SessionClaims> = StrictOmit<
  T,
  "jti" | "iat" | "exp" | "nbf"
>;

/**
 * Where the session's token comes from on this request, decided before it is opened:
 * - `"cookie"`: the session cookie, also when the session header holds the very token of that cookie.
 * - `"header"`: the session header, when it holds any other token or the session has no cookie.
 * - `"token"`: a token in hand (`{ token }`), or a token passed to `open()`.
 */
export type SessionSource = "cookie" | "header" | "token";

/** Why `onUpdate` ran: an `update()` call, or `rolling` reissuing a session that was read. */
export type SessionUpdateTrigger = "update" | "rolling";

/** What `update()` merges: a partial data object, or a function of the current data that returns one or `undefined`. */
export type SessionUpdate<T extends SessionRecord = SessionClaims> =
  | Partial<SessionData<T>>
  | ((oldData: SessionData<T>) => Partial<SessionData<T>> | undefined);

/** The session of one request. Its getters read the current state of that request. */
export interface SessionManager<
  T extends SessionRecord = SessionClaims,
  ConfigMaxAge extends ExpiresIn | undefined = ExpiresIn | undefined,
> {
  /** Session ID (`jti`), `undefined` until a token is read or issued. */
  readonly id: string | undefined;
  /** Issue time in ms, from `iat`. A session without a token holds the time it was created. */
  readonly createdAt: number;
  /** Expiry in ms: `exp`, or `iat + maxAge` when sooner. Always a number when the session has a `maxAge`. */
  readonly expiresAt: ConfigMaxAge extends ExpiresIn ? number : number | undefined;
  /** Session data, without `jti`, `iat`, `exp` and `nbf`. */
  readonly data: SessionData<T>;
  /**
   * The token read or issued on this request, `undefined` when there is none or it failed to open.
   * On a `"cookie"` session, a token `update()` issues is also written to the cookie. On a `"header"` or `"token"` session it is here alone, and reaches the client only if you send it.
   */
  readonly token: string | undefined;
  /**
   * Where the token of this request comes from, which decides what `update()` and `clear()` reach. It holds for the whole request.
   * - `"cookie"`: `update()` writes the new token to the cookie, and `clear()` expires it.
   * - `"header"` or `"token"`: `update()` re-mints onto `token` and writes nothing, and `clear()` empties the session for this request alone. The client keeps the token it sent, valid until it expires.
   */
  readonly source: SessionSource;
  /**
   * Merges `update` into the data and issues a token with a fresh `jti` and `iat`. `options.maxAge` overrides the config's `maxAge` for this token.
   * A `"cookie"` session writes the token to the response's cookie. A `"header"` or `"token"` session writes nothing: the token is on `token` alone, for you to send. Later requests read the data back through JSON.
   * If issuing or the cookie write fails, the session is restored, `onError` runs and the call rejects. A throwing `onUpdate` rejects the call and keeps the new session.
   * @throws `ERR_SESSION_READONLY_EVENT` if a `"cookie"` session has no response, or the response was already sent.
   * @throws `ERR_INVALID_OPTION` if the update is not a plain object or holds `__proto__`, `constructor` or `prototype`.
   * @throws `ERR_SESSION_CONFIG_INVALID` if a `"cookie"` session's token needs more than 16 cookie chunks.
   */
  update: (
    update?: SessionUpdate<T>,
    options?: SessionIssueOptions,
  ) => Promise<SessionManager<T, ConfigMaxAge>>;
  /**
   * Empties the session for the rest of the request and runs `onClear`.
   * A `"cookie"` session with a response expires its cookie. A `"header"` or `"token"` session writes nothing: the client keeps the token it sent, valid until it expires.
   * @throws `ERR_SESSION_READONLY_EVENT` if a `"cookie"` session's response was already sent.
   */
  clear: () => Promise<SessionManager<T, ConfigMaxAge>>;
}

/** The config members every session shares, whether it signs or encrypts its token. */
export interface SessionBaseConfig<MaxAge extends ExpiresIn | undefined = ExpiresIn | undefined> {
  /** Session lifetime: each token gets `exp = iat + maxAge` and its cookie expires then. An incoming token must have `exp` and ends at `exp` or `iat + maxAge`, whichever is sooner. @default undefined (never expires) */
  maxAge?: MaxAge;
  /**
   * Reissues a session read from its cookie. Requires `maxAge`.
   * - `true`: every read reissues.
   * - a duration, shorter than `maxAge`: a read reissues once the token is at least that old. With `maxAge: "1h"` and
   *   `rolling: "15m"`, reads in the first 15 minutes change nothing, and the first read after that issues a fresh hour.
   *
   * A read that cannot write the cookie (no response, or a response already sent) does not reissue. The next request, which sends the same token, does.
   * A session read from the session header or from a token in hand never reissues: its token stays the one the client sent.
   * @default undefined (the session expires at `iat + maxAge` however often it is read)
   */
  rolling?: true | ExpiresIn;
  /** Cookie name, also the base of the default session header. A valid cookie name without a trailing `.<digits>`. `__Host-` and `__Secure-` names get their prefix rules checked. */
  name?: string;
  /**
   * Request header to read a bare or `Bearer` token from: a header name, `true` for `x-<name>-session` (without a `__Host-` or `__Secure-` prefix), or `false` for none.
   * A request that sends it is read from it alone and its cookie is left as it is, unless the header holds the very token of the request's session cookie: that request is a cookie session.
   * A value that is not a token runs `onError`.
   * With no header read and `cookie: false`, the session has no token source and reading it throws `ERR_SESSION_CONFIG_INVALID`. @default undefined (no header is read)
   */
  sessionHeader?: boolean | string;
  /** Session ID (`jti`) generator. @default crypto.randomUUID */
  generateId?: () => string;
}

/** Lifecycle hooks. `onRead`, `onExpire` and `onError` are mutually exclusive per token. `session` is the live manager, open to `update()` and `clear()`. `oldSession` is a snapshot. */
export interface SessionHooks<TSession, TManager, TArgs extends Record<string, unknown>, TConfig> {
  /** Runs once per request, after a token is read and verified. A throw empties the session and rejects the read. */
  onRead?: (
    args: TArgs & { session: TManager & { id: string; token: string }; config: TConfig },
  ) => void | Promise<void>;
  /** Runs after `update()` or `rolling` issues a token and, on a cookie session, writes its cookie. A throw rejects the call and keeps the new session. */
  onUpdate?: (
    args: TArgs & {
      session: TManager & { id: string; token: string };
      /** The session before the update, its data deep-copied. */
      oldSession: TSession;
      trigger: SessionUpdateTrigger;
      config: TConfig;
    },
  ) => void | Promise<void>;
  /** Runs when `clear()` empties the session. `oldSession` is `undefined` when the session had no `id` and no token. */
  onClear?: (
    args: TArgs & {
      oldSession: TSession | undefined;
      config: TConfig;
    },
  ) => void | Promise<void>;
  /** Runs when the incoming token is expired, with its decoded claims and the `ERR_JWT_EXPIRED` error. The session is empty after it. */
  onExpire?: (
    args: TArgs & {
      session: {
        id: string | undefined;
        createdAt: number | undefined;
        expiresAt: number | undefined;
        token: string;
        /** Where the expired token came from. */
        source: SessionSource;
      };
      error: JWTError;
      config: TConfig;
    },
  ) => void | Promise<void>;
  /** Runs when a token fails to open for a reason other than expiry (`ERR_SESSION_TOKEN_INVALID`), and when an issue or cookie write fails. */
  onError?: (
    args: TArgs & {
      session: TManager;
      // oxlint-disable-next-line typescript/no-explicit-any -- a write-path failure is whatever the cookie write or token issue threw
      error: any;
      config: TConfig;
    },
  ) => void | Promise<void>;
}

/** Overrides for one `update()` or `issue()` call. */
export interface SessionIssueOptions {
  /** Lifetime of this token, in place of the config's `maxAge`. A read under the config's `maxAge` still ends the session at `iat + maxAge`. */
  maxAge?: ExpiresIn;
}

/** Session state for the current request, from the claims of its token. */
export interface SessionState<T extends SessionRecord, MaxAge extends ExpiresIn | undefined> {
  /** Session ID (`jti`), `undefined` until a token is read or issued. */
  id: string | undefined;
  /** Issue time in ms, from the `iat` claim in seconds. */
  createdAt: number;
  /** Expiry in ms, from the `exp` claim in seconds, or `iat + maxAge` when sooner. */
  expiresAt: MaxAge extends ExpiresIn ? number : number | undefined;
  data: SessionData<T>;
  token: string | undefined;
  /** Where the token of this request comes from. */
  source: SessionSource;
}

/** Session state that `open()` reads from a token: `id` and `createdAt` are always set, and `source` is `"token"`. */
export type OpenedSessionState<
  T extends SessionRecord,
  MaxAge extends ExpiresIn | undefined,
> = Pick<SessionState<T, MaxAge>, "id" | "createdAt" | "expiresAt" | "data" | "source"> & {
  id: string;
  createdAt: number;
};

/** One session, defined once from its config and used on any request. */
export interface SessionDefinition<
  T extends SessionRecord = SessionClaims,
  MaxAge extends ExpiresIn | undefined = ExpiresIn | undefined,
  TEvent = WebSessionEvent,
> {
  /**
   * Reads the request's session and returns its manager. Later calls on the same request share that state.
   * @throws `ERR_SESSION_CONFIG_INVALID` if the session has no token source, or a session of the other family uses its name on this request.
   * @throws `ERR_SESSION_KEY_INVALID` if a configured key fails to import.
   */
  use: (event: TEvent) => Promise<SessionManager<T, MaxAge>>;
  /** Returns the token `use()` read or issued on this request, else the one the request carries, unopened: a handed token, the session header when it is present and differs from the cookie, otherwise the cookie. */
  token: (event: TEvent) => string | undefined;
  /** Returns a token for `data` with a fresh `jti` and `iat`, and `exp` from `maxAge` (`options.maxAge` overrides it). Reads and writes no request. @throws `ERR_INVALID_OPTION` if `data` is not a plain object or holds `__proto__`, `constructor` or `prototype`. */
  issue: (data?: Partial<SessionData<T>>, options?: SessionIssueOptions) => Promise<string>;
  /**
   * Opens a token into session state. Checks `typ`, the algorithms the keys serve, `jti`, `iat`, and `exp` when `maxAge` is set. The key lookup hook receives no event.
   * @throws `ERR_JWT_EXPIRED` if the token is expired.
   * @throws `ERR_SESSION_TOKEN_INVALID` if the token fails any other check.
   */
  open: (token: string) => Promise<OpenedSessionState<T, MaxAge>>;
}

interface SessionRequestBase {
  /** The response being prepared. Without it the session is read-only. Each cookie write is copied to `errHeaders` too: h3 sends only these for a thrown handler. */
  readonly res?: { readonly headers: Headers; readonly errHeaders?: Headers };
  /** Per-request state shared with the framework. Sessions are stored in its `sessions` member. Without it, state is keyed on `req`, else on the event. */
  readonly context?: Record<string, unknown>;
}

/** A request event, by its `Request` or by its `Headers` (a `Request` itself, a WebSocket upgrade request). `req` is read first. */
export type SessionRequestEvent = SessionRequestBase &
  (
    | { readonly req: Request; readonly headers?: Headers }
    | { readonly headers: Headers; readonly req?: Request }
  );

/** A token passed in directly. `update()` issues onto `session.token`, and sending it is the caller's job. */
export interface SessionHandedToken {
  token: string | undefined;
}

/** What the Web session driver accepts: a request event, or a token in hand. Any other shape throws `ERR_SESSION_CONFIG_INVALID`. */
export type WebSessionEvent = SessionRequestEvent | SessionHandedToken;
