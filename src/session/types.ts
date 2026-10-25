import type { ExpiresIn, JWTClaims } from "../core/types/index.ts";
import type { StrictOmit } from "../core/utils/types.ts";

/** Session data shape; `any` values let an `interface` (no index signature) satisfy it. */
// oxlint-disable-next-line typescript/no-explicit-any -- an interface has no implicit index signature
export type SessionRecord = Record<string, any>;

export interface SessionClaims
  extends Required<Pick<JWTClaims, "jti" | "iat">>, StrictOmit<JWTClaims, "jti" | "iat"> {}

/** Session data without the adapter-owned `jti`, `iat`, `exp` and `nbf`. */
export type SessionData<T extends SessionRecord = SessionClaims> = StrictOmit<
  T,
  "jti" | "iat" | "exp" | "nbf"
>;

/** Why `onUpdate` fired: an `update()` call, or `rolling` reissuing a session that was read. */
export type SessionUpdateTrigger = "update" | "rolling";

export type SessionUpdate<T extends SessionRecord = SessionClaims> =
  | Partial<SessionData<T>>
  | ((oldData: SessionData<T>) => Partial<SessionData<T>> | undefined);

export interface SessionManager<
  T extends SessionRecord = SessionClaims,
  ConfigMaxAge extends ExpiresIn | undefined = ExpiresIn | undefined,
> {
  readonly id: string | undefined;
  readonly createdAt: number;
  /** Expiry in ms: `exp`, or `iat + maxAge` when sooner; always a number when the session has a `maxAge`. */
  readonly expiresAt: ConfigMaxAge extends ExpiresIn ? number : number | undefined;
  readonly data: SessionData<T>;
  readonly token: string | undefined;
  /**
   * Issues a new token after merging `update`; `options.maxAge` overrides this token's lifetime.
   * Later reads see the data's JSON round trip. Rolls back if issuing or the cookie write fails;
   * a throwing `onUpdate` rejects but keeps the new session.
   */
  update: (
    update?: SessionUpdate<T>,
    options?: SessionIssueOptions,
  ) => Promise<SessionManager<T, ConfigMaxAge>>;
  clear: () => Promise<SessionManager<T, ConfigMaxAge>>;
}

/** The config members every session shares, whether it signs or seals its token. */
export interface SessionBaseConfig<MaxAge extends ExpiresIn | undefined = ExpiresIn | undefined> {
  /** Sets `exp = iat + maxAge`, requires `exp` on incoming tokens and ends them at `iat + maxAge` at the latest, drives cookie expiry; unset never expires. */
  maxAge?: MaxAge;
  /**
   * Reissue the session when it is read, needs `maxAge`.
   *
   * - `true`: every read reissues.
   * - a duration: a read reissues once the token is at least that old, so an active session is
   *   re-signed at most once per duration. With `maxAge: "1h"` and `rolling: "15m"`, reads in the
   *   first 15 minutes change nothing; the first read after that issues a fresh hour. Must be
   *   shorter than `maxAge`.
   *
   * A read that cannot write (a read-only event, a response already sent) does not reissue;
   * the next request, carrying the same token, does.
   *
   * @default undefined — the session expires at `iat + maxAge` however often it is read.
   */
  rolling?: true | ExpiresIn;
  /** Drives the cookie name and default header; prefer `__Host-`; a trailing `.<digits>` is refused. */
  name?: string;
  /**
   * Header carrying a bare or `Bearer` token: a header name, `true` for `x-<name>-session` (cookie prefix stripped), or `false` for none.
   * A request that carries it is read from it and never from the cookie, and writes no cookie back; any other value is a token failure (`onError`).
   * Left unset, a session with cookies still reads `x-<name>-session`, and so does one with `cookie: false`.
   */
  sessionHeader?: boolean | string;
  /** Session ID (`jti`) generator. Default `crypto.randomUUID`. */
  generateId?: () => string;
}

/**
 * Lifecycle hooks; `onRead`, `onExpire` and `onError` are mutually exclusive per incoming token.
 * `session` is the live manager, so a hook can `update()` or `clear()` in place; `oldSession` is a snapshot.
 */
export interface SessionHooks<TSession, TManager, TArgs extends Record<string, unknown>, TConfig> {
  /** Fires once per request, when the session is read from its token. */
  onRead?: (
    args: TArgs & { session: TManager & { id: string; token: string }; config: TConfig },
  ) => void | Promise<void>;
  /** Fires after a token is issued and, on a cookie session, its cookie written, by `update()` or by `rolling`; a throw rejects without rollback. */
  onUpdate?: (
    args: TArgs & {
      session: TManager & { id: string; token: string };
      /** Deep-copied snapshot of the session before the update. */
      oldSession: TSession;
      trigger: SessionUpdateTrigger;
      config: TConfig;
    },
  ) => void | Promise<void>;
  /** Fires when the session is cleared. */
  onClear?: (
    args: TArgs & {
      oldSession: TSession | undefined;
      config: TConfig;
    },
  ) => void | Promise<void>;
  /** Fires when the incoming token is expired. Receives the expired token's decoded claims. */
  onExpire?: (
    args: TArgs & {
      session: {
        id: string | undefined;
        createdAt: number | undefined;
        expiresAt: number | undefined;
        token: string;
      };
      error: Error;
      config: TConfig;
    },
  ) => void | Promise<void>;
  /** Fires on read-path failures other than expiry, and on write-path issue failures. */
  onError?: (
    args: TArgs & {
      session: TManager;
      // oxlint-disable-next-line typescript/no-explicit-any -- a write-path failure is whatever the cookie write or token issue threw
      error: any;
      config: TConfig;
    },
  ) => void | Promise<void>;
}

/** Per-issue overrides for a single `update()` call. */
export interface SessionIssueOptions {
  /** Lifetime for this issue only, overriding the config's `maxAge`; a read under that `maxAge` still ends the session at `iat + maxAge`. */
  maxAge?: ExpiresIn;
}

/** In-request session state, mirroring the claims of the underlying token. */
export interface SessionState<T extends SessionRecord, MaxAge extends ExpiresIn | undefined> {
  /** JWT `jti`; `undefined` until the session is persisted. */
  id: string | undefined;
  /** In ms; mirrors the JWT `iat` claim (seconds). */
  createdAt: number;
  /** In ms; mirrors the JWT `exp` claim (seconds), or `iat + maxAge` when sooner. */
  expiresAt: MaxAge extends ExpiresIn ? number : number | undefined;
  data: SessionData<T>;
  token: string | undefined;
}

/** Session state read back from a token: always carries its `id` and `createdAt`. */
export type OpenedSessionState<
  T extends SessionRecord,
  MaxAge extends ExpiresIn | undefined,
> = Pick<SessionState<T, MaxAge>, "id" | "createdAt" | "expiresAt" | "data"> & {
  id: string;
  createdAt: number;
};

/** One session, defined once from its config and used on any request. */
export interface SessionDefinition<
  T extends SessionRecord = SessionClaims,
  MaxAge extends ExpiresIn | undefined = ExpiresIn | undefined,
  TEvent = unknown,
> {
  /** Reads the request's session once and returns its manager; later calls on the same request share that state. */
  use: (event: TEvent) => Promise<SessionManager<T, MaxAge>>;
  /** The session's token once `use()` read or wrote it, else the one the request carries (the session header before the cookie), unopened. */
  token: (event: TEvent) => string | undefined;
  /** Mints a token for `data` with a fresh `jti` and `iat`, and `exp` from `maxAge` (`options.maxAge` overrides it); reads and writes nothing. */
  issue: (data?: Partial<SessionData<T>>, options?: SessionIssueOptions) => Promise<string>;
  /** Opens a token into session state, checking `typ`, pinned algorithms, `jti`/`iat` and `exp` when `maxAge` is set; the key-lookup hook receives no request. */
  open: (token: string) => Promise<OpenedSessionState<T, MaxAge>>;
}

interface SessionRequestBase {
  /**
   * The response being prepared; without it the session is read-only.
   * With `errHeaders` too (h3 v2, which sends only those for a thrown handler), every cookie write lands in both.
   */
  readonly res?: { readonly headers: Headers; readonly errHeaders?: Headers };
  /** Per-request state shared with the framework, where `sessions` is kept; without it state is keyed on `req`, else on this object. */
  readonly context?: Record<string, unknown>;
}

/** A request event: by its `Request`, or by its `Headers` (a `Request` itself, a WebSocket upgrade's request). */
export type SessionRequestEvent = SessionRequestBase &
  (
    | { readonly req: Request; readonly headers?: Headers }
    | { readonly headers: Headers; readonly req?: Request }
  );

/** A token handed in directly; sending a re-issued one is the caller's job. */
export interface SessionHandedToken {
  token: string | undefined;
}

/** What the Web session driver takes: a request event, or a token in hand. */
export type WebSessionEvent = SessionRequestEvent | SessionHandedToken;
