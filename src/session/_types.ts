import type { JWTClaims, ExpiresIn } from "../core/types/index.ts";
import type { StrictOmit } from "../core/utils/types.ts";
import type { SessionIssueOptions } from "./_contract.ts";

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
  /** Expiry in ms — always a number when the session has a `maxAge`. */
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
  /** Sets `exp = iat + maxAge`, requires `exp` on incoming tokens, drives cookie expiry; unset never expires. */
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
   * A read that cannot write (a read-only context, a response already sent) does not reissue;
   * the next request, carrying the same token, does.
   *
   * @default undefined — the session expires at `iat + maxAge` however often it is read.
   */
  rolling?: true | ExpiresIn;
  /** Drives the cookie name and default header; prefer `__Host-`; a trailing `.<digits>` is refused. */
  name?: string;
  /**
   * Header carrying a bare or `Bearer` token: a header name, `true` for `x-<name>-session` (cookie prefix stripped), or `false` for none.
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
  /** Fires after a token is issued and its cookie written, by `update()` or by `rolling`; a throw rejects without rollback. */
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
