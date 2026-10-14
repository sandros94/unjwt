import type { JWTClaims, ExpiresIn } from "../core/types";
import type { StrictOmit } from "../core/utils/types";
import type { SessionIssueOptions } from "./_session";

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
  /** Drives the cookie name and default header; prefer `__Host-`; a trailing `.<digits>` is refused. */
  name?: string;
  /** Header carrying a bare or `Bearer` token, or `false`. Default `x-<name>-session` (cookie prefix stripped). */
  sessionHeader?: false | string;
  /** Session ID (`jti`) generator. Default `crypto.randomUUID`. */
  generateId?: () => string;
}

/** Lifecycle hooks; `onRead`, `onExpire` and `onError` are mutually exclusive per incoming token. */
export interface SessionHooks<TSession, TCarrier extends Record<string, unknown>, TConfig> {
  /** Fires on every read of a session holding a token, repeats within a request included; dedupe via `session.id`. */
  onRead?: (
    args: TCarrier & { session: TSession & { id: string; token: string }; config: TConfig },
  ) => void | Promise<void>;
  /** Fires after a token is issued and its cookie written; a throw rejects `update()` without rollback. */
  onUpdate?: (
    args: TCarrier & {
      session: TSession & { id: string; token: string };
      /** Deep-copied snapshot of the session before the update. */
      oldSession: TSession;
      config: TConfig;
    },
  ) => void | Promise<void>;
  /** Fires when the session is cleared. */
  onClear?: (
    args: TCarrier & {
      oldSession: TSession | undefined;
      config: TConfig;
    },
  ) => void | Promise<void>;
  /** Fires when the incoming token is expired. Receives the expired token's decoded claims. */
  onExpire?: (
    args: TCarrier & {
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
    args: TCarrier & {
      session: TSession;
      // oxlint-disable-next-line typescript/no-explicit-any -- a write-path failure is whatever the cookie write or token issue threw
      error: any;
      config: TConfig;
    },
  ) => void | Promise<void>;
}
