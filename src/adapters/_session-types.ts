import type { JWTClaims, ExpiresIn } from "../core/types";
import type { StrictOmit } from "../core/utils/types";
import type { SessionIssueOptions } from "./_session";

export interface SessionClaims
  extends Required<Pick<JWTClaims, "jti" | "iat">>, StrictOmit<JWTClaims, "jti" | "iat"> {}

/**
 * Session data — everything but the claims the adapter owns. `jti`, `iat`,
 * `exp` and `nbf` are minted on every issue and never read from session data.
 */
export type SessionData<T extends Record<string, any> = SessionClaims> = StrictOmit<
  T,
  "jti" | "iat" | "exp" | "nbf"
>;

export type SessionUpdate<T extends Record<string, any> = SessionClaims> =
  | Partial<SessionData<T>>
  | ((oldData: SessionData<T>) => Partial<SessionData<T>> | undefined);

export interface SessionManager<
  T extends Record<string, any> = SessionClaims,
  ConfigMaxAge extends ExpiresIn | undefined = ExpiresIn | undefined,
> {
  readonly id: string | undefined;
  readonly createdAt: number;
  /** Expiry in ms — always a number when the session has a `maxAge`. */
  readonly expiresAt: ConfigMaxAge extends ExpiresIn ? number : number | undefined;
  readonly data: SessionData<T>;
  readonly token: string | undefined;
  /**
   * Issue a new token, merging `update` into the session data first. Pass
   * `options.maxAge` to give this one token a lifetime of its own.
   */
  update: (
    update?: SessionUpdate<T>,
    options?: SessionIssueOptions,
  ) => Promise<SessionManager<T, ConfigMaxAge>>;
  clear: () => Promise<SessionManager<T, ConfigMaxAge>>;
}

/**
 * The lifecycle hooks every session exposes. `TCarrier` names the request the
 * session belongs to the way its framework does — `{ event }` for h3,
 * `{ context }` for Elysia — and is carried by every hook argument.
 *
 * `onRead`, `onExpire` and `onError` are mutually exclusive per incoming token:
 * `onRead` fires only when a session was established from it.
 */
export interface SessionHooks<TSession, TCarrier extends Record<string, unknown>, TConfig> {
  /**
   * Fires when an incoming token was opened and the session established. May
   * fire more than once per request when the session is created concurrently
   * in the same handler — dedupe via `session.id` if needed.
   */
  onRead?: (
    args: TCarrier & { session: TSession & { id: string; token: string }; config: TConfig },
  ) => void | Promise<void>;
  /** Fires after a new token was issued — including pure token refreshes (update with no data). */
  onUpdate?: (
    args: TCarrier & {
      /** Session after the update. */
      session: TSession & { id: string; token: string };
      /** Deep-copied snapshot of the session before the update. */
      oldSession: TSession;
      config: TConfig;
    },
  ) => void | Promise<void>;
  /** Fires when the session is cleared. */
  onClear?: (
    args: TCarrier & {
      /** Last known session before clearing, if any. */
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
      /** The session involved in the error. */
      session: TSession;
      error: any;
      config: TConfig;
    },
  ) => void | Promise<void>;
}
