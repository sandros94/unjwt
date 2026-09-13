import type { JWTClaims, ExpiresIn } from "../../../core/types";
import type { StrictOmit } from "../../../core/utils/types";
import type { SessionIssueOptions } from "../../_session";
import type { ChunkableCookieJar } from "../_cookie";

export type { SessionIssueOptions };

export interface SessionContext {
  cookie: ChunkableCookieJar;
  request: { headers: { get(name: string): string | null } };
}

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
