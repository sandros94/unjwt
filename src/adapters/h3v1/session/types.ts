import type { JWTClaims, ExpiresIn } from "../../../core/types";
import type { StrictOmit } from "../../../core/utils/types";

export type { JWTClaims } from "../../../core/types";

export interface SessionClaims
  extends Required<Pick<JWTClaims, "jti" | "iat">>,
    StrictOmit<JWTClaims, "jti" | "iat"> {}

export type SessionData<T extends Record<string, any> = SessionClaims> =
  StrictOmit<T, "jti" | "iat" | "exp">;

export type SessionUpdate<T extends Record<string, any> = SessionClaims> =
  | Partial<SessionData<T>>
  | ((oldData: SessionData<T>) => Partial<SessionData<T>> | undefined);

export interface SessionManager<
  T extends Record<string, any> = SessionClaims,
  ConfigMaxAge extends ExpiresIn | undefined = ExpiresIn | undefined,
> {
  readonly id: string | undefined;
  readonly createdAt: number;
  readonly expiresAt: ConfigMaxAge extends ExpiresIn
    ? number
    : "exp" extends keyof T
      ? T["exp"]
      : number | undefined;
  readonly data: SessionData<T>;
  readonly token: string | undefined;
  update: (update: SessionUpdate<T>) => Promise<SessionManager<T>>;
  clear: () => Promise<SessionManager<T>>;
}
