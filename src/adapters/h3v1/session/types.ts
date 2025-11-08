import type { JWTClaims, ExpiresIn } from "../../../core/types";

export type { JWTClaims } from "../../../core/types";
export type SessionData<T extends JWTClaims = JWTClaims> = Omit<
  T,
  "jti" | "iat" | "exp"
>;

export type SessionUpdate<T extends JWTClaims = JWTClaims> =
  | Partial<SessionData<T>>
  | ((oldData: SessionData<T>) => Partial<SessionData<T>> | undefined);

export interface SessionManager<
  T extends JWTClaims = JWTClaims,
  ConfigMaxAge extends ExpiresIn | undefined = number | undefined,
> {
  readonly id: string | undefined;
  readonly createdAt: number;
  readonly expiresAt: ConfigMaxAge extends ExpiresIn ? number : T["exp"];
  readonly data: SessionData<T>;
  update: (update: SessionUpdate<T>) => Promise<SessionManager<T>>;
  clear: () => Promise<SessionManager<T>>;
}
