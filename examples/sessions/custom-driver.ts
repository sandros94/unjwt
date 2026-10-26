import { generateJWK } from "unjwt/jwk";

// #region docs
import {
  type CookieAttributes,
  type CookieJar,
  type SessionDefinition,
  defineJWESession,
  defineSessionDriver,
} from "unjwt/session";

/** The event your framework hands each handler. */
export interface AppEvent {
  request: Request;
  /** Created for this request alone. */
  locals: { sessions?: Record<string, unknown> };
  /** `get` already sees what `set` wrote earlier in the same request. */
  cookies: {
    get(name: string): string | undefined;
    set(name: string, value: string, options: CookieAttributes): void;
  };
  /** `true` once the response has gone out. */
  sent: boolean;
}

const appDriver = defineSessionDriver<AppEvent>({
  prefix: "[app-session]",
  state: (event) => (event.locals.sessions ??= {}),
  header: (event, name) => event.request.headers.get(name),
  cookies: (event): CookieJar<CookieAttributes> => ({
    read: (name) => event.cookies.get(name),
    write: (name, value, attrs) => event.cookies.set(name, value, attrs),
  }),
  writable: (event) => !event.sent,
});

// #hide const key = the "oct" JWK from SESSION_KEY (see Configure a session)
const key = await generateJWK("A256GCM");
// #endhide

export const appSession: SessionDefinition<{ userId: string }, "7D", AppEvent> = defineJWESession(
  { key, maxAge: "7D" },
  { driver: appDriver },
);
// #endregion
