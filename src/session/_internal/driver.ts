import type { ExpirableCookieAttributes } from "./chunked-cookie.ts";

/** The cookies of one request and its response, as a framework exposes them. */
export interface CookieJar<A extends ExpirableCookieAttributes = ExpirableCookieAttributes> {
  /** Returns the request's cookie `name`. */
  read(name: string): string | undefined;
  /** Returns the value this response already set for `name` (`""` once deleted). Implement it when the framework exposes response cookies. */
  written?(name: string): string | undefined;
  /** Sets a response cookie. Omit it when the event cannot send a `Set-Cookie` (a request without a response): a cookie session is then read-only. */
  write?(name: string, value: string, attrs: A): void;
}

/** What a framework driver implements. The session reads its token and writes its cookie through these members. */
export interface SessionDriver<TEvent> {
  /** Starts the message of every error the session throws. */
  prefix: string;
  /** Returns a record unique to the request, where session state and the name registry are stored. */
  state(event: TEvent): Record<string, unknown>;
  /** Returns a request header by lowercase name. */
  header(event: TEvent, name: string): string | null | undefined;
  /** Returns the cookie jar of the request and its response. */
  cookies(event: TEvent): CookieJar;
  /** Returns `false` once the response was sent (Node `headersSent`): `update()` and `clear()` then throw `ERR_SESSION_READONLY_EVENT`. Omitted, the response stays writable. */
  writable?(event: TEvent): boolean;
  /** Returns `{ token }` when the event holds the token itself. No cookie or header is read then, and the session's source is `"token"`. */
  handed?(event: TEvent): { token: string | undefined } | undefined;
}
