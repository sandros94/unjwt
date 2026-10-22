import {
  type H3Event,
  type H3EventContext,
  getCookie,
  getRequestHeader,
  isEvent,
  setCookie,
} from "h3v1";
import { parse as parseCookies } from "cookie-es";
import { setCookieValues } from "../../../session/_chunked-cookie.ts";
import type { CookieJar, SessionDriver } from "../../../session/_driver.ts";
import { type CookieSerializeOptions, responseSetCookies } from "../_cookie.ts";

/** Message prefix for every error the h3 adapters emit. */
export const PREFIX = "[unjwt/h3]";

/**
 * Event shapes the adapter reads from in websockets.
 * @deprecated `unjwt/adapters/h3v1` is removed in 0.9.0. Nuxt 4.6+ runs sessions through `unjwt/session` with handlers from `nuxt/server`; h3 v2, Nuxt 5 and Nitro 3 through `unjwt/adapters/h3`.
 */
export type CompatEvent =
  | { request: { headers: Headers }; context: H3EventContext }
  | { headers: Headers; context: H3EventContext };

/** The h3 v1 session driver: event-context state, request headers, the response's cookies. */
export const h3SessionDriver: SessionDriver<CompatEvent | H3Event> = {
  prefix: PREFIX,

  state: (event) => (event.context.sessions ||= Object.create(null)),

  header: (event, name) =>
    isEvent(event) ? requestHeader(event, name) : compatHeaders(event).get(name),

  cookies: (event) => (isEvent(event) ? eventJar(event) : compatJar(event)),

  /** As in h3 v1's own `useSession`: an event writes until its response is handled. */
  writable: (event) => !isEvent(event) || !event.handled,
};

function eventJar(event: H3Event): CookieJar<CookieSerializeOptions> {
  return {
    read: (name) => getCookie(event, name),
    written: (name) => setCookieValues(responseSetCookies(event))[name],
    write: (name, value, attrs) => {
      setCookie(event, name, value, attrs);
    },
  };
}

function compatJar(event: CompatEvent): CookieJar {
  let cookies: Record<string, string | undefined> | undefined;
  return { read: (name) => (cookies ||= compatCookies(event))[name] };
}

function requestHeader(event: H3Event, name: string): string | undefined {
  const value = getRequestHeader(event, name);
  return Array.isArray(value) ? value[0] : value;
}

function compatHeaders(event: CompatEvent): Headers {
  return "request" in event ? event.request.headers : event.headers;
}

function compatCookies(event: CompatEvent): Record<string, string | undefined> {
  const header = compatHeaders(event).get("cookie");
  return header ? parseCookies(header) : Object.create(null);
}
