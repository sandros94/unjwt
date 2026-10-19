import { type H3Event, type H3EventContext, getCookie, getRequestHeader, isEvent } from "h3v1";
import { parse as parseCookies } from "cookie-es";
import {
  readChunkedBy,
  readChunkedFrom,
  readChunkedFromSetCookie,
  removeChunked,
  writeChunked,
} from "../../_chunked-cookie";
import { type SessionTokenSource, resolveSessionToken } from "../../_session";
import { type SessionPort, recordSlotStore } from "../../_session-core";
import { eventCookieStore, responseSetCookies } from "../_cookie";

export type { SessionTokenSource };

/** Message prefix for every error and warning the h3 adapters emit. */
export const PREFIX = "[unjwt/h3]";

/** Event shapes the adapter reads from in websockets. */
export type CompatEvent =
  | { request: { headers: Headers }; context: H3EventContext }
  | { headers: Headers; context: H3EventContext };

/** The h3 v1 session port: event-context state, request token, response cookies. */
export const h3SessionPort: SessionPort<CompatEvent | H3Event> = {
  prefix: PREFIX,

  carrier: (event) => ({ event }),

  /** Keyed by family and name, so a JWS and a JWE session sharing a `name` stay apart. */
  store: (event, slot) => recordSlotStore(() => getSessionsContext(event), slot),

  readToken: readSessionToken,

  scope: getSessionsContext,

  writable: hasWritableResponse,

  setCookie: (event, sessionName, token, { attrs, chunkMaxLength }) => {
    writeChunked(eventCookieStore(cookieEvent(event)), sessionName, token, {
      attrs,
      chunkMaxLength,
      prefix: PREFIX,
    });
  },

  deleteCookie: (event, sessionName, { attrs }) => {
    removeChunked(eventCookieStore(cookieEvent(event)), sessionName, { attrs });
  },
};

export function getSessionsContext(event: H3Event | CompatEvent): Record<string, unknown> {
  return (event.context.sessions ||= Object.create(null));
}

/** Whether the response can still take a `Set-Cookie`: an h3 event, as in h3 v1's own `useSession`, whose response is not yet handled. */
export function hasWritableResponse(event: H3Event | CompatEvent): event is H3Event {
  return isEvent(event) && !event.handled;
}

/** Read the session token: a cookie just set on the response, the request cookie, then the session header. */
export function readSessionToken(
  event: H3Event | CompatEvent,
  sessionName: string,
  source: SessionTokenSource,
): string | undefined {
  return resolveSessionToken(source, sessionName, {
    written: (name) =>
      isEvent(event) ? readChunkedFromSetCookie(responseSetCookies(event), name) : undefined,
    cookie: (name) =>
      isEvent(event)
        ? readChunkedBy((key) => getCookie(event, key), name)
        : readChunkedFrom(compatCookies(event), name),
    header: (name) =>
      isEvent(event) ? requestHeader(event, name) : compatHeaders(event).get(name),
  });
}

function cookieEvent(event: H3Event | CompatEvent): H3Event {
  // oxlint-disable-next-line typescript/no-unsafe-type-assertion -- `writable` held, so this is an H3Event
  return event as H3Event;
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
