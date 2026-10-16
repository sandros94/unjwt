import { type H3Event, type H3EventContext, isEvent } from "h3v1";
import { parse as parseCookies } from "cookie-es";
import {
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

/** Event shapes the adapter reads from: an h3 v1 event, or any request-like object. */
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

/** Whether the response can still take a `Set-Cookie`: an h3 event whose headers are unsent. */
export function hasWritableResponse(event: H3Event | CompatEvent): boolean {
  if (!isEvent(event)) return false;
  const { res } = event.node;
  return !res.headersSent && !res.writableEnded;
}

/** Read the session token: a cookie just set on the response, the request cookie, then the session header. */
export function readSessionToken(
  event: H3Event | CompatEvent,
  sessionName: string,
  source: SessionTokenSource,
): string | undefined {
  return resolveSessionToken(source, sessionName, {
    written: (name) => readChunkedFromSetCookie(getResponseSetCookie(event), name),
    cookie: (name) => readChunkedFrom(getRequestCookies(event), name),
    header: (name) => getRequestHeader(event, name),
  });
}

function cookieEvent(event: H3Event | CompatEvent): H3Event {
  // oxlint-disable-next-line typescript/no-unsafe-type-assertion -- `writable` held, so this is an H3Event
  return event as H3Event;
}

function getRequestHeader(event: H3Event | CompatEvent, name: string): string | undefined {
  if ("node" in event && event.node) {
    const value = event.node.req.headers[name];
    return Array.isArray(value) ? value[0] : value;
  }
  const headers =
    ("request" in event ? event.request?.headers : undefined) ??
    ("headers" in event ? event.headers : undefined);
  return headers?.get(name) ?? undefined;
}

function getRequestCookies(event: H3Event | CompatEvent): Record<string, string | undefined> {
  const header = getRequestHeader(event, "cookie");
  return header ? parseCookies(header) : Object.create(null);
}

function getResponseSetCookie(event: H3Event | CompatEvent): string[] {
  if ("node" in event && event.node) return responseSetCookies(event);
  const response: unknown = "response" in event ? event.response : undefined;
  return hasHeaders(response) ? response.headers.getSetCookie() : [];
}

function hasHeaders(response: unknown): response is { headers: Headers } {
  return (
    typeof response === "object" &&
    response !== null &&
    "headers" in response &&
    Boolean(response.headers)
  );
}
