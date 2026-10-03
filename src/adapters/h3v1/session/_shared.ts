import { type H3Event, type H3EventContext, isEvent } from "h3v1";
import { parse as parseCookies } from "cookie-esv1";
import { readChunkedFrom, readChunkedFromSetCookie } from "../../_chunked-cookie";
import {
  type SessionTokenSource,
  headerToken,
  pickToken,
  sessionCookieAttributes,
  sessionHeaderName,
} from "../../_session";
import type { SessionCookieOptions, SessionPort } from "../../_session-core";
import { setChunkedCookie, deleteChunkedCookie, responseSetCookies } from "../_cookie";

export type { SessionTokenSource };

/** Message prefix for every error and warning the h3 adapters emit. */
export const PREFIX = "[unjwt/h3]";

/** Event shapes the adapter reads from: an h3 v1 event, or any request-like object. */
export type CompatEvent =
  | { request: { headers: Headers }; context: H3EventContext }
  | { headers: Headers; context: H3EventContext };

/**
 * The h3 v1 side of a session: the event context it lives in, the request it
 * reads its token from, and the response it writes its cookie to.
 */
export const h3SessionPort: SessionPort<CompatEvent | H3Event> = {
  prefix: PREFIX,

  carrier: (event) => ({ event }),

  /**
   * Sessions are kept on the event context, keyed by family and name, so a JWS
   * and a JWE session that share a `name` do not overwrite one another.
   */
  store: (event, slot) => ({
    get: () => getSessionsContext(event)[slot],
    set: (state) => {
      getSessionsContext(event)[slot] = state;
    },
  }),

  readToken: readSessionToken,

  scope: getSessionsContext,

  writable: hasWritableResponse,

  setCookie: (event, sessionName, token, options) => {
    setChunkedCookie(cookieEvent(event), sessionName, token, sessionCookieAttributes(options));
  },

  deleteCookie: expireSessionCookie,

  dropCookie: (event, sessionName, options) => {
    if (!hasWritableResponse(event)) {
      console.warn(`${PREFIX} Session expired but cookie cannot be cleared on a read-only event.`);
      return;
    }
    expireSessionCookie(event, sessionName, options);
  },
};

export function getSessionsContext(event: H3Event | CompatEvent): Record<string, unknown> {
  return (event.context.sessions ||= Object.create(null));
}

/**
 * Whether the response can still take a `Set-Cookie`: an h3 event whose
 * headers have not been sent yet.
 */
export function hasWritableResponse(event: H3Event | CompatEvent): boolean {
  if (!isEvent(event)) return false;
  const { res } = event.node;
  return !res.headersSent && !res.writableEnded;
}

/**
 * Read the raw session token for the request. The cookie is consulted first —
 * a session freshly minted onto the response's `Set-Cookie` before the request
 * cookie it replaces — and the session header (default `x-<name>-session`,
 * optional case-insensitive `Bearer` prefix) only when the cookie carries none.
 */
export function readSessionToken(
  event: H3Event | CompatEvent,
  sessionName: string,
  source: SessionTokenSource,
): string | undefined {
  let cookieValue: string | undefined;
  if (source.cookie !== false) {
    const written = readChunkedFromSetCookie(getResponseSetCookie(event), sessionName);
    // A deletion this response already wrote leaves the request without a token.
    if (written === "") return undefined;
    cookieValue = written ?? readChunkedFrom(getRequestCookies(event), sessionName);
  }

  const headerValue =
    source.sessionHeader === false
      ? undefined
      : headerToken(getRequestHeader(event, sessionHeaderName(sessionName, source.sessionHeader)));

  return pickToken(cookieValue, headerValue);
}

function expireSessionCookie(
  event: H3Event | CompatEvent,
  sessionName: string,
  options: SessionCookieOptions,
): void {
  deleteChunkedCookie(cookieEvent(event), sessionName, sessionCookieAttributes(options));
}

/** The event a cookie write lands on. */
function cookieEvent(event: H3Event | CompatEvent): H3Event {
  // oxlint-disable-next-line typescript/no-unsafe-type-assertion -- a cookie is written only once `writable` (hasWritableResponse) held, and it holds only for an H3Event
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
