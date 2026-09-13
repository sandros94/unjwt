import { type H3Event, isEvent } from "h3v1";
import { parse as parseCookies } from "cookie-esv1";
import { readChunkedFrom, readChunkedFromSetCookie } from "../../_chunked-cookie";
import {
  type SessionTokenSource,
  assertTokenSource,
  headerToken,
  pickToken,
  sessionHeaderName,
} from "../../_session";

export type { SessionTokenSource };

/** Message prefix for every error and warning the h3 adapters emit. */
export const PREFIX = "[unjwt/h3]";

/** Event shapes the adapter reads from: an h3 v1 event, or any request-like object. */
export type CompatEvent =
  | { request: { headers: Headers }; context: any }
  | { headers: Headers; context: any };

/**
 * The context slot a session occupies. Keying by family keeps a JWS and a JWE
 * session that share a `name` from overwriting one another on one event.
 */
export function sessionSlot(family: "jws" | "jwe", sessionName: string): string {
  return `${family}:${sessionName}`;
}

export function getSessionsContext(event: H3Event | CompatEvent): Record<string, any> {
  if (!event.context.sessions) {
    event.context.sessions = Object.create(null);
  }
  return event.context.sessions as Record<string, any>;
}

export function hasWritableResponse(event: H3Event | CompatEvent): event is H3Event {
  return isEvent(event);
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
  assertTokenSource(source, { prefix: PREFIX });

  let cookieValue: string | undefined;
  if (source.cookie !== false) {
    cookieValue = readChunkedFromSetCookie(getResponseSetCookie(event), sessionName);
    cookieValue ??= readChunkedFrom(getRequestCookies(event), sessionName);
  }

  const headerValue =
    source.sessionHeader === false
      ? undefined
      : headerToken(getRequestHeader(event, sessionHeaderName(sessionName, source.sessionHeader)));

  return pickToken(cookieValue, headerValue);
}

function getRequestHeader(event: H3Event | CompatEvent, name: string): string | undefined {
  const nodeEvent = event as H3Event;
  if (nodeEvent.node) {
    const value = nodeEvent.node.req.headers[name];
    return Array.isArray(value) ? value[0] : value;
  }
  const headers =
    (event as { request?: { headers: Headers } }).request?.headers ??
    (event as { headers?: Headers }).headers;
  return headers?.get(name) ?? undefined;
}

function getRequestCookies(event: H3Event | CompatEvent): Record<string, string | undefined> {
  const header = getRequestHeader(event, "cookie");
  return header ? parseCookies(header) : Object.create(null);
}

function getResponseSetCookie(event: H3Event | CompatEvent): string[] {
  const nodeEvent = event as H3Event;
  if (nodeEvent.node) {
    const value = nodeEvent.node.res.getHeader("set-cookie");
    if (Array.isArray(value)) return value;
    return typeof value === "string" ? [value] : [];
  }
  const response = (event as { response?: Response }).response;
  return response?.headers ? response.headers.getSetCookie() : [];
}
