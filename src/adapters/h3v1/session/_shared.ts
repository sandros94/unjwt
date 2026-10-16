import { type H3Event, type H3EventContext, isEvent, setCookie } from "h3v1";
import { parse as parseCookies } from "cookie-es";
import { setCookieValues } from "../../_chunked-cookie";
import type { CookieJar, SessionDriver } from "../../_driver";
import { type CookieSerializeOptions, responseSetCookies } from "../_cookie";

/** Message prefix for every error the h3 adapters emit. */
export const PREFIX = "[unjwt/h3]";

/** Event shapes the adapter reads from: an h3 v1 event, or any request-like object. */
export type CompatEvent =
  | { request: { headers: Headers }; context: H3EventContext }
  | { headers: Headers; context: H3EventContext };

/** The h3 v1 session driver: event-context state, request headers, the response's cookies. */
export const h3SessionDriver: SessionDriver<CompatEvent | H3Event> = {
  prefix: PREFIX,

  state: (event) => (event.context.sessions ||= Object.create(null)),

  header: getRequestHeader,

  cookies: (event) => {
    let requestCookies: Record<string, string | undefined> | undefined;
    const jar: CookieJar<CookieSerializeOptions> = {
      read: (name) => (requestCookies ||= getRequestCookies(event))[name],
      written: (name) => setCookieValues(getResponseSetCookie(event))[name],
    };
    if (isEvent(event)) {
      jar.write = (name, value, attrs) => {
        setCookie(event, name, value, attrs);
      };
    }
    return jar;
  },

  writable: (event) =>
    !isEvent(event) || (!event.node.res.headersSent && !event.node.res.writableEnded),
};

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
