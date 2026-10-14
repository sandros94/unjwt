/**
 * This is a fork of h3 library's session utility functions.
 * @source https://github.com/h3js/h3/blob/b4dce71c256911335f3402d09f30ffad120ad61a/src/utils/session.ts
 * @license MIT https://github.com/h3js/h3/blob/b4dce71c256911335f3402d09f30ffad120ad61a/LICENSE
 */

import {
  type H3Event,
  type HTTPEvent,
  type H3EventContext,
  getEventContext,
  getCookie,
} from "h3v2";
import {
  isChunkName,
  readChunkedBy,
  readChunkedFromSetCookie,
  removeChunked,
  setCookieName,
  writeChunked,
} from "../../_chunked-cookie";
import { eventCookieStore } from "../_cookie";
import { type SessionTokenSource, resolveSessionToken } from "../../_session";
import { type SessionPort, recordSlotStore } from "../../_session-core";

export type { SessionTokenSource };

/** Message prefix for every error and warning the h3 adapters emit. */
export const PREFIX = "[unjwt/h3]";

/** The h3 v2 session port: event-context state, request token, response cookies. */
export const h3SessionPort: SessionPort<HTTPEvent> = {
  prefix: PREFIX,

  carrier: (event) => ({ event }),

  /** Keyed by family and name, so a JWS and a JWE session sharing a `name` stay apart. */
  store: (event, slot) =>
    recordSlotStore(() => {
      const context = getEventContext<H3EventContext>(event);
      return (context.sessions ||= Object.create(null));
    }, slot),

  readToken: readSessionToken,

  scope: (event) => getEventContext<H3EventContext>(event),

  writable: hasWritableResponse,

  setCookie: (event, sessionName, token, { attrs, chunkMaxLength }) => {
    const target = cookieEvent(event);
    writeChunked(eventCookieStore(target), sessionName, token, {
      attrs,
      chunkMaxLength,
      prefix: PREFIX,
    });
    stageSessionErrCookies(target, sessionName);
  },

  deleteCookie: (event, sessionName, { attrs }) => {
    const target = cookieEvent(event);
    removeChunked(eventCookieStore(target), sessionName, { attrs });
    stageSessionErrCookies(target, sessionName);
  },
};

/** Whether the event carries an h3 response the session can stage cookies on. */
export function hasResponse(event: HTTPEvent): event is H3Event {
  return "res" in event && Boolean(event.res);
}

/** Whether the response can still take a `Set-Cookie`; only the Node runtime exposes that signal. */
export function hasWritableResponse(event: HTTPEvent): event is H3Event {
  if (!hasResponse(event)) return false;
  const res = event.runtime?.node?.res;
  return !res || (!res.headersSent && !res.writableEnded);
}

/** Read the session token: a cookie just set on the response, the request cookie, then the session header. */
export function readSessionToken(
  event: HTTPEvent,
  sessionName: string,
  source: SessionTokenSource,
): string | undefined {
  return resolveSessionToken(source, sessionName, {
    written: (name) =>
      hasResponse(event)
        ? readChunkedFromSetCookie(event.res.headers.getSetCookie(), name)
        : undefined,
    cookie: (name) => readChunkedBy((key) => getCookie(event, key), name),
    header: (name) => event.req.headers.get(name),
  });
}

/** Mirror the session's `Set-Cookie` into `res.errHeaders`, the only headers h3 v2 sends for a thrown handler. */
export function stageSessionErrCookies(event: H3Event, sessionName: string): void {
  const isSessionCookie = (cookie: string) => {
    const name = setCookieName(cookie);
    return name !== undefined && (name === sessionName || isChunkName(name, sessionName));
  };
  const errHeaders = event.res.errHeaders;
  const staged = [
    ...errHeaders.getSetCookie().filter((cookie) => !isSessionCookie(cookie)),
    ...event.res.headers.getSetCookie().filter((cookie) => isSessionCookie(cookie)),
  ];
  errHeaders.delete("set-cookie");
  for (const cookie of staged) errHeaders.append("set-cookie", cookie);
}

function cookieEvent(event: HTTPEvent): H3Event {
  // oxlint-disable-next-line typescript/no-unsafe-type-assertion -- `writable` held, so this is an H3Event
  return event as H3Event;
}
