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
  setCookieName,
} from "../../_chunked-cookie";
import { setChunkedCookie, deleteChunkedCookie } from "../_cookie";
import {
  type SessionTokenSource,
  headerToken,
  pickToken,
  sessionCookieAttributes,
  sessionHeaderName,
} from "../../_session";
import type { SessionCookieOptions, SessionPort } from "../../_session-core";

export type { SessionTokenSource };

/** Message prefix for every error and warning the h3 adapters emit. */
export const PREFIX = "[unjwt/h3]";

/**
 * The h3 v2 side of a session: the event context it lives in, the request it
 * reads its token from, and the response it writes its cookie to.
 */
export const h3SessionPort: SessionPort<HTTPEvent> = {
  prefix: PREFIX,

  carrier: (event) => ({ event }),

  /**
   * Sessions are kept on the event context, keyed by family and name, so a JWS
   * and a JWE session that share a `name` do not overwrite one another.
   */
  store: (event, slot) => ({
    get: () => getEventContext<H3EventContext>(event).sessions?.[slot],
    set: (state) => {
      const context = getEventContext<H3EventContext>(event);
      const sessions: Record<string, unknown> = (context.sessions ||= Object.create(null));
      sessions[slot] = state;
    },
  }),

  readToken: readSessionToken,

  scope: (event) => getEventContext<H3EventContext>(event),

  writable: hasWritableResponse,

  setCookie: (event, sessionName, token, options) => {
    const target = cookieEvent(event);
    setChunkedCookie(target, sessionName, token, sessionCookieAttributes(options));
    stageSessionErrCookies(target, sessionName);
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

/** Whether the event carries an h3 response the session can stage cookies on. */
export function hasResponse(event: HTTPEvent): event is H3Event {
  return "res" in event && Boolean(event.res);
}

/**
 * Whether the response can still take a `Set-Cookie`: an h3 event whose
 * response has not been sent yet. Only the Node runtime exposes that signal;
 * on other runtimes a write is accepted, and one made after the response was
 * built is not sent.
 */
export function hasWritableResponse(event: HTTPEvent): event is H3Event {
  if (!hasResponse(event)) return false;
  const res = event.runtime?.node?.res;
  return !res || (!res.headersSent && !res.writableEnded);
}

/**
 * Read the raw session token for the request. The cookie is consulted first —
 * a session freshly minted onto the response's `Set-Cookie` before the request
 * cookie it replaces — and the session header (default `x-<name>-session`,
 * optional case-insensitive `Bearer` prefix) only when the cookie carries none.
 */
export function readSessionToken(
  event: HTTPEvent,
  sessionName: string,
  source: SessionTokenSource,
): string | undefined {
  let cookieValue: string | undefined;
  if (source.cookie !== false) {
    const written = hasResponse(event)
      ? readChunkedFromSetCookie(event.res.headers.getSetCookie(), sessionName)
      : undefined;
    // A deletion this response already wrote leaves the request without a token.
    if (written === "") return undefined;
    cookieValue = written ?? readChunkedBy((name) => getCookie(event, name), sessionName);
  }

  const headerValue =
    source.sessionHeader === false
      ? undefined
      : headerToken(event.req.headers.get(sessionHeaderName(sessionName, source.sessionHeader)));

  return pickToken(cookieValue, headerValue);
}

/**
 * h3 v2 builds a thrown handler's response from `res.errHeaders` alone, so a
 * session cookie written to `res.headers` would be lost when the handler
 * throws. Mirror the session's `Set-Cookie` entries there, replacing any
 * earlier ones for the same session.
 */
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

function expireSessionCookie(
  event: HTTPEvent,
  sessionName: string,
  options: SessionCookieOptions,
): void {
  const target = cookieEvent(event);
  deleteChunkedCookie(target, sessionName, sessionCookieAttributes(options));
  stageSessionErrCookies(target, sessionName);
}

/** The event a cookie write lands on. */
function cookieEvent(event: HTTPEvent): H3Event {
  // oxlint-disable-next-line typescript/no-unsafe-type-assertion -- a cookie is written only once `writable` (hasWritableResponse) held, and it holds only for an H3Event
  return event as H3Event;
}
