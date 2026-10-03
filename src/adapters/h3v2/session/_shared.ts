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
import type { CookieSerializeOptions } from "cookie-esv3";
import { readChunkedBy, readChunkedFromSetCookie } from "../../_chunked-cookie";
import { setChunkedCookie, deleteChunkedCookie } from "../_cookie";
import { type SessionTokenSource, headerToken, pickToken, sessionHeaderName } from "../../_session";
import type { SessionCookieOptions, SessionPort, SessionState } from "../../_session-core";

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
    get: () =>
      getEventContext<H3EventContext>(event).sessions?.[slot] as SessionState<any, any> | undefined,
    set: (state) => {
      const context = getEventContext<H3EventContext>(event);
      if (!context.sessions) {
        context.sessions = Object.create(null);
      }
      (context.sessions as Record<string, unknown>)[slot] = state;
    },
  }),

  readToken: readSessionToken,

  scope: (event) => getEventContext<H3EventContext>(event),

  writable: hasWritableResponse,

  setCookie: (event, sessionName, token, options) => {
    setChunkedCookie(event as H3Event, sessionName, token, {
      ...options.defaults,
      ...options.cookie,
      // The token's own lifetime decides when the cookie stops being sent: a
      // cookie outliving the token it carries is a request that cannot work.
      expires: options.expiresAt === undefined ? undefined : new Date(options.expiresAt),
    } as CookieSerializeOptions & { chunkMaxLength?: number });
    stageSessionErrCookies(event as H3Event, sessionName);
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

export function hasWritableResponse(event: HTTPEvent): event is H3Event {
  return Boolean((event as H3Event).res);
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
    if (hasWritableResponse(event)) {
      cookieValue = readChunkedFromSetCookie(event.res.headers.getSetCookie(), sessionName);
    }
    cookieValue ??= readChunkedBy((name) => getCookie(event, name), sessionName);
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
  const isSessionCookie = (cookie: string) =>
    cookie.startsWith(`${sessionName}=`) || cookie.startsWith(`${sessionName}.`);
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
  deleteChunkedCookie(event as H3Event, sessionName, {
    ...options.defaults,
    ...options.cookie,
  } as CookieSerializeOptions);
  stageSessionErrCookies(event as H3Event, sessionName);
}
