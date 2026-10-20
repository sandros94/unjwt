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
  setCookie,
} from "h3";
import { setCookieName, setCookieValues } from "../../_chunked-cookie";
import type { CookieJar, SessionDriver } from "../../_driver";
import type { CookieSerializeOptions } from "../_cookie";

/** Message prefix for every error the h3 adapters emit. */
export const PREFIX = "[unjwt/h3]";

/** The h3 v2 session driver: event-context state, request headers, the response's cookies. */
export const h3SessionDriver: SessionDriver<HTTPEvent> = {
  prefix: PREFIX,

  state: (event) => (getEventContext<H3EventContext>(event).sessions ||= Object.create(null)),

  header: (event, name) => event.req.headers.get(name),

  /** As in h3 v2's own `useSession`: only an event carrying `res` writes. */
  cookies: (event) =>
    hasResponse(event) ? responseCookieJar(event) : { read: (name) => getCookie(event, name) },
};

function responseCookieJar(event: H3Event): CookieJar<CookieSerializeOptions> {
  return {
    read: (name) => getCookie(event, name),
    written: (name) => setCookieValues(event.res.headers.getSetCookie())[name],
    write: (name, value, attrs) => {
      setCookie(event, name, value, attrs);
      stageErrCookie(event, name);
    },
  };
}

/** Whether the event carries an h3 response the session can stage cookies on. */
function hasResponse(event: HTTPEvent): event is H3Event {
  return "res" in event && Boolean(event.res);
}

/** Mirror a cookie's `Set-Cookie` into `res.errHeaders`, the only headers h3 v2 sends for a thrown handler. */
function stageErrCookie(event: H3Event, cookieName: string): void {
  const isThisCookie = (cookie: string) => setCookieName(cookie) === cookieName;
  const errHeaders = event.res.errHeaders;
  const staged = [
    ...errHeaders.getSetCookie().filter((cookie) => !isThisCookie(cookie)),
    ...event.res.headers.getSetCookie().filter((cookie) => isThisCookie(cookie)),
  ];
  errHeaders.delete("set-cookie");
  for (const cookie of staged) errHeaders.append("set-cookie", cookie);
}
