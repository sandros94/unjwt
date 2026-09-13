import {
  type H3Event,
  type HTTPEvent,
  type H3EventContext,
  getEventContext,
  getChunkedCookie,
} from "h3v2";
import { readChunkedFromSetCookie } from "../../_chunked-cookie";
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

/**
 * The context slot a session occupies. Keying by family keeps a JWS and a JWE
 * session that share a `name` from overwriting one another on one event.
 */
export function sessionSlot(family: "jws" | "jwe", sessionName: string): string {
  return `${family}:${sessionName}`;
}

export function getSessionFromContext<S>(event: HTTPEvent, slot: string): S | undefined {
  const context = getEventContext<H3EventContext>(event);
  return context.sessions?.[slot] as S | undefined;
}

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
  assertTokenSource(source, { prefix: PREFIX });

  let cookieValue: string | undefined;
  if (source.cookie !== false) {
    if (hasWritableResponse(event)) {
      cookieValue = readChunkedFromSetCookie(event.res.headers.getSetCookie(), sessionName);
    }
    cookieValue ??= getChunkedCookie(event, sessionName);
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
