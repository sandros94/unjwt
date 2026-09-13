import {
  type H3Event,
  type HTTPEvent,
  type H3EventContext,
  getEventContext,
  getChunkedCookie,
} from "h3v2";

/** The parts of a session config that decide where the token is read from. */
export interface SessionTokenSource {
  /** Request header to read the token from, or `false` for cookies only. */
  sessionHeader?: false | string;
  /** Cookie options, or `false` for header only. */
  cookie?: false | object;
}

export function getSessionFromContext<S>(event: HTTPEvent, sessionName: string): S | undefined {
  const context = getEventContext<H3EventContext>(event);
  return context.sessions?.[sessionName] as S | undefined;
}

export function hasWritableResponse(event: HTTPEvent): event is H3Event {
  return Boolean((event as H3Event).res);
}

/**
 * Read the raw session token for the request. The session header (default
 * `x-<name>-session`, `Bearer ` prefix stripped) takes precedence, then a
 * freshly-minted token on the response's `Set-Cookie`, then the session cookie.
 */
export function readSessionToken(
  event: HTTPEvent,
  sessionName: string,
  source: SessionTokenSource,
): string | undefined {
  let token: string | undefined;

  if (source.sessionHeader !== false) {
    const headerName =
      typeof source.sessionHeader === "string"
        ? source.sessionHeader.toLowerCase()
        : `x-${sessionName.toLowerCase()}-session`;
    const headerValue = event.req.headers.get(headerName);
    if (typeof headerValue === "string") {
      token = headerValue.startsWith("Bearer ") ? headerValue.slice(7).trim() : headerValue;
    }
  }

  // Set-Cookie header may carry a freshly-minted session on redirect responses.
  if (source.cookie !== false && hasWritableResponse(event)) {
    const setCookie = event.res.headers.get("set-cookie");
    if (typeof setCookie === "string") {
      token = findSetCookie(setCookie, sessionName);
    }
  }

  if (!token) {
    token = getChunkedCookie(event, sessionName);
  }

  return token;
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

function findSetCookie(setCookie: string, name: string): string | undefined {
  const regex = new RegExp(`(?:^|,\\s*)${name}=([^;]+)`);
  const match = setCookie.match(regex);

  return match ? match[1] : undefined;
}
