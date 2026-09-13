import { readChunkedCookie } from "../_cookie";
import {
  type SessionTokenSource,
  assertTokenSource,
  headerToken,
  pickToken,
  sessionHeaderName,
} from "../../_session";
import type { SessionContext, SessionData } from "./types";

export type { SessionTokenSource };

/** Message prefix for every error the Elysia adapter emits. */
export const PREFIX = "[unjwt/elysia]";

/**
 * Read the raw session token for the request. The cookie is consulted first,
 * and the session header (default `x-<name>-session`, optional case-insensitive
 * `Bearer` prefix) only when the cookie carries none.
 */
export function readSessionToken(
  context: SessionContext,
  sessionName: string,
  source: SessionTokenSource,
): string | undefined {
  assertTokenSource(source, { prefix: PREFIX });

  const cookieValue =
    source.cookie === false ? undefined : readChunkedCookie(context.cookie, sessionName);

  const headerValue =
    source.sessionHeader === false
      ? undefined
      : headerToken(
          context.request.headers.get(sessionHeaderName(sessionName, source.sessionHeader)),
        );

  return pickToken(cookieValue, headerValue);
}

export function emptyData<T extends Record<string, any>>(): SessionData<T> {
  return Object.create(null) as SessionData<T>;
}
