import {
  type CookieAttributes,
  readChunkedCookie,
  writeChunkedCookie,
  removeChunkedCookie,
} from "../_cookie";
import {
  type SessionTokenSource,
  assertTokenSource,
  headerToken,
  pickToken,
  sessionHeaderName,
} from "../../_session";
import type { SessionCookieOptions, SessionPort, SessionState } from "../../_session-core";
import type { SessionContext } from "./types";

export type { SessionTokenSource };

/** Message prefix for every error the Elysia adapter emits. */
export const PREFIX = "[unjwt/elysia]";

/**
 * The Elysia side of a session: the reactive cookie jar it reads its token
 * from and writes it back to. A session lives as long as the context it was
 * created for, so it is held by the port rather than stored on the context.
 */
export const elysiaSessionPort: SessionPort<SessionContext> = {
  prefix: PREFIX,

  carrier: (context) => ({ context }),

  store: () => {
    let state: SessionState<any, any> | undefined;
    return {
      get: () => state,
      set: (next) => {
        state = next;
      },
    };
  },

  readToken: readSessionToken,

  /** Elysia hands the cookie jar to every handler, so the response is always writable. */
  writable: () => true,

  setCookie: (context, sessionName, token, options) => {
    const { chunkMaxLength, ...attrs } = cookieAttributes(options);
    writeChunkedCookie(context.cookie, sessionName, token, {
      ...attrs,
      chunkMaxLength,
      expires: options.expiresAt === undefined ? undefined : new Date(options.expiresAt),
    });
  },

  deleteCookie: expireSessionCookie,

  dropCookie: expireSessionCookie,
};

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

function expireSessionCookie(
  context: SessionContext,
  sessionName: string,
  options: SessionCookieOptions,
): void {
  const { chunkMaxLength: _chunkMaxLength, ...attrs } = cookieAttributes(options);
  removeChunkedCookie(context.cookie, sessionName, attrs);
}

function cookieAttributes(
  options: SessionCookieOptions,
): CookieAttributes & { chunkMaxLength?: number } {
  return { ...options.defaults, ...options.cookie } as CookieAttributes & {
    chunkMaxLength?: number;
  };
}
