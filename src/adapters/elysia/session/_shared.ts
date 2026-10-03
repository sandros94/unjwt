import {
  type CookieAttributes,
  readChunkedCookie,
  writeChunkedCookie,
  removeChunkedCookie,
} from "../_cookie";
import { type SessionTokenSource, headerToken, pickToken, sessionHeaderName } from "../../_session";
import type { SessionCookieOptions, SessionPort, SessionState } from "../../_session-core";
import type { SessionContext } from "./types";

export type { SessionTokenSource };

/** Message prefix for every error the Elysia adapter emits. */
export const PREFIX = "[unjwt/elysia]";

/** The session states of each request, keyed by family and name. */
const SESSIONS = /* @__PURE__ */ new WeakMap<object, Record<string, SessionState<any, any>>>();

/**
 * The Elysia side of a session: the reactive cookie jar it reads its token
 * from and writes it back to. Elysia's context carries no slot of its own for
 * the session, so its state is held per request, and every binding of one
 * family and name on that request — the plugin's, a handler's, a hook's —
 * shares it.
 */
export const elysiaSessionPort: SessionPort<SessionContext> = {
  prefix: PREFIX,

  carrier: (context) => ({ context }),

  store: (context, slot) => ({
    get: () => SESSIONS.get(context.request)?.[slot],
    set: (state) => {
      let sessions = SESSIONS.get(context.request);
      if (!sessions) {
        sessions = Object.create(null) as Record<string, SessionState<any, any>>;
        SESSIONS.set(context.request, sessions);
      }
      sessions[slot] = state;
    },
  }),

  readToken: readSessionToken,

  /** The request is the one object every session of it is created from. */
  scope: (context) => context.request,

  /**
   * Elysia hands the cookie jar to every lifecycle stage and exposes no sign
   * that the response was already built, so a write is always accepted; one
   * made once the response is built (e.g. in `onAfterResponse`) is not sent.
   */
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
