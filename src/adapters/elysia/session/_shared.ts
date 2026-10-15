import { readChunkedCookie, writeChunkedCookie, removeChunkedCookie } from "../_cookie";
import { type SessionTokenSource, resolveSessionToken } from "../../_session";
import { type SessionPort, recordSlotStore } from "../../_session-core";
import type { SessionContext } from "./types";

export type { SessionTokenSource };

/** Message prefix for every error the Elysia adapter emits. */
export const PREFIX = "[unjwt/elysia]";

/** The session states of each request, keyed by family and name. */
const SESSIONS = /* @__PURE__ */ new WeakMap<object, Record<string, unknown>>();

/** The Elysia session port: per-request state shared by every binding, and the reactive cookie jar. */
export const elysiaSessionPort: SessionPort<SessionContext> = {
  prefix: PREFIX,

  carrier: (context) => ({ context }),

  store: (context, slot) => recordSlotStore(() => requestSessions(context.request), slot),

  readToken: readSessionToken,

  scope: (context) => context.request,

  /** Elysia exposes no response-sent signal: writes are always accepted, and lost once the response is built. */
  writable: () => true,

  setCookie: (context, sessionName, token, { attrs, chunkMaxLength }) => {
    writeChunkedCookie(context.cookie, sessionName, token, { ...attrs, chunkMaxLength });
  },

  deleteCookie: (context, sessionName, { attrs }) => {
    removeChunkedCookie(context.cookie, sessionName, attrs);
  },
};

/** Read the session token: cookie first, then the session header; the jar cannot tell a deleted cookie from none. */
export function readSessionToken(
  context: SessionContext,
  sessionName: string,
  source: SessionTokenSource,
): string | undefined {
  return resolveSessionToken(source, sessionName, {
    cookie: (name) => readChunkedCookie(context.cookie, name),
    header: (name) => context.request.headers.get(name),
  });
}

function requestSessions(request: object): Record<string, unknown> {
  const existing = SESSIONS.get(request);
  if (existing) return existing;
  const created: Record<string, unknown> = Object.create(null);
  SESSIONS.set(request, created);
  return created;
}
