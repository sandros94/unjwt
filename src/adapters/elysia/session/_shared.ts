import type { SessionDriver } from "../../_driver";
import { reactiveCookieJar } from "../_cookie";
import type { SessionContext } from "./types";

/** Message prefix for every error the Elysia adapter emits. */
export const PREFIX = "[unjwt/elysia]";

/** The session state of each request, keyed by its `Request`: the one object every resolve, guard and handler shares. */
const SESSIONS = /* @__PURE__ */ new WeakMap<object, Record<string, unknown>>();

/** The Elysia session driver: per-request state, request headers and the reactive cookie jar. */
export const elysiaSessionDriver: SessionDriver<SessionContext> = {
  prefix: PREFIX,

  state: (context) => requestSessions(context.request),

  header: (context, name) => context.request.headers.get(name),

  /** Elysia exposes no response-sent signal: writes are always accepted, and lost once the response is built. */
  cookies: (context) => reactiveCookieJar(context.cookie),
};

function requestSessions(request: object): Record<string, unknown> {
  const existing = SESSIONS.get(request);
  if (existing) return existing;
  const created: Record<string, unknown> = Object.create(null);
  SESSIONS.set(request, created);
  return created;
}
