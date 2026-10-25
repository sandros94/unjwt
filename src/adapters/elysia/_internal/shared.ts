import type { SessionDriver } from "../../../session/_internal/driver.ts";
import { createRequestState } from "../../../session/_internal/request-state.ts";
import { reactiveCookieJar } from "./cookie.ts";
import type { SessionContext } from "../session/types.ts";

/** Message prefix for every error the Elysia adapter emits. */
export const PREFIX = "[unjwt/elysia]";

/** The session state of each request, keyed by its `Request`: the one object every resolve, guard and handler shares. */
const requestSessions = /* @__PURE__ */ createRequestState();

/** The Elysia session driver: per-request state, request headers and the reactive cookie jar. */
export const elysiaSessionDriver: SessionDriver<SessionContext> = {
  prefix: PREFIX,

  state: (context) => requestSessions(context.request),

  header: (context, name) => context.request.headers.get(name),

  /** Elysia exposes no response-sent signal: writes are always accepted, and lost once the response is built. */
  cookies: (context) => reactiveCookieJar(context.cookie),
};
