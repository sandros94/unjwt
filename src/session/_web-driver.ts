import { isPlainObject } from "../core/utils/guards.ts";
import type { SessionDriver } from "./_driver.ts";
import { invalidConfigError } from "./_contract.ts";
import { webCookieJar } from "./_cookie.ts";
import type { SessionContext, SessionRequestEvent, SessionRequestHeaders } from "./types.ts";

/** Message prefix for every error the Web session entry emits. */
export const PREFIX = "[unjwt/session]";

/** The state of each request without a `context` of its own, keyed by its `Request` or by the object handed in. */
const SESSIONS = /* @__PURE__ */ new WeakMap<object, Record<string, unknown>>();

/** The Web session driver: a request event, a request that only reads, or a token in hand. */
export const webSessionDriver: SessionDriver<SessionContext> = {
  prefix: PREFIX,

  /** `context.sessions` when the framework hands a context, so middleware and handler share one state. */
  state: (context) => {
    if ("token" in context) return sessionsOf(context);
    if (context.context) return contextSessions(context.context);
    return sessionsOf("req" in context ? webRequest(context) : context);
  },

  header: (context, name) => ("token" in context ? undefined : requestHeaders(context).get(name)),

  /** The Web exposes no response-sent signal: the jar takes writes while there is a `res`. */
  cookies: (context) =>
    "token" in context
      ? { read: () => undefined }
      : webCookieJar(requestHeaders(context), context.res?.headers),

  handed: (context) => ("token" in context ? { token: context.token } : undefined),
};

function requestHeaders(context: SessionRequestEvent | SessionRequestHeaders): Headers {
  return "req" in context ? webRequest(context).headers : context.headers;
}

/** The event's `Request`; a runtime's own event (h3 v1's Node `req`) is refused with the fix spelled out. */
function webRequest(context: SessionRequestEvent): Request {
  const headers: unknown = context.req.headers;
  if (typeof headers === "object" && headers !== null && "get" in headers) return context.req;
  throw invalidConfigError(`${PREFIX} use() got an event whose "req" is not a web Request.`);
}

function contextSessions(context: Record<string, unknown>): Record<string, unknown> {
  const existing = context.sessions;
  if (isPlainObject(existing)) return existing;
  const created: Record<string, unknown> = Object.create(null);
  context.sessions = created;
  return created;
}

function sessionsOf(key: object): Record<string, unknown> {
  const existing = SESSIONS.get(key);
  if (existing) return existing;
  const created: Record<string, unknown> = Object.create(null);
  SESSIONS.set(key, created);
  return created;
}
