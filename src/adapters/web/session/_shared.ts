import type { SessionDriver } from "../../_driver";
import { webCookieJar } from "../_cookie";
import type { SessionContext } from "./types";

/** Message prefix for every error the Web session entry emits. */
export const PREFIX = "[unjwt/session]";

/** The state of each request, keyed by its `Request`, or by the context object that hands a token in. */
const SESSIONS = /* @__PURE__ */ new WeakMap<object, Record<string, unknown>>();

/** The Web session driver: a `Request` and the response's `Headers`, or a token in hand. */
export const webSessionDriver: SessionDriver<SessionContext> = {
  prefix: PREFIX,

  state: (context) => sessionsOf("token" in context ? context : context.request),

  header: (context, name) => ("token" in context ? undefined : context.request.headers.get(name)),

  /** The Web exposes no response-sent signal: the jar takes writes while there are `Headers`. */
  cookies: (context) =>
    "token" in context ? { read: () => undefined } : webCookieJar(context.request, context.headers),

  handed: (context) => ("token" in context ? { token: context.token } : undefined),
};

function sessionsOf(key: object): Record<string, unknown> {
  const existing = SESSIONS.get(key);
  if (existing) return existing;
  const created: Record<string, unknown> = Object.create(null);
  SESSIONS.set(key, created);
  return created;
}
