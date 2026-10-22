import type { SessionDriver } from "./_driver.ts";
import { invalidConfigError } from "./_contract.ts";
import { webCookieJar } from "./_cookie.ts";
import type { SessionHandedToken, SessionRequestEvent, WebSessionEvent } from "./types.ts";

/** Message prefix for every error the Web session entry emits. */
export const PREFIX = "[unjwt/session]";

/** The state of each request without a `context` of its own, keyed by its `Request` or by the object handed in. */
const SESSIONS = /* @__PURE__ */ new WeakMap<object, Record<string, unknown>>();

/** The Web session driver: a request event by its `Request` or its `Headers`, or a token in hand. */
export const webSessionDriver: SessionDriver<WebSessionEvent> = {
  prefix: PREFIX,

  /** `event.context.sessions` when the framework hands a context, so middleware and handler share one state. */
  state: (event) => {
    if (isHanded(event)) return sessionsOf(event);
    if (event.context) return contextSessions(event.context);
    return sessionsOf(event.req ? webRequest(event.req) : event);
  },

  header: (event, name) => (isHanded(event) ? undefined : requestHeaders(event).get(name)),

  /** The Web exposes no response-sent signal: the jar takes writes while there is a `res`. */
  cookies: (event) =>
    isHanded(event)
      ? { read: () => undefined }
      : webCookieJar(requestHeaders(event), event.res?.headers),

  handed: (event) => (isHanded(event) ? { token: event.token } : undefined),
};

/** A token in hand is the shape with neither `req` nor `headers`, so a request event is never mistaken for one; anything else is refused. */
function isHanded(event: WebSessionEvent): event is SessionHandedToken {
  if ("req" in event || "headers" in event) return false;
  if ("token" in event) return true;
  throw invalidConfigError(`${PREFIX} use() got neither a request event nor a token.`);
}

/** `req` first, so an event's own `Request` keys the state; `headers` alone is a request by its headers. */
function requestHeaders(event: SessionRequestEvent): Headers {
  if (event.req) return webRequest(event.req).headers;
  if (event.headers) return event.headers;
  throw invalidConfigError(`${PREFIX} use() got a request event with neither "req" nor "headers".`);
}

/** The event's `Request`; a runtime's own event (h3 v1's Node `req`) is refused with the fix spelled out. */
function webRequest(req: Request): Request {
  const headers: unknown = req.headers;
  if (typeof headers === "object" && headers !== null && "get" in headers) return req;
  throw invalidConfigError(`${PREFIX} use() got an event whose "req" is not a web Request.`);
}

/** The slot h3's own `useSession` creates too, whatever object it chose: shared, never replaced. */
function contextSessions(context: Record<string, unknown>): Record<string, unknown> {
  const existing = context.sessions;
  if (typeof existing === "object" && existing !== null) {
    // oxlint-disable-next-line typescript/no-unsafe-type-assertion -- the slot is a record by contract with h3
    return existing as Record<string, unknown>;
  }
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
