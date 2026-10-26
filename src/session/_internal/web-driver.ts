import type { SessionDriver } from "./driver.ts";
import { invalidConfigError } from "./contract.ts";
import { webCookieJar } from "./cookie.ts";
import { createRequestState } from "./request-state.ts";
import type { SessionHandedToken, SessionRequestEvent, WebSessionEvent } from "../types.ts";

/** Starts the message of every error `unjwt/session` throws. */
export const PREFIX = "[unjwt/session]";

/** The state of each request without a `context`, keyed by its `Request` or by the object passed in. */
const sessionsOf = /* @__PURE__ */ createRequestState();

/** The Web session driver: a request event by its `Request` or its `Headers`, or a token in hand. */
export const webSessionDriver: SessionDriver<WebSessionEvent> = {
  prefix: PREFIX,

  /** `event.context.sessions` when the event has a `context`, so middleware and handler share one state. */
  state: (event) => {
    if (isHanded(event)) return sessionsOf(event);
    if (event.context) return contextSessions(event.context);
    return sessionsOf(event.req ? webRequest(event.req) : event);
  },

  header: (event, name) => (isHanded(event) ? undefined : requestHeaders(event).get(name)),

  /** A Web response has no sent signal: the jar writes whenever there is a `res`. */
  cookies: (event) =>
    isHanded(event) ? { read: () => undefined } : webCookieJar(requestHeaders(event), event.res),

  handed: (event) => (isHanded(event) ? { token: event.token } : undefined),
};

/** A token in hand is the shape with neither `req` nor `headers`, so a request event is never mistaken for one. Anything else is refused. */
function isHanded(event: WebSessionEvent): event is SessionHandedToken {
  if ("req" in event || "headers" in event) return false;
  if ("token" in event) return true;
  throw invalidConfigError(`${PREFIX} use() got neither a request event nor a token.`);
}

/** `req` first, so an event's own `Request` keys the state. An event with `headers` alone is a request by its headers. */
function requestHeaders(event: SessionRequestEvent): Headers {
  if (event.req) return webRequest(event.req).headers;
  if (event.headers) return event.headers;
  throw invalidConfigError(`${PREFIX} use() got a request event with neither "req" nor "headers".`);
}

/** The event's `Request`. A `req` without Web `Headers` (a Node request) is refused. */
function webRequest(req: Request): Request {
  const headers: unknown = req.headers;
  if (typeof headers === "object" && headers !== null && "get" in headers) return req;
  throw invalidConfigError(`${PREFIX} use() got an event whose "req" is not a web Request.`);
}

/** The `sessions` slot a framework's own session helper may create too: an existing object is shared, never replaced. */
function contextSessions(context: Record<string, unknown>): Record<string, unknown> {
  const existing = context.sessions;
  if (typeof existing === "object" && existing !== null) {
    // oxlint-disable-next-line typescript/no-unsafe-type-assertion -- the slot is a record by contract with the framework
    return existing as Record<string, unknown>;
  }
  const created: Record<string, unknown> = Object.create(null);
  context.sessions = created;
  return created;
}
