import type { SessionDriver } from "./driver.ts";
import { invalidConfigError } from "./contract.ts";
import { webCookieJar } from "./cookie.ts";
import type { SessionHandedToken, SessionRequestEvent, WebSessionEvent } from "../types.ts";

/** The state of each request without a `context`, keyed by its `Request` or by the object passed in. */
const requestStates = /* @__PURE__ */ new WeakMap<object, Record<string, unknown>>();

/**
 * The Web session driver: a request event by its `Request` or its `Headers`, or a token in hand.
 * `prefix` (default `"[unjwt/session]"`) starts the message of every error a session over it throws, the driver's own included.
 * Every driver it returns shares the state of a request with the others.
 */
export function webSessionDriver(options?: { prefix?: string }): SessionDriver<WebSessionEvent> {
  const prefix = options?.prefix ?? "[unjwt/session]";
  return {
    prefix,

    /** `event.context.unjwt` when the event has a `context`, so middleware and handler share one state. */
    state: (event) => {
      if (isHanded(event, prefix)) return sessionsOf(event);
      if (event.context) return contextState(event.context);
      return sessionsOf(event.req ? webRequest(event.req, prefix) : event);
    },

    header: (event, name) =>
      isHanded(event, prefix) ? undefined : requestHeaders(event, prefix).get(name),

    /** A Web response has no sent signal: the jar writes whenever there is a `res`. */
    cookies: (event) =>
      isHanded(event, prefix)
        ? { read: () => undefined }
        : webCookieJar(requestHeaders(event, prefix), event.res),

    handed: (event) => (isHanded(event, prefix) ? { token: event.token } : undefined),
  };
}

/** The Web session driver `defineJWSSession` and `defineJWESession` run on when given none. */
export const defaultWebSessionDriver: SessionDriver<WebSessionEvent> =
  /* @__PURE__ */ webSessionDriver();

/** A token in hand is the shape with neither `req` nor `headers`, so a request event is never mistaken for one. Anything else is refused. */
function isHanded(event: WebSessionEvent, prefix: string): event is SessionHandedToken {
  if ("req" in event || "headers" in event) return false;
  if ("token" in event) return true;
  throw invalidConfigError(`${prefix} use() got neither a request event nor a token.`);
}

/** `req` first, so an event's own `Request` keys the state. An event with `headers` alone is a request by its headers. */
function requestHeaders(event: SessionRequestEvent, prefix: string): Headers {
  if (event.req) return webRequest(event.req, prefix).headers;
  if (event.headers) return event.headers;
  throw invalidConfigError(`${prefix} use() got a request event with neither "req" nor "headers".`);
}

/** The event's `Request`. A `req` without Web `Headers` (a Node request) is refused. */
function webRequest(req: Request, prefix: string): Request {
  const headers: unknown = req.headers;
  if (typeof headers === "object" && headers !== null && "get" in headers) return req;
  throw invalidConfigError(`${prefix} use() got an event whose "req" is not a web Request.`);
}

/** The `unjwt` slot of a context, created on first use: an existing object is reused, never replaced. */
function contextState(context: Record<string, unknown>): Record<string, unknown> {
  const existing = context.unjwt;
  if (typeof existing === "object" && existing !== null) {
    // oxlint-disable-next-line typescript/no-unsafe-type-assertion -- the slot holds the record this driver created
    return existing as Record<string, unknown>;
  }
  const created: Record<string, unknown> = Object.create(null);
  context.unjwt = created;
  return created;
}

/** The state of a request object, created on first use and released with the object. */
function sessionsOf(request: object): Record<string, unknown> {
  const existing = requestStates.get(request);
  if (existing) return existing;
  const created: Record<string, unknown> = Object.create(null);
  requestStates.set(request, created);
  return created;
}
