import type { SessionIssueOptions } from "../../_session";

export type { SessionIssueOptions };
export type {
  SessionClaims,
  SessionData,
  SessionManager,
  SessionUpdate,
  SessionUpdateTrigger,
} from "../../_session-types";
export type { SessionDefinition } from "../../_session-definition";
export type { OpenedSessionState } from "../../_session-core";

/** A web-standard request event: reads, and writes while `res` is there. */
export interface SessionRequestEvent {
  readonly req: Request;
  /** The response being prepared; without it the session is read-only. */
  readonly res?: { readonly headers: Headers };
  /** The framework's per-request state, where `sessions` is kept; without it state is keyed on `req`. */
  readonly context?: Record<string, unknown>;
}

/** A request by its headers: a `Request` itself, a WebSocket upgrade's request, a peer's `request` with its `context`. */
export interface SessionRequestHeaders {
  readonly headers: Headers;
  /** The response being prepared, such as the headers a WebSocket `upgrade` returns; without it the session is read-only. */
  readonly res?: { readonly headers: Headers };
  /** Per-request state shared with the framework; without it state is keyed on this object. */
  readonly context?: Record<string, unknown>;
}

/** A token handed in directly; sending a re-issued one is the caller's job. */
export interface SessionToken {
  token: string | undefined;
}

/** What `use()` takes: a request event, a request by its headers, or a token in hand. */
export type SessionContext = SessionRequestEvent | SessionRequestHeaders | SessionToken;
