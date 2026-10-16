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

/** A Web request and the Headers its response will be sent with, or a token handed in directly. */
export type SessionContext =
  | {
      request: Request;
      /** The response's headers; without them the session is read-only. */
      headers?: Headers;
    }
  | {
      /** The token itself; sending a re-issued one is the caller's job. */
      token: string | undefined;
    };
