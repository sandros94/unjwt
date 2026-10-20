import type { SessionIssueOptions } from "../../_session.ts";
import type { ChunkableCookieJar } from "../_cookie.ts";

export type { SessionIssueOptions };
export type {
  SessionClaims,
  SessionData,
  SessionManager,
  SessionUpdate,
  SessionUpdateTrigger,
} from "../../_session-types.ts";
export type { SessionDefinition } from "../../_session-definition.ts";
export type { OpenedSessionState } from "../../_session-core.ts";

export interface SessionContext {
  cookie: ChunkableCookieJar;
  request: { headers: { get(name: string): string | null } };
}
