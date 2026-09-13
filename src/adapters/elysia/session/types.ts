import type { SessionIssueOptions } from "../../_session";
import type { ChunkableCookieJar } from "../_cookie";

export type { SessionIssueOptions };
export type {
  SessionClaims,
  SessionData,
  SessionManager,
  SessionUpdate,
} from "../../_session-types";

export interface SessionContext {
  cookie: ChunkableCookieJar;
  request: { headers: { get(name: string): string | null } };
}
