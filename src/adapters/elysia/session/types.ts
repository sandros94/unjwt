import type { SessionIssueOptions } from "../../../session/_contract.ts";
import type { ChunkableCookieJar } from "../_cookie.ts";

export type { SessionIssueOptions };
export type {
  SessionClaims,
  SessionData,
  SessionManager,
  SessionUpdate,
  SessionUpdateTrigger,
} from "../../../session/_types.ts";
export type { SessionDefinition } from "../../../session/_definition.ts";
export type { OpenedSessionState } from "../../../session/_core.ts";

export interface SessionContext {
  cookie: ChunkableCookieJar;
  request: { headers: { get(name: string): string | null } };
}
