import type { ChunkableCookieJar } from "../_cookie.ts";

export type {
  OpenedSessionState,
  SessionClaims,
  SessionData,
  SessionDefinition,
  SessionIssueOptions,
  SessionManager,
  SessionUpdate,
  SessionUpdateTrigger,
} from "../../../session/types.ts";

export interface SessionContext {
  cookie: ChunkableCookieJar;
  request: { headers: { get(name: string): string | null } };
}
