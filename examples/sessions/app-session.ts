// #region docs
import { type JWK_oct, type SessionDefinition, defineJWESession } from "unjwt/session";

// An "oct" JWK as JSON: generateJWK("A256GCM"), made once and kept with your secrets
const json = process.env.SESSION_KEY;
if (!json) throw new Error("SESSION_KEY is not set");
const key: JWK_oct<"A256GCM"> = JSON.parse(json);

export interface AppSession {
  userId: string;
  role: "member" | "admin";
  workspaceId?: string;
}

export const appSession: SessionDefinition<AppSession, "7D"> = defineJWESession({
  key,
  maxAge: "7D",
  rolling: "1D",
});
// #endregion
