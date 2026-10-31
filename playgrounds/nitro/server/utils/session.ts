// #region docs
import { HTTPError } from "nitro";
import { useRuntimeConfig } from "nitro/runtime-config";
import { type SessionDefinition, type WebSessionEvent, defineJWSSession } from "unjwt/session";

export interface SessionData {
  user: string;
}

let definition: SessionDefinition<SessionData, "1h"> | undefined;

/** Reads the key from the runtime config once, on first use. */
export function appSession(): SessionDefinition<SessionData, "1h"> {
  if (definition) return definition;
  const { sessionKey } = useRuntimeConfig();
  if (!sessionKey) throw new Error("NITRO_SESSION_KEY is not set");
  definition = defineJWSSession<SessionData, "1h">({
    key: JSON.parse(sessionKey),
    maxAge: "1h",
    rolling: "15m",
  });
  return definition;
}

export function useAppSession(event: WebSessionEvent) {
  return appSession().use(event);
}

export async function requireAppSession(event: WebSessionEvent) {
  const session = await useAppSession(event);
  if (!session.id) throw new HTTPError({ status: 401, message: "Sign in first" });
  return session;
}
// #endregion
