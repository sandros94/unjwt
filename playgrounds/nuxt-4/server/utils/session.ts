// #region docs
import { createError, useRuntimeConfig } from "nuxt/server";
import {
  type JWK_oct,
  type SessionDefinition,
  type WebSessionEvent,
  defineJWSSession,
} from "unjwt/session";

let definition: SessionDefinition<SessionData, "1h"> | undefined;

/** Reads the key from the runtime config once, on first use. */
export function appSession(): SessionDefinition<SessionData, "1h"> {
  if (definition) return definition;
  // Nuxt parses a JSON environment variable into an object; a value set in nuxt.config stays a string
  const { sessionKey } = useRuntimeConfig() as { sessionKey: string | JWK_oct };
  if (!sessionKey) throw new Error("NUXT_SESSION_KEY is not set");
  definition = defineJWSSession<SessionData, "1h">({
    key: typeof sessionKey === "string" ? JSON.parse(sessionKey) : sessionKey,
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
  if (!session.id) throw createError({ statusCode: 401, message: "Sign in first" });
  return session;
}
// #endregion
