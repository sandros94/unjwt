import { HTTPError } from "nitro";
import { type SessionContext, defineJWESession, deriveJWKFromPassword } from "unjwt/session";

export interface SessionData {
  user: string;
}

const password = process.env.SESSION_PASSWORD ?? "playground-password-with-at-least-32-characters";

const key = await deriveJWKFromPassword(password, {
  alg: "PBES2-HS256+A128KW",
  salt: "unjwt-playground-nitro",
  iterations: 600_000,
});

const definition = defineJWESession<SessionData, "1h">({
  key,
  name: "unjwt-session",
  maxAge: "1h",
  rolling: "15m",
  hooks: {
    async onError({ session }) {
      await session.clear();
    },
  },
});

export function useAppSession(event: SessionContext) {
  return definition.use(event);
}

export async function requireAppSession(event: SessionContext) {
  const current = await useAppSession(event);
  if (!current.id) throw new HTTPError({ status: 401, message: "Sign in first" });
  return current;
}
