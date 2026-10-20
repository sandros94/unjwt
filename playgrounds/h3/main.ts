import { H3, serve, HTTPError } from "h3";

import { type SessionContext, defineJWESession, deriveJWKFromPassword } from "unjwt/session";

export const password =
  process.env.SESSION_PASSWORD ?? "playground-password-with-at-least-32-characters";

interface SessionData {
  user: string;
}

const key = await deriveJWKFromPassword(password, {
  alg: "PBES2-HS256+A128KW",
  salt: "unjwt-playground-h3",
  iterations: 600_000,
});

const session = defineJWESession<SessionData, "1h">({
  key,
  name: "unjwt",
  maxAge: "1h",
  rolling: "15m",
});

function useAppSession(event: SessionContext) {
  return session.use(event);
}

const app = new H3()
  .post("/login", async (event) => {
    const body: { user?: unknown } = await event.req.json();

    if (typeof body?.user !== "string")
      throw new HTTPError({ status: 400, message: "user required" });

    const current = await useAppSession(event);
    await current.update({ user: body.user });

    return { id: current.id, user: current.data.user };
  })
  .get("/me", async (event) => {
    const current = await useAppSession(event);

    if (!current.id) throw new HTTPError({ status: 401 });

    return { id: current.id, user: current.data.user };
  })
  .post("/logout", async (event) => {
    const current = await useAppSession(event);
    await current.clear();

    return { ok: true };
  });

serve(app);
