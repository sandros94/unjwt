// #region docs
import { Hono } from "hono";
import { type SessionDefinition, type SessionManager, defineJWSSession } from "unjwt/session";

interface SessionData {
  user: string;
}

type Env = {
  Bindings: { SESSION_KEY?: string };
  Variables: { session: SessionManager<SessionData, "1h"> };
};

let appSession: SessionDefinition<SessionData, "1h"> | undefined;

/** Workers hand `env` to each request, so the session is defined on the first one. */
function sessionFor(env: Env["Bindings"]): SessionDefinition<SessionData, "1h"> {
  if (!env.SESSION_KEY) throw new Error("SESSION_KEY is not set");
  return (appSession ??= defineJWSSession<SessionData, "1h">({
    key: JSON.parse(env.SESSION_KEY),
    maxAge: "1h",
    rolling: "15m",
  }));
}

const app: Hono<Env> = new Hono<Env>();

app.use(async (c, next) => {
  const session = await sessionFor(c.env).use({ req: c.req.raw, res: c.res });
  c.set("session", session);
  await next();
});

app.post("/login", async (c) => {
  const body = await c.req.json<{ user?: unknown }>().catch(() => ({ user: undefined }));
  if (typeof body.user !== "string") return c.json({ message: "user required" }, 400);
  const session = c.get("session");
  await session.update({ user: body.user });
  return c.json({ user: session.data.user });
});

app.get("/me", (c) => {
  const session = c.get("session");
  if (!session.id) return c.json({ message: "Sign in first" }, 401);
  return c.json(session.data);
});

app.post("/logout", async (c) => {
  await c.get("session").clear();
  return c.json({ ok: true });
});

export default app;
// #endregion
