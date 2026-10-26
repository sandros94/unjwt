// #region docs
import { H3, HTTPError, readBody } from "h3";
import { defineJWSSession } from "unjwt/session";

const SESSION_KEY = process.env.SESSION_KEY;
if (!SESSION_KEY) throw new Error("SESSION_KEY is not set");

const appSession = defineJWSSession<{ user: string }, "1h">({
  key: JSON.parse(SESSION_KEY),
  maxAge: "1h",
  rolling: "15m",
});

export const app: H3 = new H3()
  .post("/login", async (event) => {
    const body = await readBody<{ user?: unknown }>(event);
    if (typeof body?.user !== "string") {
      throw new HTTPError({ status: 400, message: "user required" });
    }
    const session = await appSession.use(event);
    await session.update({ user: body.user });
    return { user: session.data.user };
  })
  .get("/me", async (event) => {
    const session = await appSession.use(event);
    if (!session.id) throw new HTTPError({ status: 401, message: "Sign in first" });
    return session.data;
  })
  .post("/logout", async (event) => {
    const session = await appSession.use(event);
    await session.clear();
    return { ok: true };
  });
// #endregion

// #region middleware
app.use("/account/**", async (event) => {
  const session = await appSession.use(event);
  if (!session.id) throw new HTTPError({ status: 401, message: "Sign in first" });
});

app.get("/account/profile", async (event) => {
  // Same event, same session: the middleware's read is reused
  const session = await appSession.use(event);
  return { user: session.data.user, expiresAt: session.expiresAt };
});
// #endregion
