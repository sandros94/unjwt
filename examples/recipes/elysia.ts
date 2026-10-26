// #region docs
import { Elysia, t } from "elysia";
import { jwsSession } from "unjwt/adapters/elysia";

const SESSION_KEY = process.env.SESSION_KEY;
if (!SESSION_KEY) throw new Error("SESSION_KEY is not set");

const app = new Elysia()
  .use(
    jwsSession<{ user: string }, "1h">({
      key: JSON.parse(SESSION_KEY),
      maxAge: "1h",
      rolling: "15m",
    }),
  )
  .post(
    "/login",
    async ({ session, body }) => {
      await session.update({ user: body.user });
      return { user: session.data.user };
    },
    { body: t.Object({ user: t.String() }) },
  )
  .get("/me", ({ session }) => session.data, { requireSession: true })
  .post("/logout", async ({ session }) => {
    await session.clear();
    return { ok: true };
  });
// #endregion

// #region guard
app.guard({ requireSession: true }, (account) =>
  account
    .get("/account/profile", ({ session }) => ({
      user: session.data.user,
      expiresAt: session.expiresAt,
    }))
    .post(
      "/account/rename",
      async ({ session, body }) => {
        await session.update({ user: body.user });
        return { user: session.data.user };
      },
      { body: t.Object({ user: t.String() }) },
    ),
);
// #endregion

export function handle(request: Request): Promise<Response> {
  return app.handle(request);
}
