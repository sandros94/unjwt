import { generateJWK } from "unjwt/jwk";

// #region docs
import { Elysia, t } from "elysia";
import { jweSession } from "unjwt/adapters/elysia";

// #hide const key = the "oct" JWK from SESSION_KEY (see Configure a session)
const key = await generateJWK("A256GCM");
// #endhide

interface AppSession {
  userId: string;
}

const app = new Elysia()
  .use(jweSession<AppSession, "7D">({ key, maxAge: "7D" }))
  .post(
    "/login",
    async ({ session, body }) => {
      // Check the credentials first, then:
      await session.update({ userId: body.userId });
      return { expiresAt: session.expiresAt };
    },
    { body: t.Object({ userId: t.String() }) },
  )
  .get("/me", ({ session }) => session.data, { requireSession: true })
  .post("/logout", async ({ session }) => {
    await session.clear();
    return { signedOut: true };
  });
// #endregion

// #region define
import { defineJWSSession } from "unjwt/adapters/elysia";

// #hide const signingKey = an HS256 JWK loaded at start-up
const signingKey = await generateJWK("HS256");
// #endhide

const apiSession = defineJWSSession<{ userId: string; scope: string }, "30D", "api">({
  key: signingKey,
  name: "__Host-api",
  contextKey: "api",
  maxAge: "30D",
  sessionHeader: "authorization",
});

const apiApp = new Elysia()
  .use(apiSession.plugin())
  .get("/api/whoami", ({ api }) => api.data, { requireApi: true });

/** A token for a script or a CLI, minted outside any request. */
export function apiTokenFor(userId: string): Promise<string> {
  return apiSession.issue({ userId, scope: "read" });
}
// #endregion

// #region resolve
const accountSession = defineJWSSession<{ userId: string }, "1h">({
  key: signingKey,
  name: "__Host-account",
  maxAge: "1h",
});

const accountApp = new Elysia()
  .resolve(async ({ cookie, request }) => ({
    account: await accountSession.use({ cookie, request }),
  }))
  .get("/account", ({ account }) => account.data);
// #endregion

export const handle = (request: Request): Promise<Response> => app.handle(request);
export const handleAccount = (request: Request): Promise<Response> => accountApp.handle(request);
export const accountTokenFor = (userId: string): Promise<string> =>
  accountSession.issue({ userId });
export const handleApi = (request: Request): Promise<Response> => apiApp.handle(request);
