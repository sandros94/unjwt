import { generateJWK } from "unjwt/jwk";

// #region docs
import { defineJWESession } from "unjwt/session";

// #hide const key = the "oct" JWK from SESSION_KEY (see Configure a session)
const key = await generateJWK("A256GCM");
// #endhide

/** The header the page sends and the response answers with: `x-<name>-session`. */
const SESSION_HEADER = "x-unjwt-jwe-session";

export const webSession = defineJWESession<{ userId: string }, "1h">({
  key,
  maxAge: "1h",
  rolling: "15m",
  sessionHeader: true,
});

/** Call once your own credential check has passed: the cookie for the browser, the token for the page. */
export async function signIn(req: Request, userId: string) {
  const headers = new Headers();
  const session = await webSession.use({ req, res: { headers } });
  await session.update({ userId });
  return Response.json({ token: session.token }, { headers });
}

/** Any later request: when the token changed, the page gets the new one to mirror. */
export async function profile(req: Request) {
  const headers = new Headers();
  const session = await webSession.use({ req, res: { headers } });
  if (!session.id) return new Response("Sign in first", { status: 401, headers });
  if (session.token && session.token !== req.headers.get(SESSION_HEADER)) {
    headers.set(SESSION_HEADER, session.token);
  }
  return Response.json({ userId: session.data.userId, source: session.source }, { headers });
}
// #endregion
