import { generateJWK } from "unjwt/jwk";

// #region docs
import { isJWTError } from "unjwt/error";
import { defineJWESession } from "unjwt/session";
import { appSession } from "./app-session.ts";

// #hide const linkKey = a second "oct" JWK, loaded like SESSION_KEY
const linkKey = await generateJWK("A256GCM");
// #endhide

const magicLink = defineJWESession<{ email: string }, "15m">({
  key: linkKey,
  maxAge: "15m",
  cookie: false,
  sessionHeader: false,
});

/** The link to email; it signs in whoever opens it within 15 minutes. */
export async function magicLinkFor(email: string) {
  const url = new URL("https://app.example.com/auth/callback");
  url.searchParams.set("token", await magicLink.issue({ email }));
  return url;
}

/** `GET /auth/callback?token=…`: opens the link token, then starts the app session. */
export async function redeemMagicLink(req: Request) {
  const token = new URL(req.url).searchParams.get("token");
  if (!token) return new Response("Missing token", { status: 400 });

  let email: string;
  try {
    ({ email } = (await magicLink.open(token)).data);
  } catch (error) {
    if (isJWTError(error)) return new Response("This link is invalid or expired", { status: 401 });
    throw error;
  }

  const user = await findUserByEmail(email);
  const headers = new Headers({ location: "/" });
  const session = await appSession.use({ req, res: { headers } });
  await session.update({ userId: user.id, role: user.role });
  return new Response(null, { status: 303, headers });
}
// #endregion

/** Stands in for the application's user lookup. */
async function findUserByEmail(email: string): Promise<{ id: string; role: "member" }> {
  return { id: `user_${email.split("@")[0]}`, role: "member" };
}
