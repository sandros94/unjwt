// #region docs
import { defineJWSSession } from "unjwt/session";
import type { JWK_oct } from "unjwt";

const json = process.env.SESSION_JWK;
if (!json) throw new Error("SESSION_JWK is not set");
const key: JWK_oct<"HS256"> = JSON.parse(json);

const appSession = defineJWSSession<{ user: string }>({ key, maxAge: "7D" });

export async function handle(request: Request) {
  const headers = new Headers();
  const session = await appSession.use({ req: request, res: { headers } });
  const { pathname } = new URL(request.url);

  if (request.method === "POST" && pathname === "/login") {
    // #hide Check the credentials against your user store first
    const user = "user_1a2b";
    // #endhide
    await session.update({ user });
    return Response.json({ user }, { headers });
  }
  if (pathname === "/me") {
    if (!session.id) return Response.json({ error: "Not signed in" }, { status: 401, headers });
    return Response.json({ user: session.data.user }, { headers });
  }
  if (request.method === "POST" && pathname === "/logout") {
    await session.clear();
    return new Response(null, { status: 204, headers });
  }
  return new Response("Not found", { status: 404, headers });
}
// #endregion
