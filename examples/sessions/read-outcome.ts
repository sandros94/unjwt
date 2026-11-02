// #region docs
import { appSession } from "./key-lookup.ts";

/** `GET /dashboard`: the visitor's data, a guest view, or why there is neither. */
export async function dashboard(req: Request) {
  const headers = new Headers();
  const session = await appSession.use({ req, res: { headers } });
  if (session.id) return Response.json({ userId: session.data.userId }, { headers });

  switch (session.error?.code) {
    case undefined:
      return Response.json({ guest: true }, { headers });
    case "ERR_SESSION_READ_FAILED":
      headers.set("retry-after", "5");
      return new Response("Sign-in is unavailable, try again shortly", { status: 503, headers });
    case "ERR_JWT_EXPIRED":
      return new Response("Your session expired, sign in again", { status: 401, headers });
    default:
      return new Response("Sign in again", { status: 401, headers });
  }
}
// #endregion
