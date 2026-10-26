import { appSession } from "./app-session.ts";

// #region sign-in
/** Call once your own credential check has passed. */
export async function signIn(
  req: Request,
  user: { id: string; role: "member" | "admin" },
): Promise<Response> {
  const headers = new Headers();
  const session = await appSession.use({ req, res: { headers } });
  await session.update({ userId: user.id, role: user.role });
  return Response.json({ expiresAt: session.expiresAt }, { headers });
}
// #endregion

// #region profile
export async function profile(req: Request): Promise<Response> {
  const headers = new Headers();
  const session = await appSession.use({ req, res: { headers } });
  if (!session.id) return new Response("Sign in first", { status: 401, headers });
  return Response.json(session.data, { headers });
}
// #endregion

// #region switch-workspace
export async function switchWorkspace(req: Request, workspaceId: string): Promise<Response> {
  const headers = new Headers();
  const session = await appSession.use({ req, res: { headers } });
  if (!session.id) return new Response("Sign in first", { status: 401, headers });
  await session.update({ workspaceId });
  return new Response(null, { status: 204, headers });
}
// #endregion

// #region sign-out
export async function signOut(req: Request): Promise<Response> {
  const headers = new Headers();
  const session = await appSession.use({ req, res: { headers } });
  await session.clear();
  return new Response(null, { status: 204, headers });
}
// #endregion

// #region token-in-hand
/** A desktop client keeps its token itself and sends it in each message. */
export async function renew(message: { session: string }): Promise<{ session: string | null }> {
  const session = await appSession.use({ token: message.session });
  if (!session.id) return { session: null };
  await session.update();
  return { session: session.token ?? null };
}
// #endregion
