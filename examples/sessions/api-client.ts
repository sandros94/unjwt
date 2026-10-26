import { generateJWK } from "unjwt/jwk";

// #region docs
import { type SessionDefinition, defineJWSSession } from "unjwt/session";

// #hide const key = an HS256 JWK loaded at start-up (see Configure a session)
const key = await generateJWK("HS256");
// #endhide

export interface ApiSession {
  accountId: string;
  scope: "read" | "write";
}

export const apiSession: SessionDefinition<ApiSession, "1h"> = defineJWSSession({
  key,
  maxAge: "1h",
  cookie: false,
  sessionHeader: "x-acme-session",
});
// #endregion

// #region handlers
/** `POST /login` with `{ clientId, clientSecret }`: the token goes back in the body. */
export async function login(req: Request): Promise<Response> {
  const { clientId, clientSecret } = await req.json();
  const account = await findServiceAccount(clientId, clientSecret);
  if (!account) return Response.json({ error: "invalid_client" }, { status: 401 });
  const token = await apiSession.issue({ accountId: account.id, scope: account.scope });
  return Response.json({ token });
}

/** `GET /me`: the client sends `x-acme-session: Bearer <token>`. */
export async function me(req: Request): Promise<Response> {
  const session = await apiSession.use({ req });
  if (!session.id) return Response.json({ error: "unauthorized" }, { status: 401 });
  return Response.json(session.data);
}

/** `POST /refresh`: a fresh hour on a new token, which the client keeps in place of the old one. */
export async function refresh(req: Request): Promise<Response> {
  const session = await apiSession.use({ req });
  if (!session.id) return Response.json({ error: "unauthorized" }, { status: 401 });
  await session.update();
  return Response.json({ token: session.token, expiresAt: session.expiresAt });
}

/** `POST /logout`: the client deletes its copy; the token itself stays valid until it expires. */
export async function logout(req: Request): Promise<Response> {
  const session = await apiSession.use({ req });
  await session.clear();
  return new Response(null, { status: 204 });
}
// #endregion

// #region client
/** The command-line side: sign in once, keep the token, send it on every call. */
export function acmeClient(options: { baseUrl: string; fetch?: typeof fetch }): {
  login: (clientId: string, clientSecret: string) => Promise<void>;
  refresh: () => Promise<void>;
  logout: () => Promise<void>;
  me: () => Promise<Response>;
} {
  const send = options.fetch ?? fetch;
  let token: string | undefined;

  const call = (path: string, init: RequestInit = {}): Promise<Response> => {
    const headers = new Headers(init.headers);
    if (token) headers.set("x-acme-session", `Bearer ${token}`);
    return send(new URL(path, options.baseUrl), { ...init, headers });
  };

  return {
    async login(clientId: string, clientSecret: string): Promise<void> {
      const body = JSON.stringify({ clientId, clientSecret });
      const response = await call("/login", { method: "POST", body });
      if (!response.ok) throw new Error(`login failed: ${response.status}`);
      ({ token } = await response.json());
    },
    async refresh(): Promise<void> {
      const response = await call("/refresh", { method: "POST" });
      if (response.ok) ({ token } = await response.json());
    },
    async logout(): Promise<void> {
      await call("/logout", { method: "POST" });
      token = undefined;
    },
    me: () => call("/me"),
  };
}
// #endregion

/** Stands in for the application's table of service accounts. */
const accounts = new Map([
  ["ci-deploy", { id: "acct_7f3e", secret: "s3cr3t-from-the-vault", scope: "write" as const }],
]);

async function findServiceAccount(
  clientId: unknown,
  clientSecret: unknown,
): Promise<{ id: string; scope: "read" | "write" } | undefined> {
  const account = typeof clientId === "string" ? accounts.get(clientId) : undefined;
  return account && account.secret === clientSecret ? account : undefined;
}
