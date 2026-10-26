import { afterEach, describe, expect, it, vi } from "vitest";
import {
  acmeClient,
  apiSession,
  login,
  logout,
  me,
  refresh,
} from "../../../examples/sessions/api-client.ts";

const API = "https://api.example.com";

function post(path: string, options: { token?: string; body?: unknown } = {}): Request {
  return new Request(`${API}${path}`, {
    method: "POST",
    headers: options.token ? { "x-acme-session": `Bearer ${options.token}` } : {},
    body: options.body === undefined ? undefined : JSON.stringify(options.body),
  });
}

function getMe(header?: string): Request {
  return new Request(`${API}/me`, { headers: header ? { "x-acme-session": header } : {} });
}

async function tokenOf(response: Response): Promise<string> {
  return ((await response.json()) as { token: string }).token;
}

const CREDENTIALS = { clientId: "ci-deploy", clientSecret: "s3cr3t-from-the-vault" };

/** Routes the client's calls to the handlers, the way the server would. */
const server: typeof fetch = async (input, init) => {
  const req = new Request(input, init);
  const routes: Record<string, (req: Request) => Promise<Response>> = {
    "POST /login": login,
    "GET /me": me,
    "POST /refresh": refresh,
    "POST /logout": logout,
  };
  const route = routes[`${req.method} ${new URL(req.url).pathname}`];
  return route ? route(req) : new Response("Not found", { status: 404 });
};

afterEach(() => {
  vi.useRealTimers();
});

describe("examples/sessions/api-client", () => {
  it("answers a login with the token in the body and no cookie", async () => {
    const response = await login(post("/login", { body: CREDENTIALS }));
    expect(response.status).toBe(200);
    expect(response.headers.getSetCookie()).toEqual([]);
    expect((await apiSession.open(await tokenOf(response))).data).toEqual({
      accountId: "acct_7f3e",
      scope: "write",
    });

    const refused = await login(post("/login", { body: { ...CREDENTIALS, clientSecret: "x" } }));
    expect(refused.status).toBe(401);
  });

  it("reads the token from the header, bare or as Bearer", async () => {
    const token = await tokenOf(await login(post("/login", { body: CREDENTIALS })));
    for (const header of [token, `Bearer ${token}`, `bearer ${token}`]) {
      const response = await me(getMe(header));
      expect(response.status).toBe(200);
      expect(await response.json()).toEqual({ accountId: "acct_7f3e", scope: "write" });
    }
    const session = await apiSession.use({ headers: new Headers({ "x-acme-session": token }) });
    expect(session.source).toBe("header");
    expect(session.data.accountId).toBe("acct_7f3e");
  });

  it("refreshes onto a new token in the body, and writes no cookie", async () => {
    const token = await tokenOf(await login(post("/login", { body: CREDENTIALS })));
    vi.useFakeTimers({ toFake: ["Date"] });
    vi.setSystemTime(Date.now() + 10 * 60 * 1000);
    const response = await refresh(post("/refresh", { token }));
    expect(response.headers.getSetCookie()).toEqual([]);
    const { token: next, expiresAt } = (await response.json()) as {
      token: string;
      expiresAt: number;
    };
    expect(next).not.toBe(token);
    const opened = await apiSession.open(next);
    expect(opened.data).toEqual({ accountId: "acct_7f3e", scope: "write" });
    expect(opened.expiresAt).toBe(expiresAt);
    expect(opened.expiresAt).toBeGreaterThan((await apiSession.open(token)).expiresAt);
  });

  it("logs out without a cookie; the old token opens until it expires", async () => {
    const token = await tokenOf(await login(post("/login", { body: CREDENTIALS })));
    const response = await logout(post("/logout", { token }));
    expect(response.status).toBe(204);
    expect(response.headers.getSetCookie()).toEqual([]);
    expect((await me(getMe(token))).status).toBe(200);
  });

  it("refuses a missing, malformed, tampered or expired header, and a cookie", async () => {
    const token = await tokenOf(await login(post("/login", { body: CREDENTIALS })));
    expect((await me(getMe())).status).toBe(401);
    expect((await me(getMe(`Basic ${token}`))).status).toBe(401);
    expect((await me(getMe(`${token.slice(0, -4)}AAAA`))).status).toBe(401);
    const withCookie = new Request(`${API}/me`, {
      headers: { cookie: `__Host-unjwt-jws=${token}` },
    });
    expect((await me(withCookie)).status).toBe(401);

    vi.useFakeTimers({ toFake: ["Date"] });
    vi.setSystemTime(Date.now() + 61 * 60 * 1000);
    expect((await me(getMe(token))).status).toBe(401);
  });

  it("a request without the header is an empty header session that update() issues onto", async () => {
    const session = await apiSession.use({ req: getMe() });
    expect(session.source).toBe("header");
    expect(session.id).toBeUndefined();
    await session.update({ accountId: "acct_7f3e", scope: "read" });
    expect((await apiSession.open(String(session.token))).data.scope).toBe("read");
  });

  it("the command-line client signs in, calls, refreshes and logs out", async () => {
    const cli = acmeClient({ baseUrl: API, fetch: server });
    expect((await cli.me()).status).toBe(401);

    await cli.login("ci-deploy", "s3cr3t-from-the-vault");
    expect(await (await cli.me()).json()).toEqual({ accountId: "acct_7f3e", scope: "write" });

    await cli.refresh();
    expect((await cli.me()).status).toBe(200);

    await cli.logout();
    expect((await cli.me()).status).toBe(401);
    await expect(cli.login("ci-deploy", "wrong")).rejects.toThrow("login failed: 401");
  });
});
