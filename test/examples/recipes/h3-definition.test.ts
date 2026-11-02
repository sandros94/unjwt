import { afterEach, describe, expect, it, vi } from "vitest";
import { get, login, nextCookie, sessionKeyJSON } from "./_http.ts";

const origin = "https://app.example.com";

async function load() {
  vi.resetModules();
  vi.stubEnv("SESSION_KEY", await sessionKeyJSON());
  const { app } = await import("../../../examples/recipes/h3-definition.ts");
  const { appSession } = await import("../../../examples/recipes/h3.ts");
  return { app, appSession };
}

function check(token?: string): Request {
  return new Request(`${origin}/internal/session-check`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ token }),
  });
}

afterEach(() => {
  vi.unstubAllEnvs();
  vi.unstubAllGlobals();
  vi.useRealTimers();
});

describe("examples/recipes/h3-definition", () => {
  it("passes the cookie's token on unopened", async () => {
    const { app } = await load();
    const upstream = vi.fn(async (_url: string, _init?: RequestInit) =>
      Response.json({ visits: 12 }),
    );
    vi.stubGlobal("fetch", upstream);

    const cookie = nextCookie(await app.fetch(login(origin, "user_1a2b")));
    const reports = await app.fetch(get(`${origin}/reports`, cookie));
    expect(reports.status).toBe(200);
    expect(await reports.json()).toEqual({ visits: 12 });
    const [url, init] = upstream.mock.calls[0];
    expect(url).toBe("https://reports.example.com/v1/summary");
    expect(new Headers(init?.headers).get("authorization")).toBe(
      `Bearer ${cookie.slice(cookie.indexOf("=") + 1)}`,
    );

    await app.fetch(get(`${origin}/reports`, "__Host-unjwt-jws=not-a-token"));
    expect(new Headers(upstream.mock.calls[1][1]?.headers).get("authorization")).toBe(
      "Bearer not-a-token",
    );
  });

  it("answers 401 on /reports without a cookie and calls nothing", async () => {
    const { app } = await load();
    const upstream = vi.fn();
    vi.stubGlobal("fetch", upstream);
    expect((await app.fetch(get(`${origin}/reports`))).status).toBe(401);
    expect(upstream).not.toHaveBeenCalled();
  });

  it("issues a 15-minute token for a signed-in user and opens it as a token source", async () => {
    const { app, appSession } = await load();
    const cookie = nextCookie(await app.fetch(login(origin, "user_1a2b")));

    const issued = await app.fetch(
      new Request(`${origin}/api-token`, { method: "POST", headers: { cookie } }),
    );
    expect(issued.status).toBe(200);
    expect(issued.headers.getSetCookie()).toEqual([]);
    const { token } = (await issued.json()) as { token: string };

    const opened = await appSession.open(token);
    expect(opened.source).toBe("token");
    expect(opened.data).toEqual({ user: "user_1a2b" });
    expect(opened.expiresAt - opened.createdAt).toBe(15 * 60 * 1000);

    const valid = await app.fetch(check(token));
    expect(await valid.json()).toEqual({
      valid: true,
      user: "user_1a2b",
      expiresAt: opened.expiresAt,
    });
  });

  it("answers 401 on /api-token without a session", async () => {
    const { app } = await load();
    const response = await app.fetch(new Request(`${origin}/api-token`, { method: "POST" }));
    expect(response.status).toBe(401);
  });

  it("reports a missing, changed, foreign or expired token as not valid", async () => {
    vi.useFakeTimers({ toFake: ["Date"] });
    const other = await load();
    const foreign = await other.appSession.issue({ user: "user_1a2b" });
    const { app, appSession } = await load();
    const token = await appSession.issue({ user: "user_1a2b" }, { maxAge: "15m" });

    expect(await (await app.fetch(check())).json()).toEqual({ valid: false });
    expect(await (await app.fetch(check(`${token}x`))).json()).toEqual({ valid: false });
    expect(await (await app.fetch(check(foreign))).json()).toEqual({ valid: false });

    vi.setSystemTime(Date.now() + 20 * 60 * 1000);
    expect(await (await app.fetch(check(token))).json()).toEqual({ valid: false });
  });
});
