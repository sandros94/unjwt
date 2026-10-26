import { afterEach, describe, expect, it, vi } from "vitest";
import { get, login, nextCookie, post, sessionKeyJSON } from "./_http.ts";

const origin = "https://app.example.com";

/** A fresh Worker isolate: the module, and the session it defines on its first request. */
async function worker(env: { SESSION_KEY?: string }) {
  vi.resetModules();
  const { default: app } = await import("../../../examples/recipes/hono.ts");
  return (request: Request) => app.fetch(request, env);
}

afterEach(() => {
  vi.useRealTimers();
});

describe("examples/recipes/hono", () => {
  it("signs in, reads the session, signs out", async () => {
    const fetch = await worker({ SESSION_KEY: await sessionKeyJSON() });

    const signedIn = await fetch(login(origin, "user_1a2b"));
    expect(signedIn.status).toBe(200);
    expect(await signedIn.json()).toEqual({ user: "user_1a2b" });
    const [line = ""] = signedIn.headers.getSetCookie();
    expect(line).toMatch(/^__Host-unjwt-jws=ey/);
    expect(line).toMatch(/Secure/);
    const cookie = nextCookie(signedIn);

    const me = await fetch(get(`${origin}/me`, cookie));
    expect(me.status).toBe(200);
    expect(await me.json()).toEqual({ user: "user_1a2b" });

    const signedOut = await fetch(post(`${origin}/logout`, cookie));
    expect(signedOut.status).toBe(200);
    expect(signedOut.headers.getSetCookie()[0]).toMatch(/^__Host-unjwt-jws=;.*Max-Age=0/);
    const after = nextCookie(signedOut, cookie);
    expect(after).toBe("");
    expect((await fetch(get(`${origin}/me`, after))).status).toBe(401);
  });

  it("answers 401 without a cookie, 400 without a user", async () => {
    const fetch = await worker({ SESSION_KEY: await sessionKeyJSON() });
    expect((await fetch(get(`${origin}/me`))).status).toBe(401);
    const response = await fetch(new Request(`${origin}/login`, { method: "POST", body: "{}" }));
    expect(response.status).toBe(400);
    expect(response.headers.getSetCookie()).toEqual([]);
  });

  it("answers 401 for an expired session and drops its cookie", async () => {
    vi.useFakeTimers({ toFake: ["Date"] });
    const fetch = await worker({ SESSION_KEY: await sessionKeyJSON() });
    const cookie = nextCookie(await fetch(login(origin, "user_1a2b")));

    vi.setSystemTime(Date.now() + 2 * 60 * 60 * 1000);
    const me = await fetch(get(`${origin}/me`, cookie));
    expect(me.status).toBe(401);
    expect(me.headers.getSetCookie()[0]).toMatch(/^__Host-unjwt-jws=;.*Max-Age=0/);
  });

  it("answers 500 on every request while the binding is missing", async () => {
    const fetch = await worker({});
    expect((await fetch(get(`${origin}/me`))).status).toBe(500);
  });
});
