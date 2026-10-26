import { afterEach, describe, expect, it, vi } from "vitest";
import { get, login, nextCookie, post, sessionKeyJSON } from "./_http.ts";

const origin = "https://app.example.com";

async function load(key: string | undefined) {
  vi.resetModules();
  vi.stubEnv("SESSION_KEY", key);
  const { app } = await import("../../../examples/recipes/h3.ts");
  return app;
}

afterEach(() => {
  vi.unstubAllEnvs();
  vi.useRealTimers();
});

describe("examples/recipes/h3", () => {
  it("signs in, reads the session, signs out", async () => {
    const app = await load(await sessionKeyJSON());

    const signedIn = await app.fetch(login(origin, "user_1a2b"));
    expect(signedIn.status).toBe(200);
    expect(await signedIn.json()).toEqual({ user: "user_1a2b" });
    const [line = ""] = signedIn.headers.getSetCookie();
    expect(line).toMatch(/^__Host-unjwt-jws=ey/);
    expect(line).toMatch(/Path=\//);
    expect(line).toMatch(/HttpOnly/);
    expect(line).toMatch(/Secure/);
    expect(line).toMatch(/SameSite=Lax/);
    const cookie = nextCookie(signedIn);

    const me = await app.fetch(get(`${origin}/me`, cookie));
    expect(me.status).toBe(200);
    expect(await me.json()).toEqual({ user: "user_1a2b" });

    const profile = await app.fetch(get(`${origin}/account/profile`, cookie));
    expect(profile.status).toBe(200);
    expect(await profile.json()).toMatchObject({ user: "user_1a2b" });

    const signedOut = await app.fetch(post(`${origin}/logout`, cookie));
    expect(signedOut.status).toBe(200);
    expect(signedOut.headers.getSetCookie()[0]).toMatch(/^__Host-unjwt-jws=;.*Max-Age=0/);
    const after = nextCookie(signedOut, cookie);
    expect(after).toBe("");

    expect((await app.fetch(get(`${origin}/me`, after))).status).toBe(401);
  });

  it("answers 401 without a cookie, on the route and behind the middleware", async () => {
    const app = await load(await sessionKeyJSON());
    expect((await app.fetch(get(`${origin}/me`))).status).toBe(401);
    expect((await app.fetch(get(`${origin}/account/profile`))).status).toBe(401);
  });

  it("refuses a login without a user", async () => {
    const app = await load(await sessionKeyJSON());
    const response = await app.fetch(
      new Request(`${origin}/login`, { method: "POST", body: "{}" }),
    );
    expect(response.status).toBe(400);
    expect(response.headers.getSetCookie()).toEqual([]);
  });

  it("answers 401 for an expired session and drops its cookie", async () => {
    vi.useFakeTimers({ toFake: ["Date"] });
    const app = await load(await sessionKeyJSON());
    const cookie = nextCookie(await app.fetch(login(origin, "user_1a2b")));

    vi.setSystemTime(Date.now() + 2 * 60 * 60 * 1000);
    const me = await app.fetch(get(`${origin}/me`, cookie));
    expect(me.status).toBe(401);
    expect(me.headers.getSetCookie()[0]).toMatch(/^__Host-unjwt-jws=;.*Max-Age=0/);
  });

  it("rolls a session read after 15 minutes onto a fresh hour", async () => {
    vi.useFakeTimers({ toFake: ["Date"] });
    const app = await load(await sessionKeyJSON());
    const cookie = nextCookie(await app.fetch(login(origin, "user_1a2b")));

    vi.setSystemTime(Date.now() + 20 * 60 * 1000);
    const me = await app.fetch(get(`${origin}/me`, cookie));
    expect(me.status).toBe(200);
    expect(nextCookie(me, cookie)).not.toBe(cookie);
  });

  it("answers 401 for a cookie signed with another key, and drops it", async () => {
    const other = await load(await sessionKeyJSON());
    const cookie = nextCookie(await other.fetch(login(origin, "user_1a2b")));

    const app = await load(await sessionKeyJSON());
    const me = await app.fetch(get(`${origin}/me`, cookie));
    expect(me.status).toBe(401);
    expect(me.headers.getSetCookie()[0]).toMatch(/^__Host-unjwt-jws=;.*Max-Age=0/);
  });

  it("fails at start-up without a key", async () => {
    await expect(load(undefined)).rejects.toThrow("SESSION_KEY is not set");
    await expect(load("")).rejects.toThrow("SESSION_KEY is not set");
  });

  it("answers 500 on the first request when the key is not a usable JWK", async () => {
    const app = await load(JSON.stringify({ kty: "oct" }));
    const response = await app.fetch(get(`${origin}/me`));
    expect(response.status).toBe(500);
  });
});
