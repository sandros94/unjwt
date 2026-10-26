import { afterEach, describe, expect, it, vi } from "vitest";
import { generateJWK } from "unjwt/jwk";
import { get, login, nextCookie, post, sessionKeyJSON } from "./_http.ts";

const origin = "https://app.example.com";

async function load(key: string | undefined) {
  vi.resetModules();
  vi.stubEnv("SESSION_KEY", key);
  const { handle } = await import("../../../examples/recipes/elysia.ts");
  return handle;
}

afterEach(() => {
  vi.unstubAllEnvs();
  vi.useRealTimers();
});

describe("examples/recipes/elysia", () => {
  it("signs in, reads the session, signs out", async () => {
    const handle = await load(await sessionKeyJSON());

    const signedIn = await handle(login(origin, "user_1a2b"));
    expect(signedIn.status).toBe(200);
    expect(await signedIn.json()).toEqual({ user: "user_1a2b" });
    const [line = ""] = signedIn.headers.getSetCookie();
    expect(line).toMatch(/^__Host-elysia-jws=ey/);
    expect(line).toMatch(/Secure/);
    expect(line).toMatch(/HttpOnly/);
    const cookie = nextCookie(signedIn);

    const me = await handle(get(`${origin}/me`, cookie));
    expect(me.status).toBe(200);
    expect(await me.json()).toEqual({ user: "user_1a2b" });

    const renamed = await handle(
      new Request(`${origin}/account/rename`, {
        method: "POST",
        headers: { "content-type": "application/json", cookie },
        body: JSON.stringify({ user: "user_3c4d" }),
      }),
    );
    expect(await renamed.json()).toEqual({ user: "user_3c4d" });
    const renamedCookie = nextCookie(renamed, cookie);
    const profile = await handle(get(`${origin}/account/profile`, renamedCookie));
    expect(await profile.json()).toMatchObject({ user: "user_3c4d" });

    const signedOut = await handle(post(`${origin}/logout`, renamedCookie));
    expect(signedOut.status).toBe(200);
    const after = nextCookie(signedOut, renamedCookie);
    expect(after).toBe("");
    expect((await handle(get(`${origin}/me`, after))).status).toBe(401);
  });

  it("answers 401 without a cookie on every guarded route", async () => {
    const handle = await load(await sessionKeyJSON());
    expect((await handle(get(`${origin}/me`))).status).toBe(401);
    expect((await handle(get(`${origin}/account/profile`))).status).toBe(401);
  });

  it("refuses a login without a user", async () => {
    const handle = await load(await sessionKeyJSON());
    const response = await handle(
      new Request(`${origin}/login`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: "{}",
      }),
    );
    expect(response.status).toBe(422);
    expect(response.headers.getSetCookie()).toEqual([]);
  });

  it("answers 401 for an expired session and drops its cookie", async () => {
    vi.useFakeTimers({ toFake: ["Date"] });
    const handle = await load(await sessionKeyJSON());
    const cookie = nextCookie(await handle(login(origin, "user_1a2b")));

    vi.setSystemTime(Date.now() + 2 * 60 * 60 * 1000);
    const me = await handle(get(`${origin}/me`, cookie));
    expect(me.status).toBe(401);
    expect(me.headers.getSetCookie().join("\n")).toMatch(/__Host-elysia-jws=;.*Max-Age=0/);
  });

  it("answers 401 for a cookie signed with another key", async () => {
    const other = await load(await sessionKeyJSON());
    const cookie = nextCookie(await other(login(origin, "user_1a2b")));
    const handle = await load(await sessionKeyJSON());
    expect((await handle(get(`${origin}/me`, cookie))).status).toBe(401);
  });

  it("fails at start-up without a key", async () => {
    await expect(load(undefined)).rejects.toThrow("SESSION_KEY is not set");
  });

  it("fails at start-up with ERR_SESSION_KEY_INVALID when the key is not a signing key", async () => {
    const { publicKey } = await generateJWK("ES256");
    await expect(load(JSON.stringify(publicKey))).rejects.toMatchObject({
      code: "ERR_SESSION_KEY_INVALID",
    });
  });

  it("answers 500 on every request when the key's secret cannot be decoded", async () => {
    const handle = await load(JSON.stringify({ kty: "oct", alg: "HS256", k: "not base64url!" }));
    expect((await handle(get(`${origin}/me`))).status).toBe(500);
    expect((await handle(post(`${origin}/logout`))).status).toBe(500);
  });
});
