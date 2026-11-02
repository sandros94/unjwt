import { afterEach, describe, expect, it, vi } from "vitest";
import { generateJWK } from "unjwt/jwk";

async function load(json: string | undefined) {
  vi.resetModules();
  vi.stubEnv("SESSION_JWK", json);
  return import("../../../examples/getting-started/cookie-session.ts");
}

function call(method: string, path: string, cookie?: string): Request {
  return new Request(`https://app.example.com${path}`, {
    method,
    headers: cookie ? { cookie } : {},
  });
}

function cookieOf(response: Response): string {
  return response.headers.get("set-cookie")!.split(";")[0];
}

afterEach(() => {
  vi.unstubAllEnvs();
});

describe("examples/getting-started/cookie-session", () => {
  it("signs in, reads the session back, and signs out", async () => {
    const { handle } = await load(JSON.stringify(await generateJWK("HS256")));

    const login = await handle(call("POST", "/login"));
    expect(login.status).toBe(200);
    const setCookie = login.headers.get("set-cookie")!;
    expect(setCookie).toMatch(/^__Host-unjwt-jws=/);
    expect(setCookie).toContain("HttpOnly");
    expect(setCookie).toContain("Secure");

    const me = await handle(call("GET", "/me", cookieOf(login)));
    expect(await me.json()).toEqual({ user: "user_1a2b" });

    const logout = await handle(call("POST", "/logout", cookieOf(login)));
    expect(logout.status).toBe(204);
    expect(logout.headers.get("set-cookie")).toContain("Max-Age=0");
  });

  it("answers 401 without a session, or with a cookie signed by another key", async () => {
    const { handle } = await load(JSON.stringify(await generateJWK("HS256")));
    expect((await handle(call("GET", "/me"))).status).toBe(401);

    const other = await load(JSON.stringify(await generateJWK("HS256")));
    const login = await other.handle(call("POST", "/login"));
    const { handle: original } = await load(JSON.stringify(await generateJWK("HS256")));
    const foreign = await original(call("GET", "/me", cookieOf(login)));
    expect(foreign.status).toBe(401);
    expect(foreign.headers.get("set-cookie")).toContain("Max-Age=0");
  });

  it("fails at start-up when the key is missing", async () => {
    await expect(load(undefined)).rejects.toThrow("SESSION_JWK is not set");
  });
});
