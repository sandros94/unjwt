import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { generateJWK } from "unjwt/jwk";

async function load() {
  vi.resetModules();
  vi.stubEnv("SESSION_KEY", JSON.stringify(await generateJWK("A256GCM")));
  const handlers = await import("../../../examples/sessions/handlers.ts");
  const { appSession } = await import("../../../examples/sessions/app-session.ts");
  return { ...handlers, appSession };
}

function request(cookie?: string): Request {
  return new Request("https://app.example.com/", { headers: cookie ? { cookie } : {} });
}

function cookieOf(response: Response): string {
  return response.headers
    .getSetCookie()
    .map((line) => line.split(";", 1)[0])
    .join("; ");
}

async function codeOf(promise: Promise<unknown>): Promise<string | undefined> {
  try {
    await promise;
    return undefined;
  } catch (error) {
    return (error as { code?: string }).code;
  }
}

let app: Awaited<ReturnType<typeof load>>;
beforeEach(async () => {
  app = await load();
});
afterEach(() => {
  vi.unstubAllEnvs();
});

describe("examples/sessions/handlers", () => {
  it("signs in, reads, updates and signs out", async () => {
    const signIn = await app.signIn(request(), { id: "user_1a2b", role: "member" });
    const cookie = cookieOf(signIn);
    expect(cookie).toMatch(/^__Host-unjwt-jwe=/);
    expect(typeof (await signIn.json()).expiresAt).toBe("number");

    const profile = await app.profile(request(cookie));
    expect(profile.status).toBe(200);
    expect(await profile.json()).toEqual({ userId: "user_1a2b", role: "member" });
    expect(profile.headers.getSetCookie()).toEqual([]);

    const switched = await app.switchWorkspace(request(cookie), "ws_9f8e");
    expect(switched.status).toBe(204);
    const next = cookieOf(switched);
    expect(next).not.toBe(cookie);
    expect(await (await app.profile(request(next))).json()).toEqual({
      userId: "user_1a2b",
      role: "member",
      workspaceId: "ws_9f8e",
    });

    const signOut = await app.signOut(request(next));
    const [line = ""] = signOut.headers.getSetCookie();
    expect(line).toMatch(/^__Host-unjwt-jwe=;/);
    expect(line).toContain("Max-Age=0");
  });

  it("answers 401 without a session, and for a tampered cookie, which it also drops", async () => {
    expect((await app.profile(request())).status).toBe(401);
    const signIn = await app.signIn(request(), { id: "user_1a2b", role: "member" });
    const tampered = `${cookieOf(signIn).slice(0, -4)}AAAA`;
    const response = await app.profile(request(tampered));
    expect(response.status).toBe(401);
    expect(response.headers.getSetCookie()[0]).toContain("Max-Age=0");
  });

  it("signs out a request without a session too", async () => {
    const response = await app.signOut(request());
    expect(response.status).toBe(204);
    expect(response.headers.getSetCookie()[0]).toContain("Max-Age=0");
  });

  it("re-mints a token in hand and hands it back; a bad one gives null", async () => {
    const token = await app.appSession.issue({ userId: "user_1a2b", role: "member" });
    const { session } = await app.renew({ session: token });
    expect(session).toEqual(expect.any(String));
    expect(session).not.toBe(token);
    expect((await app.appSession.open(String(session))).data).toEqual({
      userId: "user_1a2b",
      role: "member",
    });
    expect(await app.renew({ session: "not-a-token" })).toEqual({ session: null });
  });

  it("a Request alone is read-only: update() throws, clear() empties the session", async () => {
    const cookie = cookieOf(await app.signIn(request(), { id: "user_1a2b", role: "member" }));
    const session = await app.appSession.use(request(cookie));
    expect(session.data.userId).toBe("user_1a2b");
    expect(await codeOf(session.update({ role: "admin" }))).toBe("ERR_SESSION_READONLY_EVENT");
    await session.clear();
    expect(session.id).toBeUndefined();
    expect(session.data).toEqual({});
  });

  it("update() takes a function of the current data, and a maxAge for one token", async () => {
    const headers = new Headers();
    const session = await app.appSession.use({ req: request(), res: { headers } });
    await session.update({ userId: "user_1a2b", role: "member" });
    await session.update((data) => (data.role === "member" ? { role: "admin" } : undefined));
    expect(session.data.role).toBe("admin");
    await session.update(undefined, { maxAge: "15m" });
    expect(session.expiresAt - session.createdAt).toBe(15 * 60 * 1000);
    expect(session.data).toEqual({ userId: "user_1a2b", role: "admin" });
  });

  it("strips reserved claims and refuses data that is not a plain object", async () => {
    const session = await app.appSession.use({ req: request(), res: { headers: new Headers() } });
    await session.update({ userId: "user_1a2b", role: "member", exp: 1, jti: "x" } as never);
    expect(session.data).toEqual({ userId: "user_1a2b", role: "member" });
    expect(await codeOf(session.update(["user_1a2b"] as never))).toBe("ERR_INVALID_OPTION");
  });

  it("a write after the Response was built does not reach it", async () => {
    const headers = new Headers();
    const session = await app.appSession.use({ req: request(), res: { headers } });
    const response = new Response(null, { headers });
    await session.update({ userId: "user_1a2b", role: "member" });
    expect(response.headers.getSetCookie()).toEqual([]);
    expect(headers.getSetCookie()).toHaveLength(1);
  });

  it("token() returns the request's token unopened", async () => {
    const signIn = await app.signIn(request(), { id: "user_1a2b", role: "member" });
    const [, token] = cookieOf(signIn).split("=");
    expect(app.appSession.token(request(cookieOf(signIn)))).toBe(token);
    expect(app.appSession.token(request("__Host-unjwt-jwe=garbage"))).toBe("garbage");
  });
});
