import { afterEach, describe, expect, it, vi } from "vitest";
import { sessionKeyJSON } from "./_http.ts";
import type { ExpressEvent } from "../../../examples/recipes/custom-driver.ts";

async function load(key: string | undefined) {
  vi.resetModules();
  vi.stubEnv("SESSION_KEY", key);
  return import("../../../examples/recipes/custom-driver.ts");
}

/** A hand-built Express `req`/`res` pair that records what the handler sends. */
function exchange(options: { cookie?: string; body?: unknown } = {}) {
  const headers = new Map<string, number | string | string[]>();
  const sent: { status?: number; body?: unknown } = {};
  const event: ExpressEvent = {
    req: { headers: options.cookie ? { cookie: options.cookie } : {}, body: options.body },
    res: {
      locals: {},
      headersSent: false,
      statusCode: 200,
      getHeader: (name) => headers.get(name.toLowerCase()),
      setHeader: (name, value) => headers.set(name.toLowerCase(), value),
      end(body) {
        sent.status = this.statusCode;
        sent.body = body === undefined ? undefined : JSON.parse(body);
        this.headersSent = true;
      },
    },
  };
  const setCookie = () => (headers.get("set-cookie") as string[] | undefined) ?? [];
  return { event, sent, setCookie };
}

/** The `Cookie` header a browser sends back: live cookies only. */
function cookieFrom(lines: string[]): string {
  return lines
    .filter((line) => !/Max-Age=0/.test(line))
    .map((line) => line.split(";", 1)[0])
    .join("; ");
}

afterEach(() => {
  vi.unstubAllEnvs();
  vi.useRealTimers();
});

describe("examples/recipes/custom-driver", () => {
  it("signs in, reads the session, signs out", async () => {
    const { login, me, logout } = await load(await sessionKeyJSON());

    const signIn = exchange({ body: { user: "user_1a2b" } });
    await login(signIn.event);
    expect(signIn.sent).toEqual({ status: 200, body: { user: "user_1a2b" } });
    const lines = signIn.setCookie();
    expect(lines).toHaveLength(1);
    expect(lines[0]).toMatch(
      /^__Host-unjwt-jws=ey[\w.-]+; Path=\/; Expires=.+ GMT; HttpOnly; Secure; SameSite=Lax$/,
    );
    const cookie = cookieFrom(lines);

    const read = exchange({ cookie });
    await me(read.event);
    expect(read.sent).toEqual({ status: 200, body: { user: "user_1a2b" } });
    expect(read.setCookie()).toEqual([]);

    const signOut = exchange({ cookie });
    await logout(signOut.event);
    expect(signOut.setCookie()[0]).toMatch(/^__Host-unjwt-jws=; Path=\/; Max-Age=0; Expires=/);
    const after = cookieFrom(signOut.setCookie());
    expect(after).toBe("");

    const again = exchange({ cookie: after });
    await me(again.event);
    expect(again.sent.status).toBe(401);
  });

  it("answers 401 without a cookie and 400 without a user", async () => {
    const { login, me } = await load(await sessionKeyJSON());
    const read = exchange();
    await me(read.event);
    expect(read.sent.status).toBe(401);
    const signIn = exchange({ body: {} });
    await login(signIn.event);
    expect(signIn.sent.status).toBe(400);
    expect(signIn.setCookie()).toEqual([]);
  });

  it("replaces its own Set-Cookie line and keeps the others", async () => {
    const { appSession } = await load(await sessionKeyJSON());
    const { event, setCookie } = exchange();
    event.res.setHeader("set-cookie", ["theme=dark; Path=/"]);
    const session = await appSession.use(event);
    await session.update({ user: "user_1a2b" });
    await session.update({ user: "user_3c4d" });
    const lines = setCookie();
    expect(lines).toHaveLength(2);
    expect(lines[0]).toBe("theme=dark; Path=/");
    expect(session.token).toBe(lines[1]?.split(";", 1)[0]?.split("=")[1]);
  });

  it("shares one session between two reads of one request", async () => {
    const { appSession } = await load(await sessionKeyJSON());
    const { event } = exchange();
    const first = await appSession.use(event);
    await first.update({ user: "user_1a2b" });
    const second = await appSession.use(event);
    expect(second.id).toBe(first.id);
  });

  it("refuses to update once the response was sent", async () => {
    const { appSession } = await load(await sessionKeyJSON());
    const { event } = exchange();
    const session = await appSession.use(event);
    event.res.headersSent = true;
    // `isJWTError` would compare against a second copy of the module here, after `vi.resetModules()`
    await expect(session.update({ user: "user_1a2b" })).rejects.toMatchObject({
      name: "JWTError",
      code: "ERR_SESSION_READONLY_EVENT",
      message: expect.stringMatching(/^\[express-session\]/),
    });
  });

  it("answers 401 for an expired session and drops its cookie", async () => {
    vi.useFakeTimers({ toFake: ["Date"] });
    const { login, me } = await load(await sessionKeyJSON());
    const signIn = exchange({ body: { user: "user_1a2b" } });
    await login(signIn.event);

    vi.setSystemTime(Date.now() + 2 * 60 * 60 * 1000);
    const read = exchange({ cookie: cookieFrom(signIn.setCookie()) });
    await me(read.event);
    expect(read.sent.status).toBe(401);
    expect(read.setCookie()[0]).toMatch(/^__Host-unjwt-jws=;.*Max-Age=0/);
  });

  it("fails at start-up without a key", async () => {
    await expect(load(undefined)).rejects.toThrow("SESSION_KEY is not set");
  });
});
