import { afterEach, describe, expect, it, vi } from "vitest";
import { isJWTError } from "unjwt/error";
import { generateJWK } from "unjwt/jwk";
import { defineJWESession, defineJWSSession } from "unjwt/session";

const DAY = 24 * 60 * 60 * 1000;

async function load(key: string | undefined) {
  vi.resetModules();
  vi.stubEnv("SESSION_KEY", key);
  return import("../../../examples/sessions/app-session.ts");
}

function request(headers: Record<string, string> = {}): Request {
  return new Request("https://app.example.com/", { headers });
}

function cookiesOf(headers: Headers): string {
  return headers
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

function codeOfCall(call: () => unknown): string | undefined {
  try {
    call();
    return undefined;
  } catch (error) {
    return (error as { code?: string }).code;
  }
}

afterEach(() => {
  vi.unstubAllEnvs();
  vi.useRealTimers();
});

describe("examples/sessions/app-session", () => {
  it("refuses to load without SESSION_KEY", async () => {
    await expect(load(undefined)).rejects.toThrow("SESSION_KEY is not set");
  });

  it("writes a __Host-unjwt-jwe cookie with the default attributes and a 7 day expiry", async () => {
    const { appSession } = await load(JSON.stringify(await generateJWK("A256GCM")));
    const headers = new Headers();
    const session = await appSession.use({ req: request(), res: { headers } });
    expect(session.id).toBeUndefined();
    await session.update({ userId: "user_1a2b", role: "member" });

    const [line = ""] = headers.getSetCookie();
    expect(line.startsWith(`__Host-unjwt-jwe=${session.token}`)).toBe(true);
    for (const part of ["Path=/", "Expires=", "HttpOnly", "Secure", "SameSite=Lax"]) {
      expect(line).toContain(part);
    }
    expect(session.expiresAt - session.createdAt).toBe(7 * DAY);

    const read = await appSession.use(request({ cookie: cookiesOf(headers) }));
    expect(read.id).toBe(session.id);
    expect(read.data).toEqual({ userId: "user_1a2b", role: "member" });
  });

  it("reissues a token once it is a day old, not before", async () => {
    vi.useFakeTimers({ toFake: ["Date"] });
    const { appSession } = await load(JSON.stringify(await generateJWK("A256GCM")));
    const signIn = new Headers();
    await (
      await appSession.use({ req: request(), res: { headers: signIn } })
    ).update({
      userId: "user_1a2b",
      role: "member",
    });
    const cookie = cookiesOf(signIn);

    vi.setSystemTime(Date.now() + DAY / 2);
    const early = new Headers();
    await appSession.use({ req: request({ cookie }), res: { headers: early } });
    expect(early.getSetCookie()).toEqual([]);

    vi.setSystemTime(Date.now() + DAY);
    const late = new Headers();
    const rolled = await appSession.use({ req: request({ cookie }), res: { headers: late } });
    expect(late.getSetCookie()).toHaveLength(1);
    expect(rolled.expiresAt - Date.now()).toBeGreaterThan(6.9 * DAY);
  });

  it("refuses to load with ERR_SESSION_KEY_INVALID when SESSION_KEY holds a key pair half", async () => {
    const { privateKey } = await generateJWK("ECDH-ES");
    expect(await codeOf(load(JSON.stringify(privateKey)))).toBe("ERR_SESSION_KEY_INVALID");
  });

  it("loads a key whose secret is the wrong length, then fails the first use with ERR_SESSION_KEY_INVALID", async () => {
    const short = { kty: "oct", alg: "A256GCM", k: "c2hvcnQ" };
    const { appSession } = await load(JSON.stringify(short));
    expect(await codeOf(appSession.use(request()))).toBe("ERR_SESSION_KEY_INVALID");
  });
});

describe("Configure a session: inline settings", async () => {
  const key = await generateJWK("A256GCM");

  it("a plain name with secure: false writes a cookie without Secure", async () => {
    const devSession = defineJWESession({ key, name: "app-session", cookie: { secure: false } });
    const headers = new Headers();
    await (await devSession.use({ req: request(), res: { headers } })).update({ userId: "u" });
    const [line = ""] = headers.getSetCookie();
    expect(line.startsWith("app-session=")).toBe(true);
    expect(line).not.toContain("Secure");
  });

  it("a __Host- name with secure: false, a domain or another path is ERR_SESSION_CONFIG_INVALID", async () => {
    for (const cookie of [{ secure: false }, { domain: "example.com" }, { path: "/app" }]) {
      expect(codeOfCall(() => defineJWESession({ key, cookie }))).toBe(
        "ERR_SESSION_CONFIG_INVALID",
      );
    }
  });

  it("rolling without maxAge, or not shorter than it, is ERR_SESSION_CONFIG_INVALID", async () => {
    expect(codeOfCall(() => defineJWESession({ key, rolling: true }))).toBe(
      "ERR_SESSION_CONFIG_INVALID",
    );
    expect(codeOfCall(() => defineJWESession({ key, maxAge: "1h", rolling: "1h" }))).toBe(
      "ERR_SESSION_CONFIG_INVALID",
    );
  });

  it("maxAge ends a token at iat + maxAge even when its exp is later", async () => {
    vi.useFakeTimers({ toFake: ["Date"] });
    const long = defineJWESession({ key, maxAge: "30D" });
    const short = defineJWESession({ key, maxAge: "1D" });
    const token = await long.issue({ userId: "user_1a2b" });
    vi.setSystemTime(Date.now() + 2 * DAY);
    const expired: string[] = [];
    const reader = defineJWESession({
      key,
      maxAge: "1D",
      hooks: { onExpire: ({ error }) => void expired.push(isJWTError(error) ? error.code : "") },
    });
    const session = await reader.use({ token });
    expect(session.id).toBeUndefined();
    expect(expired).toEqual(["ERR_JWT_EXPIRED"]);
    expect(await codeOf(short.open(token))).toBe("ERR_JWT_EXPIRED");
  });

  it('sessionHeader: "authorization" reads a Bearer token first and writes no cookie', async () => {
    const apiSession = defineJWSSession({
      key: await generateJWK("HS256"),
      sessionHeader: "authorization",
    });
    const token = await apiSession.issue({ userId: "user_1a2b" });
    const headers = new Headers();
    const session = await apiSession.use({
      req: request({ authorization: `Bearer ${token}`, cookie: "__Host-unjwt-jws=stale" }),
      res: { headers },
    });
    expect(session.data).toEqual({ userId: "user_1a2b" });
    await session.update({ plan: "pro" });
    expect(session.token).not.toBe(token);
    expect(headers.getSetCookie()).toEqual([]);

    const basic = await apiSession.use(request({ authorization: "Basic dXNlcjpwYXNz" }));
    expect(basic.id).toBeUndefined();
  });

  it("sessionHeader: true reads x-<name>-session without the cookie prefix", async () => {
    const session = defineJWESession({ key, name: "__Host-app", sessionHeader: true });
    const token = await session.issue({ userId: "user_1a2b" });
    const read = await session.use(request({ "x-app-session": token }));
    expect(read.data).toEqual({ userId: "user_1a2b" });
  });

  it("cookie: false without a session header has no token source", async () => {
    const session = defineJWESession({ key, cookie: false });
    expect(await codeOf(session.use(request()))).toBe("ERR_SESSION_CONFIG_INVALID");
    expect(await session.issue({ userId: "user_1a2b" })).toMatch(/^[\w-]+(\.[\w-]*){4}$/);
  });

  it("a token past 16 chunks fails the update with ERR_SESSION_CONFIG_INVALID and rolls back", async () => {
    const session = defineJWESession({ key });
    const manager = await session.use({ req: request(), res: { headers: new Headers() } });
    await manager.update({ userId: "user_1a2b" });
    const id = manager.id;
    expect(await codeOf(manager.update({ notes: "x".repeat(70_000) }))).toBe(
      "ERR_SESSION_CONFIG_INVALID",
    );
    expect(manager.id).toBe(id);
    expect(manager.data).toEqual({ userId: "user_1a2b" });
  });

  it("splits a long token into name.1 … name.N behind a __chunked__N marker", async () => {
    const session = defineJWESession({ key, name: "app" });
    const headers = new Headers();
    const manager = await session.use({ req: request(), res: { headers } });
    await manager.update({ notes: "x".repeat(9_000) });
    const names = headers.getSetCookie().map((line) => line.split("=", 1)[0]);
    const count = Math.ceil(String(manager.token).length / 4000);
    expect(count).toBeGreaterThan(1);
    expect(names).toEqual(["app", ...Array.from({ length: count }, (_, i) => `app.${i + 1}`)]);
    expect(headers.getSetCookie()[0]).toMatch(new RegExp(`^app=__chunked__${count};`));
    const read = await session.use(request({ cookie: cookiesOf(headers) }));
    expect(read.id).toBe(manager.id);
  });

  it("a password string is ERR_SESSION_KEY_INVALID", async () => {
    // @ts-expect-error a string is not key material
    expect(codeOfCall(() => defineJWESession({ key: "correct horse battery staple" }))).toBe(
      "ERR_SESSION_KEY_INVALID",
    );
  });
});
