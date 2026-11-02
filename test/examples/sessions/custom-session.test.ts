import { afterEach, describe, expect, it, vi } from "vitest";
import { generateJWK } from "unjwt/jwk";
import { defineJWESession } from "unjwt/session";
import { appSession, defineStoredSession } from "../../../examples/sessions/custom-session.ts";

const APP = "https://app.example.com";
const NAME = "__Host-app";
const HEADER = "x-app-session";

function request(headers: Record<string, string> = {}): Request {
  return new Request(`${APP}/`, { headers });
}

/** The `Cookie` header a browser sends back after this response. */
function cookieFrom(headers: Headers): string {
  return headers
    .getSetCookie()
    .map((line) => line.split(";", 1)[0])
    .join("; ");
}

async function signedIn(userId: string): Promise<{ token: string; cookie: string }> {
  const headers = new Headers();
  const session = await appSession.use({ req: request(), res: { headers } });
  await session.update({ userId });
  return { token: String(session.token), cookie: cookieFrom(headers) };
}

function refusal(run: () => unknown): { code?: string; message?: string } {
  try {
    run();
    return {};
  } catch (error) {
    const { code, message } = error as { code?: string; message?: string };
    return { code, message };
  }
}

async function codeOf(promise: Promise<unknown>): Promise<string | undefined> {
  try {
    await promise;
    return undefined;
  } catch (error) {
    return (error as { code?: string }).code;
  }
}

afterEach(() => {
  vi.useRealTimers();
});

describe("examples/sessions/custom-session", () => {
  it("writes a random token to the cookie and reads the stored data back", async () => {
    const headers = new Headers();
    const first = await appSession.use({ req: request(), res: { headers } });
    expect(first.id).toBeUndefined();
    await first.update({ userId: "user_1a2b" });
    expect(first.token).toMatch(/^[\w-]{43}$/);
    expect(first.id).toMatch(/^[\da-f]{64}$/);
    expect(first.id).not.toBe(first.token);

    const [line = ""] = headers.getSetCookie();
    expect(line.startsWith(`${NAME}=${first.token};`)).toBe(true);
    for (const attribute of ["Path=/", "Secure", "HttpOnly", "SameSite=Lax", "Expires="]) {
      expect(line).toContain(attribute);
    }
    expect(line).not.toMatch(/max-age/i);

    const next = await appSession.use({ req: request({ cookie: cookieFrom(headers) }) });
    expect(next.source).toBe("cookie");
    expect(next.id).toBe(first.id);
    expect(next.token).toBe(first.token);
    expect(next.data).toEqual({ userId: "user_1a2b" });
  });

  it("refuses update() on a request read by its headers alone", async () => {
    const session = await appSession.use({ headers: new Headers() });
    expect(await codeOf(session.update({ userId: "user_1a2b" }))).toBe(
      "ERR_SESSION_READONLY_EVENT",
    );
  });

  it("reads the session header and writes no cookie", async () => {
    const { token } = await signedIn("user_1a2b");
    const headers = new Headers();
    const session = await appSession.use({
      req: request({ [HEADER]: `Bearer ${token}` }),
      res: { headers },
    });
    expect(session.source).toBe("header");
    expect(session.data).toEqual({ userId: "user_1a2b" });

    await session.update({ userId: "user_3c4d" });
    expect(session.token).not.toBe(token);
    expect(headers.getSetCookie()).toEqual([]);
    expect((await appSession.use({ token: session.token })).data).toEqual({ userId: "user_3c4d" });
    expect((await appSession.use({ token })).id).toBeUndefined();
  });

  it("clear() expires the cookie and forgets the session", async () => {
    const { cookie } = await signedIn("user_1a2b");
    const headers = new Headers();
    const session = await appSession.use({ req: request({ cookie }), res: { headers } });
    await session.clear();
    const [line = ""] = headers.getSetCookie();
    expect(line.startsWith(`${NAME}=;`)).toBe(true);
    expect(line).toContain("Max-Age=0");

    const after = await appSession.use({ req: request({ cookie }) });
    expect(after.id).toBeUndefined();
  });

  it("drops the cookie of a session past its maxAge", async () => {
    const { cookie } = await signedIn("user_1a2b");
    vi.useFakeTimers({ toFake: ["Date"] });
    vi.setSystemTime(Date.now() + 25 * 60 * 60 * 1000);
    const headers = new Headers();
    const session = await appSession.use({ req: request({ cookie }), res: { headers } });
    expect(session.id).toBeUndefined();
    expect(headers.getSetCookie()[0]).toContain("Max-Age=0");
  });

  it("refuses a JWE session of the same name on the same request", async () => {
    const jweSession = defineJWESession({ name: NAME, key: await generateJWK("A128KW") });
    const event = { req: request(), res: { headers: new Headers() }, context: {} };
    await appSession.use(event);
    expect(await codeOf(jweSession.use(event))).toBe("ERR_SESSION_CONFIG_INVALID");
  });

  it("refuses a __Host- name with secure: false when defined", () => {
    const { code, message = "" } = refusal(() =>
      defineStoredSession({ name: "__Host-app", cookie: { secure: false } }),
    );
    expect(code).toBe("ERR_SESSION_CONFIG_INVALID");
    expect(message.startsWith("[app-session] ")).toBe(true);
  });
});
