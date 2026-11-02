import { afterEach, describe, expect, it, vi } from "vitest";
import { profile, signIn, webSession } from "../../../examples/sessions/mirrored-header.ts";

const APP = "https://app.example.com";
const NAME = "__Host-unjwt-jwe";
const HEADER = "x-unjwt-jwe-session";

function request(options: { cookie?: string; header?: string } = {}): Request {
  const headers = new Headers();
  if (options.cookie) headers.set("cookie", `${NAME}=${options.cookie}`);
  if (options.header) headers.set(HEADER, options.header);
  return new Request(`${APP}/profile`, { headers });
}

function cookieOf(response: Response): string | undefined {
  const line = response.headers.getSetCookie().find((entry) => entry.startsWith(`${NAME}=`));
  return line?.split(";", 1)[0]?.slice(NAME.length + 1);
}

async function signedIn(userId: string): Promise<{ cookie: string; token: string }> {
  const response = await signIn(request(), userId);
  const { token } = (await response.json()) as { token: string };
  return { cookie: String(cookieOf(response)), token };
}

afterEach(() => {
  vi.useRealTimers();
});

describe("examples/sessions/mirrored-header", () => {
  it("sign-in sets the cookie and hands the page the same token", async () => {
    const { cookie, token } = await signedIn("user_1a2b");
    expect(token).toBe(cookie);
  });

  it("a mirrored header equal to the cookie runs on the cookie", async () => {
    const { cookie, token } = await signedIn("user_1a2b");
    const response = await profile(request({ cookie, header: token }));
    expect(await response.json()).toEqual({ userId: "user_1a2b", source: "cookie" });
    expect(response.headers.get(HEADER)).toBeNull();
    expect(response.headers.getSetCookie()).toEqual([]);
  });

  it("a rolling reissue writes the cookie and hands the page the new token", async () => {
    const { cookie, token } = await signedIn("user_1a2b");
    vi.useFakeTimers({ toFake: ["Date"] });
    vi.setSystemTime(Date.now() + 16 * 60 * 1000);

    const response = await profile(request({ cookie, header: token }));
    const rolled = cookieOf(response);
    expect(rolled).toBeDefined();
    expect(rolled).not.toBe(cookie);
    expect(response.headers.get(HEADER)).toBe(rolled);

    const next = await profile(request({ cookie: rolled, header: String(rolled) }));
    expect(await next.json()).toEqual({ userId: "user_1a2b", source: "cookie" });
  });

  it("a page without its copy gets the token from the cookie session", async () => {
    const { cookie } = await signedIn("user_1a2b");
    const response = await profile(request({ cookie }));
    expect(response.headers.get(HEADER)).toBe(cookie);
  });

  it("a header holding another token runs on the header and leaves the cookie alone", async () => {
    const ada = await signedIn("user_ada");
    const grace = await signedIn("user_grace");
    vi.useFakeTimers({ toFake: ["Date"] });
    vi.setSystemTime(Date.now() + 16 * 60 * 1000);

    const response = await profile(request({ cookie: ada.cookie, header: grace.token }));
    expect(await response.json()).toEqual({ userId: "user_grace", source: "header" });
    expect(response.headers.getSetCookie()).toEqual([]);
    expect(response.headers.get(HEADER)).toBeNull();
  });

  it("a header session does not fall back to the cookie", async () => {
    const { cookie, token } = await signedIn("user_1a2b");
    const response = await profile(request({ cookie, header: `${token.slice(0, -4)}AAAA` }));
    expect(response.status).toBe(401);
    expect(response.headers.getSetCookie()).toEqual([]);
  });

  it("a cookie session read without a response cannot update, even with an equal header", async () => {
    const { cookie, token } = await signedIn("user_1a2b");
    const session = await webSession.use(request({ cookie, header: token }));
    expect(session.source).toBe("cookie");
    await expect(session.update({ userId: "user_3c4d" })).rejects.toMatchObject({
      code: "ERR_SESSION_READONLY_EVENT",
    });
  });
});
