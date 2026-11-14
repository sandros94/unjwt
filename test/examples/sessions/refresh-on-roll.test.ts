import { afterEach, describe, expect, it, vi } from "vitest";
import { appSession, saveUser } from "../../../examples/sessions/refresh-on-roll.ts";

const DAY = 24 * 60 * 60 * 1000;

function request(cookie?: string): Request {
  return new Request("https://app.example.com/", { headers: cookie ? { cookie } : {} });
}

function cookieOf(headers: Headers): string {
  return headers.getSetCookie()[0]?.split(";", 1)[0] ?? "";
}

async function signIn(userId: string, grants: string[]): Promise<string> {
  const headers = new Headers();
  await (await appSession.use({ req: request(), res: { headers } })).update({ userId, grants });
  return cookieOf(headers);
}

afterEach(() => {
  vi.useRealTimers();
});

describe("examples/sessions/refresh-on-roll", () => {
  it("keeps the grants between rolls and refreshes them in the one token a roll issues", async () => {
    vi.useFakeTimers({ toFake: ["Date"] });
    await saveUser("user_1a2b", { grants: ["read"], blocked: false });
    const cookie = await signIn("user_1a2b", ["read"]);
    await saveUser("user_1a2b", { grants: ["read", "write"], blocked: false });

    const early = new Headers();
    const before = await appSession.use({ req: request(cookie), res: { headers: early } });
    expect(before.data.grants).toEqual(["read"]);
    expect(early.getSetCookie()).toEqual([]);

    vi.setSystemTime(Date.now() + DAY + 1000);
    const headers = new Headers();
    const rolled = await appSession.use({ req: request(cookie), res: { headers } });
    expect(rolled.data.grants).toEqual(["read", "write"]);
    expect(headers.getSetCookie()).toHaveLength(1);

    const next = await appSession.use(request(cookieOf(headers)));
    expect(next.data).toMatchObject({ userId: "user_1a2b", grants: ["read", "write"] });
  });

  it("clears the session of a blocked user on any read", async () => {
    await saveUser("user_3c4d", { grants: ["read"], blocked: false });
    const cookie = await signIn("user_3c4d", ["read"]);
    await saveUser("user_3c4d", { grants: ["read"], blocked: true });

    const headers = new Headers();
    const session = await appSession.use({ req: request(cookie), res: { headers } });
    expect(session.id).toBeUndefined();
    expect(headers.getSetCookie()[0]).toContain("Max-Age=0");
  });

  it("keeps a token in hand as issued, since it never rolls", async () => {
    vi.useFakeTimers({ toFake: ["Date"] });
    await saveUser("user_5e6f", { grants: ["read"], blocked: false });
    const token = await appSession.issue({ userId: "user_5e6f", grants: ["read"] });
    await saveUser("user_5e6f", { grants: ["read", "write"], blocked: false });

    vi.setSystemTime(Date.now() + 2 * DAY);
    const session = await appSession.use({ token });
    expect(session.data.grants).toEqual(["read"]);
    expect(session.token).toBe(token);
  });
});
