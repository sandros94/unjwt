import { afterEach, describe, expect, it, vi } from "vitest";
import {
  DatabaseUnavailableError,
  appSession,
  failLookups,
  lookupCount,
  saveGrants,
} from "../../../examples/sessions/skip-roll.ts";

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
  failLookups();
  vi.useRealTimers();
});

describe("examples/sessions/skip-roll", () => {
  it("keeps the session as issued while the database is unavailable on a due roll, and rolls once it is back", async () => {
    vi.useFakeTimers({ toFake: ["Date"] });
    await saveGrants("user_1a2b", ["read"]);
    const cookie = await signIn("user_1a2b", ["read"]);
    const issued = await appSession.use(request(cookie));
    await saveGrants("user_1a2b", ["read", "write"]);

    vi.setSystemTime(Date.now() + DAY + 1000);
    failLookups(new DatabaseUnavailableError("database unreachable"));
    const held = new Headers();
    const session = await appSession.use({ req: request(cookie), res: { headers: held } });
    expect(session.token).toBe(issued.token);
    expect(session.id).toBe(issued.id);
    expect(session.expiresAt).toBe(issued.expiresAt);
    expect(session.data).toEqual(issued.data);
    expect(held.getSetCookie()).toEqual([]);

    failLookups();
    const headers = new Headers();
    const rolled = await appSession.use({ req: request(cookie), res: { headers } });
    expect(rolled.token).not.toBe(issued.token);
    expect(rolled.data.grants).toEqual(["read", "write"]);
    expect(headers.getSetCookie()).toHaveLength(1);
  });

  it("rejects the read on a lookup error other than an unavailable database", async () => {
    vi.useFakeTimers({ toFake: ["Date"] });
    await saveGrants("user_3c4d", ["read"]);
    const cookie = await signIn("user_3c4d", ["read"]);

    vi.setSystemTime(Date.now() + DAY + 1000);
    const error = new Error("unexpected row");
    failLookups(error);
    const headers = new Headers();
    await expect(appSession.use({ req: request(cookie), res: { headers } })).rejects.toBe(error);
    expect(headers.getSetCookie()).toEqual([]);
  });

  it("does not ask the database on a read between rolls", async () => {
    await saveGrants("user_5e6f", ["read"]);
    const cookie = await signIn("user_5e6f", ["read"]);
    const before = lookupCount();

    const headers = new Headers();
    const session = await appSession.use({ req: request(cookie), res: { headers } });
    expect(session.data.grants).toEqual(["read"]);
    expect(lookupCount()).toBe(before);
    expect(headers.getSetCookie()).toEqual([]);
  });
});
