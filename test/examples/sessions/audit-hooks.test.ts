import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { generateJWK } from "unjwt/jwk";
import { sign } from "unjwt/jws";
import { defineJWSSession } from "unjwt/session";
import { appSession, auditLog } from "../../../examples/sessions/audit-hooks.ts";

function request(cookie?: string): Request {
  return new Request("https://app.example.com/", { headers: cookie ? { cookie } : {} });
}

function cookiesOf(headers: Headers): string {
  return headers
    .getSetCookie()
    .map((line) => line.split(";", 1)[0])
    .join("; ");
}

async function errorOf(promise: Promise<unknown>): Promise<unknown> {
  try {
    await promise;
    return undefined;
  } catch (error) {
    return error;
  }
}

beforeEach(() => {
  auditLog.length = 0;
});
afterEach(() => {
  vi.useRealTimers();
});

describe("examples/sessions/audit-hooks", () => {
  it("records sign-in, one read per request, an update, a sign-out", async () => {
    const signIn = new Headers();
    await (
      await appSession.use({ req: request(), res: { headers: signIn } })
    ).update({
      userId: "user_1a2b",
    });
    const first = auditLog[0]?.[1];

    const headers = new Headers();
    const event = { req: request(cookiesOf(signIn)), res: { headers } };
    await appSession.use(event);
    const session = await appSession.use(event);
    await session.update({ userId: "user_1a2b" });
    const second = session.id;
    await session.clear();

    expect(auditLog).toEqual([
      ["issued", first, "-"],
      ["read", first],
      ["issued", second, first],
      ["signed out", second],
    ]);
  });

  it("records an expired token and a tampered one, each in place of the read", async () => {
    vi.useFakeTimers({ toFake: ["Date"] });
    const signIn = new Headers();
    await (
      await appSession.use({ req: request(), res: { headers: signIn } })
    ).update({
      userId: "user_1a2b",
    });
    const cookie = cookiesOf(signIn);
    const id = auditLog[0]?.[1];
    auditLog.length = 0;

    await appSession.use(request(`${cookie.slice(0, -4)}AAAA`));
    vi.setSystemTime(Date.now() + 2 * 60 * 60 * 1000);
    const headers = new Headers();
    await appSession.use({ req: request(cookie), res: { headers } });

    expect(auditLog).toEqual([
      ["refused", "-", "ERR_SESSION_TOKEN_INVALID"],
      ["expired", id],
    ]);
    expect(headers.getSetCookie()[0]).toContain("Max-Age=0");
  });
});

describe("Hooks: what a throw does", async () => {
  const key = await generateJWK("HS256");
  const boom = new Error("audit store unavailable");
  const fail = () => {
    throw boom;
  };

  it("onRead: use() rejects with the error", async () => {
    const session = defineJWSSession({ key, hooks: { onRead: fail } });
    const token = await session.issue({ userId: "user_1a2b" });
    expect(await errorOf(session.use({ token }))).toBe(boom);
  });

  it("onUpdate: update() rejects, the new token and cookie stay", async () => {
    const session = defineJWSSession({ key, hooks: { onUpdate: fail } });
    const headers = new Headers();
    const manager = await session.use({ req: request(), res: { headers } });
    expect(await errorOf(manager.update({ userId: "user_1a2b" }))).toBe(boom);
    expect(manager.id).toEqual(expect.any(String));
    expect(manager.data).toEqual({ userId: "user_1a2b" });
    expect(headers.getSetCookie()).toHaveLength(1);
  });

  it("onClear: clear() rejects, the session is already empty and the cookie expired", async () => {
    const session = defineJWSSession({ key, hooks: { onClear: fail } });
    const token = await session.issue({ userId: "user_1a2b" });
    const headers = new Headers();
    const manager = await session.use({
      req: request(`__Host-unjwt-jws=${token}`),
      res: { headers },
    });
    expect(await errorOf(manager.clear())).toBe(boom);
    expect(manager.id).toBeUndefined();
    expect(headers.getSetCookie()[0]).toContain("Max-Age=0");
  });

  it("onExpire and onError: use() rejects with the error", async () => {
    const now = Math.floor(Date.now() / 1000);
    const expired = await sign({ jti: "a1", iat: now - 7200, exp: now - 3600 }, key, {
      protectedHeader: { typ: "session+jwt" },
    });
    const onExpire = defineJWSSession({ key, maxAge: "1h", hooks: { onExpire: fail } });
    const onError = defineJWSSession({ key, hooks: { onError: fail } });
    expect(await errorOf(onExpire.use({ token: expired }))).toBe(boom);
    expect(await errorOf(onError.use({ token: "not-a-token" }))).toBe(boom);
  });

  it("onError on the write path: update() rethrows after the hook, data rolled back", async () => {
    const seen: string[] = [];
    const session = defineJWSSession({
      key,
      hooks: { onError: ({ error }) => void seen.push(error.code) },
    });
    const manager = await session.use({ req: request(), res: { headers: new Headers() } });
    await manager.update({ userId: "user_1a2b" });
    const error = await errorOf(manager.update({ notes: "x".repeat(70_000) }));
    expect((error as { code: string }).code).toBe("ERR_SESSION_CONFIG_INVALID");
    expect(seen).toEqual(["ERR_SESSION_CONFIG_INVALID"]);
    expect(manager.data).toEqual({ userId: "user_1a2b" });
  });

  it("a rolling reissue reaches onUpdate with trigger 'rolling', after onRead", async () => {
    vi.useFakeTimers({ toFake: ["Date"] });
    const order: string[] = [];
    const session = defineJWSSession({
      key,
      maxAge: "1h",
      rolling: "15m",
      hooks: {
        onRead: () => void order.push("onRead"),
        onUpdate: ({ trigger }) => void order.push(`onUpdate ${trigger}`),
      },
    });
    const token = await session.issue({ userId: "user_1a2b" });
    vi.setSystemTime(Date.now() + 16 * 60 * 1000);
    const headers = new Headers();
    await session.use({ req: request(`__Host-unjwt-jws=${token}`), res: { headers } });
    expect(order).toEqual(["onRead", "onUpdate rolling"]);
    expect(headers.getSetCookie()).toHaveLength(1);
  });

  it("a key lookup that throws keeps the cookie; a bad token drops it", async () => {
    const errors: unknown[] = [];
    const session = defineJWSSession({
      key,
      hooks: {
        onKeyLookup: fail,
        onError: ({ error }) => void errors.push(error),
      },
    });
    const token = await session.issue({ userId: "user_1a2b" });
    const kept = new Headers();
    await session.use({ req: request(`__Host-unjwt-jws=${token}`), res: { headers: kept } });
    expect(kept.getSetCookie()).toEqual([]);
    const dropped = new Headers();
    await session.use({ req: request("__Host-unjwt-jws=not-a-token"), res: { headers: dropped } });
    expect(dropped.getSetCookie()[0]).toContain("Max-Age=0");

    const [readFailed, invalid] = errors as Array<{ code: string; cause: unknown }>;
    expect(readFailed?.code).toBe("ERR_SESSION_READ_FAILED");
    expect(readFailed?.cause).toBe(boom);
    expect(invalid?.code).toBe("ERR_SESSION_TOKEN_INVALID");
    expect(((await errorOf(session.open(token))) as { code: string }).code).toBe(
      "ERR_SESSION_READ_FAILED",
    );
  });
});
