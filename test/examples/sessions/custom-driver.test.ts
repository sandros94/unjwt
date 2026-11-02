import { describe, expect, it } from "vitest";
import type { CookieAttributes } from "unjwt/session";
import { type AppEvent, appSession } from "../../../examples/sessions/custom-driver.ts";

type Jar = Map<string, { value: string; options: CookieAttributes }>;

/** A stand-in framework: request cookies plus the ones this response set. */
function eventFor(cookies: Record<string, string> = {}): AppEvent & { written: Jar } {
  const written: Jar = new Map();
  return {
    request: new Request("https://app.example.com/"),
    locals: {},
    written,
    sent: false,
    cookies: {
      get: (name) => (written.has(name) ? written.get(name)?.value || undefined : cookies[name]),
      set: (name, value, options) => void written.set(name, { value, options }),
    },
  };
}

function carried(jar: Jar): Record<string, string> {
  return Object.fromEntries([...jar].filter(([, c]) => c.value).map(([n, c]) => [n, c.value]));
}

async function codeOf(promise: Promise<unknown>): Promise<string | undefined> {
  try {
    await promise;
    return undefined;
  } catch (error) {
    return (error as { code?: string }).code;
  }
}

describe("examples/sessions/custom-driver", () => {
  it("writes through the framework's cookies and reads them on the next request", async () => {
    const first = eventFor();
    const session = await appSession.use(first);
    await session.update({ userId: "user_1a2b" });
    const cookie = first.written.get("__Host-unjwt-jwe");
    expect(cookie?.value).toBe(session.token);
    expect(cookie?.options).toMatchObject({
      path: "/",
      secure: true,
      httpOnly: true,
      sameSite: "lax",
    });
    expect(cookie?.options.expires).toBeInstanceOf(Date);

    const next = eventFor(carried(first.written));
    expect((await appSession.use(next)).data).toEqual({ userId: "user_1a2b" });
    expect(first.locals.sessions).toBeDefined();
  });

  it("shares one state across use() calls on the same event", async () => {
    const event = eventFor();
    const a = await appSession.use(event);
    await a.update({ userId: "user_1a2b" });
    const b = await appSession.use(event);
    expect(b.id).toBe(a.id);
  });

  it("refuses update() and clear() once the response was sent", async () => {
    const event = eventFor();
    const session = await appSession.use(event);
    event.sent = true;
    expect(await codeOf(session.update({ userId: "user_1a2b" }))).toBe(
      "ERR_SESSION_READONLY_EVENT",
    );
    expect(await codeOf(session.clear())).toBe("ERR_SESSION_READONLY_EVENT");
  });

  it("clear() writes an expired cookie", async () => {
    const first = eventFor();
    await (await appSession.use(first)).update({ userId: "user_1a2b" });
    const next = eventFor(carried(first.written));
    await (await appSession.use(next)).clear();
    expect(next.written.get("__Host-unjwt-jwe")).toMatchObject({
      value: "",
      options: { maxAge: 0 },
    });
  });
});
