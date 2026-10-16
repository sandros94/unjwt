import { describe, it, expect, expectTypeOf, vi } from "vitest";

import { isJWTError } from "../src/core/error";
import { generateJWK } from "../src/core/jwk";
import { sign } from "../src/core/jws";
import { encrypt } from "../src/core/jwe";
import {
  type CookieJar,
  type SessionContext,
  type SessionDefinition,
  type SessionDriver,
  type SessionManager,
  defineJWESession,
  defineJWSSession,
  defineSessionDriver,
} from "../src/adapters/web";

const [jwsKey, jweKey] = await Promise.all([generateJWK("HS256"), generateJWK("A128KW")]);

const nowSeconds = () => Math.floor(Date.now() / 1000);

type Family = "jws" | "jwe";
type Definition = SessionDefinition<SessionContext, Record<string, unknown>>;

interface FamilyCase {
  family: Family;
  define: (config?: Record<string, unknown>) => Definition;
}

const FAMILIES: FamilyCase[] = [
  {
    family: "jws",
    define: (config) => defineJWSSession({ name: "web", key: jwsKey, ...config }),
  },
  {
    family: "jwe",
    define: (config) => defineJWESession({ name: "web", key: jweKey, ...config }),
  },
];

describe("unjwt/session over a Web request", () => {
  it.each(FAMILIES)(
    "$family: writes the cookie with the codec defaults and reads it back",
    async ({ family, define }) => {
      const session = define();
      const headers = new Headers();
      const written = await session.use({ request: get(), headers });
      await written.update({ user: "ada" });

      const [line = ""] = headers.getSetCookie();
      expect(line.startsWith(`web=${written.token}`)).toBe(true);
      expect(line).toContain("Path=/");
      expect(line).toContain("Secure");
      expect(line).toContain("SameSite=Lax");
      expect(line.includes("HttpOnly")).toBe(family === "jwe");

      const read = await session.use({ request: get({ cookie: replay(headers) }) });
      expect(read.id).toBe(written.id);
      expect(read.data).toEqual({ user: "ada" });
    },
  );

  it.each(FAMILIES)(
    "$family: replaces its own Set-Cookie line and keeps the others",
    async ({ define }) => {
      const session = define();
      const headers = new Headers();
      headers.append("set-cookie", "theme=dark; Path=/");
      const manager = await session.use({ request: get(), headers });

      await manager.update({ step: 1 });
      const first = manager.token;
      await manager.update({ step: 2 });

      expect(linesOf(headers, "web")).toEqual([expect.stringContaining(`web=${manager.token}`)]);
      expect(headers.getSetCookie()).toContain("theme=dark; Path=/");

      await manager.clear();
      const [cleared = ""] = linesOf(headers, "web");
      expect(linesOf(headers, "web")).toHaveLength(1);
      expect(cleared).toContain("Max-Age=0");
      expect(cleared).not.toContain(first);
      expect(cleared).not.toContain(String(manager.token));
    },
  );

  it.each(FAMILIES)(
    "$family: chunks a long token over Headers and expires the surplus",
    async ({ define }) => {
      const session = define({ cookie: { chunkMaxLength: 64 } });
      const headers = new Headers();
      const manager = await session.use({ request: get(), headers });

      await manager.update({ pad: "x".repeat(400) });
      const count = chunkCount(headers);
      expect(count).toBeGreaterThan(2);
      for (let index = 1; index <= count; index++) {
        expect(linesOf(headers, `web.${index}`)).toHaveLength(1);
      }
      const read = await session.use({ request: get({ cookie: replay(headers) }) });
      expect(read.data).toEqual({ pad: "x".repeat(400) });

      await manager.update({ pad: "" });
      const shorter = chunkCount(headers);
      expect(shorter).toBeLessThan(count);
      for (let index = shorter + 1; index <= count; index++) {
        expect(linesOf(headers, `web.${index}`)).toEqual([expect.stringContaining("Max-Age=0")]);
      }
      const reread = await session.use({ request: get({ cookie: replay(headers) }) });
      expect(reread.data).toEqual({ pad: "" });
    },
  );

  it.each(FAMILIES)("$family: is read-only without response headers", async ({ define }) => {
    const session = define();
    const token = await session.issue({ user: "ada" });
    const manager = await session.use({ request: get({ cookie: `web=${token}` }) });

    expect(manager.data).toEqual({ user: "ada" });
    expect(isJWTError(await caught(manager.update({})), "ERR_SESSION_READONLY_EVENT")).toBe(true);
    expect(isJWTError(await caught(manager.clear()), "ERR_SESSION_READONLY_EVENT")).toBe(true);

    const headerOnly = define({ cookie: false });
    const reissued = await headerOnly.use({ request: get({ "x-web-session": token }) });
    await reissued.update({ user: "grace" });
    expect(reissued.token).toBeTypeOf("string");
    expect(reissued.token).not.toBe(token);
    expect((await headerOnly.open(String(reissued.token))).data).toEqual({ user: "grace" });
  });

  it.each(FAMILIES)("$family: reads the configured session header", async ({ define }) => {
    const token = await define().issue({ user: "ada" });

    const bearer = define({ cookie: false, sessionHeader: "authorization" });
    const viaBearer = await bearer.use({ request: get({ authorization: `Bearer ${token}` }) });
    expect(viaBearer.data).toEqual({ user: "ada" });

    const named = define({ sessionHeader: true });
    const viaNamed = await named.use({
      request: get({ "x-web-session": token }),
      headers: new Headers(),
    });
    expect(viaNamed.data).toEqual({ user: "ada" });
  });

  it.each(FAMILIES)("$family: keeps the state of each Request apart", async ({ define }) => {
    const session = define();
    const request = get();
    const headers = new Headers();
    const first = await session.use({ request, headers });
    await first.update({ user: "ada" });

    const other = await session.use({ request: get(), headers: new Headers() });
    expect(other.id).toBeUndefined();

    const again = await session.use({ request, headers });
    expect(again.id).toBe(first.id);
    expect(again.data).toEqual({ user: "ada" });
  });

  it("refuses a JWS and a JWE under one name on one Request, and allows them on two", async () => {
    const jws = defineJWSSession({ name: "web", key: jwsKey });
    const jwe = defineJWESession({ name: "web", key: jweKey });
    const request = get();
    await jws.use({ request });
    const error = await caught(jwe.use({ request }));
    expect(isJWTError(error, "ERR_SESSION_CONFIG_INVALID")).toBe(true);
    expect((await jwe.use({ request: get() })).id).toBeUndefined();
  });
});

describe("unjwt/session with a token in hand", () => {
  const CONFIGS = [
    { label: "token only", config: { cookie: false, sessionHeader: false } },
    { label: "cookie", config: {} },
  ];
  const cases = FAMILIES.flatMap((family) =>
    CONFIGS.map(({ label, config }) => ({ ...family, label, config })),
  );

  it.each(cases)("$family, $label: reads, re-mints and clears", async ({ define, config }) => {
    const onRead = vi.fn();
    const session = define({ ...config, hooks: { onRead } });
    const token = await session.issue({ user: "ada" });
    const context: SessionContext = { token };

    expect(session.token(context)).toBe(token);
    const manager = await session.use(context);
    expect(manager.data).toEqual({ user: "ada" });
    expect(manager.token).toBe(token);
    expect(onRead).toHaveBeenCalledOnce();
    expect(onRead.mock.calls[0]?.[0]).toMatchObject({ context });

    await manager.update({ user: "grace" });
    expect(manager.token).not.toBe(token);
    expect((await session.open(String(manager.token))).data).toEqual({ user: "grace" });

    await manager.clear();
    expect(manager.id).toBeUndefined();
    expect(manager.token).toBeUndefined();
  });

  it.each(cases)("$family, $label: no token is an empty session", async ({ define, config }) => {
    const manager = await define(config).use({ token: undefined });
    expect(manager.id).toBeUndefined();
    expect(manager.token).toBeUndefined();
    await manager.update({ user: "ada" });
    expect(manager.token).toBeTypeOf("string");
  });

  it.each(cases)("$family, $label: rolls a handed token", async ({ define, config }) => {
    const onUpdate = vi.fn();
    const session = define({ ...config, maxAge: 60, rolling: true, hooks: { onUpdate } });
    const token = await session.issue({ user: "ada" });
    const manager = await session.use({ token });

    expect(onUpdate).toHaveBeenCalledOnce();
    expect(onUpdate.mock.calls[0]?.[0]).toMatchObject({ trigger: "rolling" });
    expect(manager.token).not.toBe(token);
    expect(manager.data).toEqual({ user: "ada" });
  });

  it.each(cases)(
    "$family, $label: reports an expired token to onExpire and garbage to onError",
    async ({ family, define, config }) => {
      const onExpire = vi.fn();
      const onError = vi.fn();
      const session = define({ ...config, hooks: { onExpire, onError } });

      const expired = await foreignToken(family, {
        jti: "gone",
        iat: nowSeconds() - 120,
        exp: nowSeconds() - 60,
      });
      const afterExpiry = await session.use({ token: expired });
      expect(afterExpiry.id).toBeUndefined();
      expect(onExpire).toHaveBeenCalledOnce();
      expect(onExpire.mock.calls[0]?.[0]).toMatchObject({
        session: { id: "gone", token: expired },
      });

      const afterGarbage = await session.use({ token: "garbage" });
      expect(afterGarbage.id).toBeUndefined();
      expect(onError).toHaveBeenCalledOnce();
      expect(isJWTError(onError.mock.calls[0]?.[0]?.error, "ERR_SESSION_TOKEN_INVALID")).toBe(true);
    },
  );
});

describe("defineSessionDriver", () => {
  interface PlainContext {
    locals: Record<string, unknown>;
    headers: Record<string, string>;
    cookies: Map<string, string>;
  }

  const plainDriver = defineSessionDriver<PlainContext>({
    prefix: "[plain]",
    state: (context) => context.locals,
    header: (context, name) => context.headers[name],
    cookies: (context): CookieJar => ({
      read: (name) => context.cookies.get(name),
      write: (name, value, attrs) => {
        if (attrs.maxAge === 0) context.cookies.delete(name);
        else context.cookies.set(name, value);
      },
    }),
  });

  const plain = (cookies = new Map<string, string>()): PlainContext => ({
    locals: {},
    headers: {},
    cookies,
  });

  it.each(["jws", "jwe"] as const)("%s: reads and writes through the driver", async (family) => {
    const onRead = vi.fn();
    const session =
      family === "jws"
        ? defineJWSSession({ key: jwsKey, hooks: { onRead } }, { driver: plainDriver })
        : defineJWESession({ key: jweKey, hooks: { onRead } }, { driver: plainDriver });
    const cookies = new Map<string, string>();

    const written = await session.use(plain(cookies));
    await written.update({ user: "ada" });
    expect(cookies.get(`unjwt-${family}`)).toBe(written.token);

    const context = plain(cookies);
    const read = await session.use(context);
    expect(read.data).toEqual({ user: "ada" });
    expect(onRead).toHaveBeenCalledOnce();
    expect(onRead.mock.calls[0]?.[0]?.context).toBe(context);

    await read.clear();
    expect(cookies.has(`unjwt-${family}`)).toBe(false);
  });

  it("types the context from the driver, and as SessionContext without one", () => {
    expectTypeOf(plainDriver).toEqualTypeOf<SessionDriver<PlainContext>>();

    const custom = defineJWSSession(
      {
        key: jwsKey,
        hooks: {
          onRead: ({ context }) => {
            expectTypeOf(context).toEqualTypeOf<PlainContext>();
          },
        },
      },
      { driver: plainDriver },
    );
    expectTypeOf(custom.use).parameter(0).toEqualTypeOf<PlainContext>();

    const web = defineJWESession({
      key: jweKey,
      hooks: {
        onRead: ({ context }) => {
          expectTypeOf(context).toEqualTypeOf<SessionContext>();
        },
      },
    });
    expectTypeOf(web.use).parameter(0).toEqualTypeOf<SessionContext>();
  });
});

describe("unjwt/session types", () => {
  it("carries the data and maxAge generics to the manager", () => {
    const session = defineJWESession<{ userId: string }, "7D">({ key: jweKey, maxAge: "7D" });
    expectTypeOf(session.use({ token: undefined })).toEqualTypeOf<
      Promise<SessionManager<{ userId: string }, "7D">>
    >();
  });

  it("takes a request or a token as its context, never an empty object", () => {
    expectTypeOf<{ request: Request }>().toExtend<SessionContext>();
    expectTypeOf<{ request: Request; headers: Headers }>().toExtend<SessionContext>();
    expectTypeOf<{ token: string }>().toExtend<SessionContext>();
    expectTypeOf<{ token: undefined }>().toExtend<SessionContext>();
    expectTypeOf<{}>().not.toExtend<SessionContext>();
  });
});

function get(headers: Record<string, string> = {}): Request {
  return new Request("http://localhost/", { headers });
}

/** The `Cookie` header a browser sends back after a response with these `Set-Cookie` lines. */
function replay(headers: Headers): string {
  return headers
    .getSetCookie()
    .filter((line) => !/max-age=0/i.test(line))
    .map((line) => line.split(";", 1)[0])
    .join("; ");
}

function linesOf(headers: Headers, name: string): string[] {
  return headers.getSetCookie().filter((line) => line.startsWith(`${name}=`));
}

function chunkCount(headers: Headers): number {
  const [line = ""] = linesOf(headers, "web");
  const match = /^web=__chunked__(\d+)/.exec(line);
  return match ? Number(match[1]) : 0;
}

async function caught(promise: Promise<unknown>): Promise<unknown> {
  try {
    await promise;
  } catch (error) {
    return error;
  }
  return undefined;
}

/** A session-shaped token sealed with the session key, minted outside the session. */
function foreignToken(family: Family, claims: Record<string, unknown>): Promise<string> {
  const options = { protectedHeader: { typ: "session+jwt" } };
  return family === "jws" ? sign(claims, jwsKey, options) : encrypt(claims, jweKey, options);
}
