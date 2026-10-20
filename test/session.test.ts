import { describe, it, expect, expectTypeOf, vi } from "vitest";

import { isJWTError } from "../src/core/error.ts";
import { generateJWK } from "../src/core/jwk.ts";
import { sign } from "../src/core/jws.ts";
import { encrypt } from "../src/core/jwe.ts";
import {
  type CookieJar,
  type SessionContext,
  type SessionDefinition,
  type SessionDriver,
  type SessionManager,
  defineJWESession,
  defineJWSSession,
  defineSessionDriver,
} from "../src/session/index.ts";

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
      const written = await session.use({ req: get(), res: { headers } });
      await written.update({ user: "ada" });

      const [line = ""] = headers.getSetCookie();
      expect(line.startsWith(`web=${written.token}`)).toBe(true);
      expect(line).toContain("Path=/");
      expect(line).toContain("Secure");
      expect(line).toContain("SameSite=Lax");
      expect(line.includes("HttpOnly")).toBe(family === "jwe");

      const read = await session.use({ req: get({ cookie: replay(headers) }) });
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
      const manager = await session.use({ req: get(), res: { headers } });

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
      const manager = await session.use({ req: get(), res: { headers } });

      await manager.update({ pad: "x".repeat(400) });
      const count = chunkCount(headers);
      expect(count).toBeGreaterThan(2);
      for (let index = 1; index <= count; index++) {
        expect(linesOf(headers, `web.${index}`)).toHaveLength(1);
      }
      const read = await session.use({ req: get({ cookie: replay(headers) }) });
      expect(read.data).toEqual({ pad: "x".repeat(400) });

      await manager.update({ pad: "" });
      const shorter = chunkCount(headers);
      expect(shorter).toBeLessThan(count);
      for (let index = shorter + 1; index <= count; index++) {
        expect(linesOf(headers, `web.${index}`)).toEqual([expect.stringContaining("Max-Age=0")]);
      }
      const reread = await session.use({ req: get({ cookie: replay(headers) }) });
      expect(reread.data).toEqual({ pad: "" });
    },
  );

  it.each(FAMILIES)("$family: is read-only without response headers", async ({ define }) => {
    const session = define();
    const token = await session.issue({ user: "ada" });
    const manager = await session.use({ req: get({ cookie: `web=${token}` }) });

    expect(manager.data).toEqual({ user: "ada" });
    const update = await caught(manager.update({}));
    expect(isJWTError(update, "ERR_SESSION_READONLY_EVENT")).toBe(true);
    expect((update as Error).message).toBe(
      "[unjwt/session] Cannot update session on read-only event.",
    );

    const headerOnly = define({ cookie: false });
    const reissued = await headerOnly.use({ req: get({ "x-web-session": token }) });
    await reissued.update({ user: "grace" });
    expect(reissued.token).toBeTypeOf("string");
    expect(reissued.token).not.toBe(token);
    expect((await headerOnly.open(String(reissued.token))).data).toEqual({ user: "grace" });
  });

  it.each(FAMILIES)(
    "$family: clear() without response headers empties the session for the request",
    async ({ family, define }) => {
      const onClear = vi.fn();
      const lookup = vi.fn(() => (family === "jws" ? jwsKey : jweKey));
      const session = define({
        hooks: {
          onClear,
          ...(family === "jws" ? { onVerifyKeyLookup: lookup } : { onUnsealKeyLookup: lookup }),
        },
      });
      const request = get({ cookie: `web=${await session.issue({ user: "ada" })}` });
      const manager = await session.use({ req: request });
      const id = manager.id;

      expect(await caught(manager.clear())).toBeUndefined();
      expect(onClear).toHaveBeenCalledOnce();
      expect(onClear.mock.calls[0]?.[0]).toMatchObject({ oldSession: { id } });
      expect(manager.id).toBeUndefined();

      const again = await session.use({ req: request });
      expect(again.id).toBeUndefined();
      expect(again.data).toEqual({});
      expect(lookup).toHaveBeenCalledOnce();
      expect(isJWTError(await caught(again.update({})), "ERR_SESSION_READONLY_EVENT")).toBe(true);
    },
  );

  it.each(FAMILIES)(
    "$family: an onRead hook clears a revoked session without response headers",
    async ({ define }) => {
      const revoked = new Set<string | undefined>();
      const session = define({
        hooks: {
          onRead: async ({ session: current }: { session: SessionManager }) => {
            if (revoked.has(current.id)) await current.clear();
          },
        },
      });
      const token = await session.issue({ user: "ada" });
      revoked.add((await session.open(token)).id);

      const manager = await session.use({ req: get({ cookie: `web=${token}` }) });
      expect(manager.id).toBeUndefined();
      expect(manager.data).toEqual({});
    },
  );

  it.each(FAMILIES)("$family: reads the configured session header", async ({ define }) => {
    const token = await define().issue({ user: "ada" });

    const bearer = define({ cookie: false, sessionHeader: "authorization" });
    const viaBearer = await bearer.use({ req: get({ authorization: `Bearer ${token}` }) });
    expect(viaBearer.data).toEqual({ user: "ada" });

    const named = define({ sessionHeader: true });
    const viaNamed = await named.use({
      req: get({ "x-web-session": token }),
      res: { headers: new Headers() },
    });
    expect(viaNamed.data).toEqual({ user: "ada" });
  });

  it.each(FAMILIES)("$family: keeps the state of each Request apart", async ({ define }) => {
    const session = define();
    const request = get();
    const headers = new Headers();
    const first = await session.use({ req: request, res: { headers } });
    await first.update({ user: "ada" });

    const other = await session.use({ req: get(), res: { headers: new Headers() } });
    expect(other.id).toBeUndefined();

    const again = await session.use({ req: request, res: { headers } });
    expect(again.id).toBe(first.id);
    expect(again.data).toEqual({ user: "ada" });
  });

  it.each(FAMILIES)(
    "$family: keeps the state on the event's context when it has one",
    async ({ define }) => {
      const session = define();
      const context: Record<string, unknown> = {};
      const request = get();
      const headers = new Headers();
      const first = await session.use({ req: request, res: { headers }, context });
      await first.update({ user: "ada" });
      expect(context.sessions).toBeTypeOf("object");

      const again = await session.use({ req: request, context });
      expect(again.id).toBe(first.id);

      const elsewhere = await session.use({ req: get(), context });
      expect(elsewhere.id).toBe(first.id);
    },
  );

  it.each(FAMILIES)(
    "$family: reads a bare Request, and a headers-only object with its context",
    async ({ define }) => {
      const session = define();
      const token = await session.issue({ user: "ada" });
      const request = get({ cookie: `web=${token}` });

      const direct = await session.use(request);
      expect(direct.data).toEqual({ user: "ada" });
      expect(isJWTError(await caught(direct.update({})), "ERR_SESSION_READONLY_EVENT")).toBe(true);
      expect((await session.use(request)).id).toBe(direct.id);

      const context: Record<string, unknown> = {};
      const upgrade = { headers: request.headers, url: "/ws", context };
      const atUpgrade = await session.use(upgrade);
      expect(atUpgrade.id).toBe(direct.id);
      const peer = await session.use({ headers: request.headers, context });
      expect(peer.id).toBe(direct.id);
    },
  );

  it.each(FAMILIES)(
    "$family: a headers-only request with a res writes, as a WebSocket upgrade returns its headers",
    async ({ family, define }) => {
      const session = define({ maxAge: 3600, rolling: "15m" });
      const issuedAt = nowSeconds() - 20 * 60;
      const old = await foreignToken(family, {
        jti: "old",
        iat: issuedAt,
        exp: issuedAt + 3600,
        user: "ada",
      });
      const headers = new Headers();
      const upgrade = { headers: new Headers({ cookie: `web=${old}` }), url: "/ws", context: {} };
      const rolled = await session.use({ ...upgrade, res: { headers } });
      expect(rolled.data).toEqual({ user: "ada" });
      expect(rolled.token).not.toBe(old);
      expect(linesOf(headers, "web")).toEqual([expect.stringContaining(`web=${rolled.token}`)]);

      await rolled.clear();
      expect(linesOf(headers, "web")).toEqual([expect.stringContaining("Max-Age=0")]);
    },
  );

  it.each(FAMILIES)(
    "$family: refuses a runtime event whose req is not a web Request",
    async ({ define }) => {
      const h3v1Like = { req: { headers: { cookie: "web=x" } }, context: {} };
      const error = await caught(define().use(h3v1Like as never));
      expect(isJWTError(error, "ERR_SESSION_CONFIG_INVALID")).toBe(true);
      expect((error as Error).message).toContain('got an event whose "req" is not a web Request');
    },
  );

  it("refuses a JWS and a JWE under one name on one Request, and allows them on two", async () => {
    const jws = defineJWSSession({ name: "web", key: jwsKey });
    const jwe = defineJWESession({ name: "web", key: jweKey });
    const request = get();
    await jws.use({ req: request });
    const error = await caught(jwe.use({ req: request }));
    expect(isJWTError(error, "ERR_SESSION_CONFIG_INVALID")).toBe(true);
    expect((await jwe.use({ req: get() })).id).toBeUndefined();
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
    expectTypeOf<{ req: Request }>().toExtend<SessionContext>();
    expectTypeOf<{ req: Request; headers: Headers }>().toExtend<SessionContext>();
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
