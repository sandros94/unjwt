import { describe, it, expect, expectTypeOf, vi } from "vitest";

import type { ExpiresIn, JWEAsymmetricPrivateJWK } from "../src/core/types/index.ts";
import { isJWTError } from "../src/core/error.ts";
import { generateJWK, generateKey, importPEM } from "../src/core/jwk.ts";
import type { JWESessionKey } from "../src/session/_codec-jwe.ts";
import { rsa } from "./keys.ts";
import { sign } from "../src/core/jws.ts";
import { encrypt } from "../src/core/jwe.ts";
import {
  type CookieJar,
  type SessionDefinition,
  type SessionDriver,
  type SessionHandedToken,
  type SessionManager,
  type SessionRequestEvent,
  type WebSessionEvent,
  defineJWESession,
  defineJWSSession,
  defineSessionDriver,
} from "../src/session/index.ts";

const [jwsKey, jweKey] = await Promise.all([generateJWK("HS256"), generateJWK("A128KW")]);

const nowSeconds = () => Math.floor(Date.now() / 1000);

type Family = "jws" | "jwe";
type Definition = SessionDefinition<
  Record<string, unknown>,
  ExpiresIn | undefined,
  WebSessionEvent
>;

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
    "$family: keeps a context.sessions slot another library created, whatever its prototype",
    async ({ define }) => {
      const session = define();
      const sessions: Record<string, unknown> = Object.create(Object.create(null));
      sessions.other = { id: "theirs" };
      const context: Record<string, unknown> = { sessions };
      const manager = await session.use({ req: get(), res: { headers: new Headers() }, context });
      await manager.update({ user: "ada" });

      expect(context.sessions).toBe(sessions);
      expect(sessions.other).toEqual({ id: "theirs" });
    },
  );

  it.each(FAMILIES)(
    "$family: a request that also carries a token key is a request, and an empty object is refused",
    async ({ define }) => {
      const session = define();
      const token = await session.issue({ user: "ada" });
      const request = get({ cookie: `web=${token}` });

      const asRequest = await session.use({ req: request, token: "ignored" });
      expect(asRequest.data).toEqual({ user: "ada" });

      const error = await caught(session.use({} as never));
      expect(isJWTError(error, "ERR_SESSION_CONFIG_INVALID")).toBe(true);
      expect((error as Error).message).toContain("neither");
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

describe("unjwt/session token sources", () => {
  it.each(FAMILIES)(
    "$family: a session header the request presents wins over the cookie",
    async ({ define }) => {
      const session = define({ sessionHeader: true });
      const fromCookie = await session.issue({ who: "cookie" });
      const fromHeader = await session.issue({ who: "header" });

      const manager = await session.use({
        req: get({ "cookie": `web=${fromCookie}`, "x-web-session": `Bearer ${fromHeader}` }),
        res: { headers: new Headers() },
      });
      expect(manager.data).toEqual({ who: "header" });
      expect(manager.token).toBe(fromHeader);
    },
  );

  it.each(FAMILIES)(
    "$family: a malformed session header is a token failure that leaves the cookie alone",
    async ({ define }) => {
      const onError = vi.fn();
      const onRead = vi.fn();
      const session = define({ sessionHeader: true, hooks: { onError, onRead } });
      const fromCookie = await session.issue({ who: "cookie" });
      const headers = new Headers();
      const event = {
        req: get({ "cookie": `web=${fromCookie}`, "x-web-session": "Basic dXNlcjpwYXNz" }),
        res: { headers },
      };

      const manager = await session.use(event);
      expect(manager.id).toBeUndefined();
      expect(manager.data).toEqual({});
      expect(manager.token).toBeUndefined();
      expect(session.token(event)).toBeUndefined();
      expect(onRead).not.toHaveBeenCalled();
      expect(onError).toHaveBeenCalledOnce();
      const [{ error }] = onError.mock.calls[0] as [{ error: unknown }];
      expect(isJWTError(error, "ERR_SESSION_TOKEN_INVALID")).toBe(true);
      expect(headers.getSetCookie()).toEqual([]);
    },
  );

  it.each(FAMILIES)(
    "$family: a session read from the header rolls onto session.token, never a cookie",
    async ({ define }) => {
      const onUpdate = vi.fn();
      const session = define({ maxAge: 3600, rolling: true, hooks: { onUpdate } });
      const fromHeader = await session.issue({ who: "header" });
      const headers = new Headers();

      const manager = await session.use({
        req: get({ "x-web-session": fromHeader }),
        res: { headers },
      });
      expect(manager.data).toEqual({ who: "header" });
      expect(manager.token).toBeTypeOf("string");
      expect(manager.token).not.toBe(fromHeader);
      expect(onUpdate).toHaveBeenCalledOnce();
      expect(onUpdate.mock.calls[0]?.[0]).toMatchObject({ trigger: "rolling" });
      expect(headers.getSetCookie()).toEqual([]);
      expect((await session.open(String(manager.token))).data).toEqual({ who: "header" });
    },
  );

  it.each(FAMILIES)(
    "$family: update() and clear() on a header session write no cookie",
    async ({ define }) => {
      const onClear = vi.fn();
      const session = define({ hooks: { onClear } });
      const fromCookie = await session.issue({ who: "cookie" });
      const fromHeader = await session.issue({ who: "header" });
      const headers = new Headers();
      const event = {
        req: get({ "cookie": `web=${fromCookie}`, "x-web-session": fromHeader }),
        res: { headers },
      };

      const manager = await session.use(event);
      await manager.update({ who: "updated" });
      expect(manager.token).not.toBe(fromHeader);
      expect(session.token(event)).toBe(manager.token);
      expect((await session.open(String(manager.token))).data).toEqual({ who: "updated" });
      expect(headers.getSetCookie()).toEqual([]);

      await manager.clear();
      expect(manager.id).toBeUndefined();
      expect(manager.data).toEqual({});
      expect(manager.token).toBeUndefined();
      expect(session.token(event)).toBeUndefined();
      expect(onClear).toHaveBeenCalledOnce();
      expect(headers.getSetCookie()).toEqual([]);
    },
  );

  it.each(FAMILIES)(
    "$family: a header session updates without response headers",
    async ({ define }) => {
      const session = define();
      const fromHeader = await session.issue({ who: "header" });

      const manager = await session.use({ req: get({ "x-web-session": fromHeader }) });
      await manager.update({ who: "updated" });
      expect((await session.open(String(manager.token))).data).toEqual({ who: "updated" });
    },
  );

  it.each(FAMILIES)(
    "$family: without the session header the cookie is read",
    async ({ define }) => {
      const session = define({ sessionHeader: true });
      const fromCookie = await session.issue({ who: "cookie" });

      const manager = await session.use({ req: get({ cookie: `web=${fromCookie}` }) });
      expect(manager.data).toEqual({ who: "cookie" });
    },
  );
});

describe("unjwt/session bounds a token by maxAge", () => {
  const HOUR = 3600;
  const DAY = 24 * HOUR;

  it.each(FAMILIES)(
    "$family: a token past iat + maxAge is expired whatever its exp",
    async ({ family, define }) => {
      const onExpire = vi.fn();
      const onRead = vi.fn();
      const session = define({ maxAge: "1h", hooks: { onExpire, onRead } });
      const iat = nowSeconds() - 2 * HOUR;
      const token = await foreignToken(family, { jti: "long", iat, exp: iat + 10 * DAY });
      const headers = new Headers();

      const manager = await session.use({ req: get({ cookie: `web=${token}` }), res: { headers } });

      expect(manager.id).toBeUndefined();
      expect(manager.data).toEqual({});
      expect(onRead).not.toHaveBeenCalled();
      expect(onExpire).toHaveBeenCalledOnce();
      const [{ session: expired, error }] = onExpire.mock.calls[0] as [
        { session: { id: string; createdAt: number; expiresAt: number }; error: unknown },
      ];
      expect(expired).toMatchObject({ id: "long", createdAt: iat * 1000 });
      expect(expired.expiresAt).toBe((iat + HOUR) * 1000);
      expect(isJWTError(error, "ERR_JWT_EXPIRED")).toBe(true);
      expect(linesOf(headers, "web")).toEqual([expect.stringContaining("Max-Age=0")]);

      const opened = await caught(session.open(token));
      expect(isJWTError(opened, "ERR_JWT_EXPIRED")).toBe(true);
    },
  );

  it.each(FAMILIES)(
    "$family: a token within maxAge ends at iat + maxAge, not at its exp",
    async ({ family, define }) => {
      const session = define({ maxAge: "1h" });
      const iat = nowSeconds() - 30 * 60;
      const token = await foreignToken(family, {
        jti: "long",
        iat,
        exp: iat + 10 * DAY,
        user: "ada",
      });

      const manager = await session.use({ req: get({ cookie: `web=${token}` }) });
      expect(manager.id).toBe("long");
      expect(manager.data).toEqual({ user: "ada" });
      expect(manager.expiresAt).toBe((iat + HOUR) * 1000);
      expect((await session.open(token)).expiresAt).toBe((iat + HOUR) * 1000);
    },
  );

  it.each(FAMILIES)(
    "$family: a reissue under rolling writes the cookie from the fresh lifetime",
    async ({ family, define }) => {
      const session = define({ maxAge: "1h", rolling: true });
      const iat = nowSeconds() - 30 * 60;
      const token = await foreignToken(family, { jti: "long", iat, exp: iat + 10 * DAY });
      const headers = new Headers();

      const manager = await session.use({ req: get({ cookie: `web=${token}` }), res: { headers } });
      const expiresAt = Number(manager.expiresAt);
      expect(manager.id).not.toBe("long");
      expect(expiresAt - manager.createdAt).toBe(HOUR * 1000);
      const [line = ""] = linesOf(headers, "web");
      expect(line).toContain(`Expires=${new Date(expiresAt).toUTCString()}`);
    },
  );

  it.each(FAMILIES)(
    "$family: without maxAge the token's exp alone decides",
    async ({ family, define }) => {
      const session = define();
      const iat = nowSeconds() - 2 * HOUR;
      const token = await foreignToken(family, { jti: "long", iat, exp: iat + 10 * DAY });

      const manager = await session.use({ req: get({ cookie: `web=${token}` }) });
      expect(manager.id).toBe("long");
      expect(manager.expiresAt).toBe((iat + 10 * DAY) * 1000);
    },
  );
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
    const event: WebSessionEvent = { token };

    expect(session.token(event)).toBe(token);
    const manager = await session.use(event);
    expect(manager.data).toEqual({ user: "ada" });
    expect(manager.token).toBe(token);
    expect(onRead).toHaveBeenCalledOnce();
    expect(onRead.mock.calls[0]?.[0]).toMatchObject({ event });

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
  interface PlainEvent {
    locals: Record<string, unknown>;
    headers: Record<string, string>;
    cookies: Map<string, string>;
  }

  const plainDriver = defineSessionDriver<PlainEvent>({
    prefix: "[plain]",
    state: (event) => event.locals,
    header: (event, name) => event.headers[name],
    cookies: (event): CookieJar => ({
      read: (name) => event.cookies.get(name),
      write: (name, value, attrs) => {
        if (attrs.maxAge === 0) event.cookies.delete(name);
        else event.cookies.set(name, value);
      },
    }),
  });

  const plain = (cookies = new Map<string, string>()): PlainEvent => ({
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

    const event = plain(cookies);
    const read = await session.use(event);
    expect(read.data).toEqual({ user: "ada" });
    expect(onRead).toHaveBeenCalledOnce();
    expect(onRead.mock.calls[0]?.[0]?.event).toBe(event);

    await read.clear();
    expect(cookies.has(`unjwt-${family}`)).toBe(false);
  });

  it("types the event from the driver, and as WebSessionEvent without one", () => {
    expectTypeOf(plainDriver).toEqualTypeOf<SessionDriver<PlainEvent>>();

    const custom = defineJWSSession(
      {
        key: jwsKey,
        hooks: {
          onRead: ({ event }) => {
            expectTypeOf(event).toEqualTypeOf<PlainEvent>();
          },
        },
      },
      { driver: plainDriver },
    );
    expectTypeOf(custom.use).parameter(0).toEqualTypeOf<PlainEvent>();

    const web = defineJWESession({
      key: jweKey,
      hooks: {
        onRead: ({ event }) => {
          expectTypeOf(event).toEqualTypeOf<WebSessionEvent>();
        },
      },
    });
    expectTypeOf(web.use).parameter(0).toEqualTypeOf<WebSessionEvent>();
  });
});

describe("unjwt/session types", () => {
  it("carries the data and maxAge generics to the manager", () => {
    const session = defineJWESession<{ userId: string }, "7D">({ key: jweKey, maxAge: "7D" });
    expectTypeOf(session.use({ token: undefined })).toEqualTypeOf<
      Promise<SessionManager<{ userId: string }, "7D">>
    >();
  });

  it("narrows use() and the hooks to a framework's event through the third generic", () => {
    interface FrameworkEvent {
      req: Request;
      res: { headers: Headers; errHeaders: Headers };
      context: Record<string, unknown>;
    }
    const narrowed = defineJWESession<{ user: string }, "1h", FrameworkEvent>({
      key: jweKey,
      maxAge: "1h",
      hooks: {
        onUpdate: ({ event }) => {
          expectTypeOf(event).toEqualTypeOf<FrameworkEvent>();
        },
      },
    });
    expectTypeOf(narrowed.use).parameter(0).toEqualTypeOf<FrameworkEvent>();
    // @ts-expect-error a bare Request is no longer accepted once narrowed
    void narrowed.use(new Request("http://localhost/"));
  });

  it("takes a request event by its Request or its Headers, or a token, never an empty object", () => {
    expectTypeOf<{ req: Request }>().toExtend<SessionRequestEvent>();
    expectTypeOf<{ headers: Headers }>().toExtend<SessionRequestEvent>();
    expectTypeOf<{ req: Request; headers: Headers }>().toExtend<SessionRequestEvent>();
    expectTypeOf<Request>().toExtend<SessionRequestEvent>();
    expectTypeOf<{ res: { headers: Headers } }>().not.toExtend<SessionRequestEvent>();
    expectTypeOf<{ token: string }>().toExtend<SessionHandedToken>();
    expectTypeOf<{ token: undefined }>().toExtend<SessionHandedToken>();
    expectTypeOf<{}>().not.toExtend<WebSessionEvent>();
  });
});

describe("JWE key pair halves", () => {
  const roundTrip = async (key: JWESessionKey) => {
    const session = defineJWESession({ name: "web", key });
    const headers = new Headers();
    const written = await session.use({ req: get(), res: { headers } });
    await written.update({ user: "ada" });
    const read = await session.use({ req: get({ cookie: replay(headers) }) });
    return { id: read.id, data: read.data, writtenId: written.id };
  };

  it("a private JWK alone seals with its own public half", async () => {
    const { privateKey } = await generateJWK("RSA-OAEP-256");
    const result = await roundTrip({ privateKey });
    expect(result.id).toBe(result.writtenId);
    expect(result.data).toEqual({ user: "ada" });
  });

  it("an imported PKCS8 PEM is a session key as it comes", async () => {
    const privateKey = await importPEM(rsa.pem.pkcs8, "RSA-OAEP-256", { pemType: "pkcs8" });
    const result = await roundTrip({ privateKey });
    expect(result.id).toBe(result.writtenId);
    expect(result.data).toEqual({ user: "ada" });
  });

  it("a private CryptoKey alone is refused, its public half cannot be derived", async () => {
    const { privateKey } = await generateKey("RSA-OAEP-256");
    const session = defineJWESession({ name: "web", key: { privateKey } as never });
    const error = await session
      .use({ req: get(), res: { headers: new Headers() } })
      .catch((e) => e);
    expect(isJWTError(error, "ERR_SESSION_KEY_INVALID")).toBe(true);
    expect((error as Error).message).toContain('a CryptoKey "privateKey" needs its "publicKey"');
  });

  it("types: a private JWK may come alone, a private CryptoKey may not", () => {
    expectTypeOf<{ privateKey: JWEAsymmetricPrivateJWK }>().toExtend<JWESessionKey>();
    expectTypeOf<{ privateKey: CryptoKey }>().not.toExtend<JWESessionKey>();
    expectTypeOf<{ privateKey: CryptoKey; publicKey: CryptoKey }>().toExtend<JWESessionKey>();
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
