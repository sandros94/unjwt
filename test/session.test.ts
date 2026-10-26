import { describe, it, expect, expectTypeOf, vi } from "vitest";
import { type H3Event, H3, HTTPError } from "h3";

import type { JWEAsymmetricPrivateJWK } from "../src/core/types/index.ts";
import { isJWTError } from "../src/error.ts";
import { generateJWK, generateKey, importPEM } from "../src/core/jwk/index.ts";
import type { JWESessionKey } from "../src/session/_internal/codec-jwe.ts";
import { rsa } from "./keys.ts";
import { sign } from "../src/core/jws/index.ts";
import { encrypt } from "../src/core/jwe/index.ts";
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
const rotation = await Promise.all(
  ["current", "previous", "unknown"].map(async (kid) => ({
    ...(await generateJWK("A256KW")),
    kid,
  })),
);

const nowSeconds = () => Math.floor(Date.now() / 1000);

type Family = "jws" | "jwe";
type Definition = SessionDefinition<Record<string, unknown>>;

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
    async ({ define }) => {
      const session = define();
      const headers = new Headers();
      const written = await session.use({ req: get(), res: { headers } });
      await written.update({ user: "ada" });

      const [line = ""] = headers.getSetCookie();
      expect(line.startsWith(`web=${written.token}`)).toBe(true);
      expect(line).toContain("Path=/");
      expect(line).toContain("Secure");
      expect(line).toContain("SameSite=Lax");
      expect(line.includes("HttpOnly")).toBe(true);

      const read = await session.use({ req: get({ cookie: replay(headers) }) });
      expect(read.id).toBe(written.id);
      expect(read.data).toEqual({ user: "ada" });
    },
  );

  it("names the two families __Host-unjwt-jws and __Host-unjwt-jwe, side by side on one request", async () => {
    const jws = defineJWSSession({ key: jwsKey, sessionHeader: true });
    const jwe = defineJWESession({ key: jweKey, sessionHeader: true });
    const headers = new Headers();
    const event = { req: get(), res: { headers } };
    await (await jws.use(event)).update({ family: "jws" });
    await (await jwe.use(event)).update({ family: "jwe" });

    const names = headers.getSetCookie().map((line) => line.split("=", 1)[0]);
    expect(names).toEqual(["__Host-unjwt-jws", "__Host-unjwt-jwe"]);
    const cookie = replay(headers);
    expect((await jws.use({ req: get({ cookie }) })).data).toEqual({ family: "jws" });
    expect((await jwe.use({ req: get({ cookie }) })).data).toEqual({ family: "jwe" });

    const token = await jws.issue({ via: "header" });
    const read = await jws.use({ req: get({ "x-unjwt-jws-session": token }) });
    expect(read.data).toEqual({ via: "header" });
  });

  it.each(FAMILIES)(
    "$family: cookie.httpOnly false is the explicit opt-out of HttpOnly",
    async ({ define }) => {
      const session = define({ cookie: { httpOnly: false } });
      const headers = new Headers();
      await (await session.use({ req: get(), res: { headers } })).update({ user: "ada" });

      const [line = ""] = headers.getSetCookie();
      expect(line).toContain("Secure");
      expect(line.includes("HttpOnly")).toBe(false);
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

    const headerOnly = define({ cookie: false, sessionHeader: true });
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

describe("unjwt/session with res.errHeaders", () => {
  it.each(FAMILIES)(
    "$family: mirrors every cookie write and drop into errHeaders",
    async ({ define }) => {
      const session = define({ cookie: { chunkMaxLength: 64 } });
      const headers = new Headers();
      const errHeaders = new Headers();
      errHeaders.append("set-cookie", "other=1; Path=/");
      errHeaders.append("set-cookie", "web.theme=dark; Path=/");
      const manager = await session.use({ req: get(), res: { headers, errHeaders } });

      await manager.update({ pad: "x".repeat(200) });
      const sessionLines = (target: Headers) =>
        target.getSetCookie().filter((line) => /^web(\.\d+)?=/.test(line));
      expect(chunkCount(headers)).toBeGreaterThan(1);
      expect(sessionLines(errHeaders)).toEqual(sessionLines(headers));

      await manager.update({ pad: "" });
      expect(sessionLines(errHeaders)).toEqual(sessionLines(headers));

      await manager.clear();
      expect(linesOf(errHeaders, "web")).toEqual([expect.stringContaining("Max-Age=0")]);
      expect(sessionLines(errHeaders)).toEqual(sessionLines(headers));
      expect(errHeaders.getSetCookie()).toContain("other=1; Path=/");
      expect(errHeaders.getSetCookie()).toContain("web.theme=dark; Path=/");
    },
  );

  it.each(FAMILIES)(
    "$family: an h3 v2 handler that throws after a write still sends the cookie",
    async ({ define }) => {
      const session = define();
      const app = new H3()
        .post("/login", async (event) => {
          await (await session.use(event)).update({ user: "ada" });
          throw new HTTPError({ status: 418 });
        })
        .post("/logout", async (event) => {
          await (await session.use(event)).clear();
          throw new HTTPError({ status: 401 });
        });

      const login = await app.request("/login", { method: "POST" });
      expect(login.status).toBe(418);
      const [issued = ""] = linesOf(login.headers, "web");
      expect(issued).toMatch(/^web=ey/);

      const logout = await app.request("/logout", {
        method: "POST",
        headers: { cookie: issued.split(";", 1)[0] ?? "" },
      });
      expect(logout.status).toBe(401);
      expect(linesOf(logout.headers, "web")).toEqual([expect.stringContaining("Max-Age=0")]);
    },
  );
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
      const session = define({
        maxAge: 3600,
        rolling: true,
        sessionHeader: true,
        hooks: { onUpdate },
      });
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
      const session = define({ sessionHeader: true, hooks: { onClear } });
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
      const session = define({ sessionHeader: true });
      const fromHeader = await session.issue({ who: "header" });

      const manager = await session.use({ req: get({ "x-web-session": fromHeader }) });
      await manager.update({ who: "updated" });
      expect((await session.open(String(manager.token))).data).toEqual({ who: "updated" });
    },
  );

  it.each(FAMILIES)(
    "$family: with sessionHeader unset a session with cookies reads only its cookie",
    async ({ define }) => {
      const session = define();
      const fromCookie = await session.issue({ who: "cookie" });
      const fromHeader = await session.issue({ who: "header" });
      const event = { req: get({ "cookie": `web=${fromCookie}`, "x-web-session": fromHeader }) };

      expect((await session.use(event)).data).toEqual({ who: "cookie" });
      expect(session.token(event)).toBe(fromCookie);
      expect(
        (await define().use({ req: get({ "x-web-session": fromHeader }) })).id,
      ).toBeUndefined();
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
    expect(cookies.get(`__Host-unjwt-${family}`)).toBe(written.token);

    const event = plain(cookies);
    const read = await session.use(event);
    expect(read.data).toEqual({ user: "ada" });
    expect(onRead).toHaveBeenCalledOnce();
    expect(onRead.mock.calls[0]?.[0]?.event).toBe(event);

    await read.clear();
    expect(cookies.has(`__Host-unjwt-${family}`)).toBe(false);
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
    expectTypeOf<{
      req: Request;
      res: { headers: Headers; errHeaders: Headers };
    }>().toExtend<SessionRequestEvent>();
    expectTypeOf<H3Event>().toExtend<SessionRequestEvent>();
    expectTypeOf<{ token: string }>().toExtend<SessionHandedToken>();
    expectTypeOf<{ token: undefined }>().toExtend<SessionHandedToken>();
    expectTypeOf<{}>().not.toExtend<WebSessionEvent>();
  });
});

describe("unjwt/session checks its config when defined", () => {
  type Code = "ERR_SESSION_CONFIG_INVALID" | "ERR_SESSION_KEY_INVALID" | "ERR_INVALID_OPTION";
  const refusals: {
    label: string;
    config: Record<string, unknown>;
    code: Code;
    message: string;
  }[] = [
    {
      label: "rolling without a maxAge",
      config: { rolling: true },
      code: "ERR_SESSION_CONFIG_INVALID",
      message: '"rolling" needs a "maxAge" to extend.',
    },
    {
      label: "rolling not shorter than maxAge",
      config: { maxAge: 60, rolling: "1m" },
      code: "ERR_SESSION_CONFIG_INVALID",
      message: '"rolling" must be shorter than "maxAge".',
    },
    {
      label: "rolling neither true nor a duration",
      config: { maxAge: 60, rolling: false },
      code: "ERR_INVALID_OPTION",
      message: '"rolling" must be true or a duration.',
    },
    {
      label: "a name that is not a cookie name",
      config: { name: "bad name" },
      code: "ERR_SESSION_CONFIG_INVALID",
      message: 'Session "name" must be a valid cookie name',
    },
    {
      label: "a name spelling a chunk cookie",
      config: { name: "web.1" },
      code: "ERR_SESSION_CONFIG_INVALID",
      message: "cannot end in a dot and digits",
    },
    {
      label: "a sessionHeader that is not a header name",
      config: { sessionHeader: "x session" },
      code: "ERR_SESSION_CONFIG_INVALID",
      message: 'Session "sessionHeader" must be true, false or a header name',
    },
    {
      label: "a __Host- name with a Domain",
      config: { name: "__Host-web", cookie: { domain: "example.com" } },
      code: "ERR_SESSION_CONFIG_INVALID",
      message: 'a "__Host-" cookie must be Secure, with Path=/ and no Domain',
    },
    {
      label: "a missing key",
      config: { key: undefined },
      code: "ERR_SESSION_KEY_INVALID",
      message: 'Session "key" is required.',
    },
    {
      label: "a password string as key",
      config: { key: "secret" },
      code: "ERR_SESSION_KEY_INVALID",
      message: 'Session "key" cannot be a string',
    },
  ];

  it.each(FAMILIES.flatMap((family) => refusals.map((refusal) => ({ ...family, ...refusal }))))(
    "$family: refuses $label",
    ({ define, config, code, message }) => {
      const error = thrown(() => define(config));
      expect(isJWTError(error, code)).toBe(true);
      expect((error as Error).message).toContain(message);
    },
  );

  it("refuses a CryptoKey without its algorithm pinned, and takes one with it", async () => {
    const [hmac, wrap] = await Promise.all([generateKey("HS256"), generateKey("A128KW")]);
    for (const error of [
      thrown(() => defineJWSSession({ key: hmac })),
      thrown(() => defineJWESession({ key: wrap })),
    ]) {
      expect(isJWTError(error, "ERR_SESSION_CONFIG_INVALID")).toBe(true);
      expect((error as Error).message).toContain("carries no algorithm");
    }

    const jws = defineJWSSession({
      name: "web",
      key: hmac,
      jws: { signOptions: { alg: "HS256" } },
    });
    const jwe = defineJWESession({
      name: "web",
      key: wrap,
      jwe: { encryptOptions: { alg: "A128KW", enc: "A128GCM" } },
    });
    expect((await jws.open(await jws.issue({ user: "ada" }))).data).toEqual({ user: "ada" });
    expect((await jwe.open(await jwe.issue({ user: "ada" }))).data).toEqual({ user: "ada" });
  });

  it("refuses a JWS key pair whose halves are not what they are named", async () => {
    const { publicKey } = await generateJWK("RS256");
    const error = thrown(() =>
      defineJWSSession({ key: { privateKey: publicKey, publicKey } as never }),
    );
    expect(isJWTError(error, "ERR_SESSION_KEY_INVALID")).toBe(true);
    expect((error as Error).message).toContain('"privateKey" must be a private JWK or a CryptoKey');
  });

  it.each(FAMILIES)(
    "$family: defines a key that fails only on import, and throws on use",
    async ({ family, define }) => {
      const key =
        family === "jws"
          ? { kty: "oct", k: "!!!not-base64url!!!", alg: "HS256" }
          : { kty: "oct", k: "A".repeat(27), alg: "A128KW" };
      const session = define({ key });
      const errors = [
        await caught(session.use({ req: get(), res: { headers: new Headers() } })),
        await caught(session.issue({ user: "ada" })),
      ];
      for (const error of errors) expect(isJWTError(error, "ERR_SESSION_KEY_INVALID")).toBe(true);
    },
  );

  it.each(FAMILIES)(
    "$family: defines a session without a token source, refused per request",
    async ({ define }) => {
      const session = define({ cookie: false, sessionHeader: false });
      const error = await caught(session.use({ req: get() }));
      expect(isJWTError(error, "ERR_SESSION_CONFIG_INVALID")).toBe(true);
      expect((await session.open(await session.issue({ user: "ada" }))).data).toEqual({
        user: "ada",
      });
    },
  );

  it.each(FAMILIES)(
    "$family: a valid rolling session defines, reads and rolls as before",
    async ({ define }) => {
      const session = define({ maxAge: 60, rolling: true });
      const token = await session.issue({ user: "ada" });
      const headers = new Headers();
      const manager = await session.use({ req: get({ cookie: `web=${token}` }), res: { headers } });
      expect(manager.data).toEqual({ user: "ada" });
      expect(headers.getSetCookie().some((line) => line.startsWith("web="))).toBe(true);
    },
  );
});

describe("JWE session keys", () => {
  const asymmetric = (error: unknown) =>
    isJWTError(error, "ERR_SESSION_KEY_INVALID") &&
    error.message.includes("an asymmetric key seals with its public half") &&
    error.message.includes("defineJWSSession");

  const defined = (key: unknown) =>
    thrown(() => defineJWESession({ name: "web", key: key as JWESessionKey }));

  it("refuses a key pair, a lone private or public JWK and a non-secret CryptoKey at definition", async () => {
    const [jwkPair, cryptoPair] = await Promise.all([
      generateJWK("RSA-OAEP-256"),
      generateKey("RSA-OAEP-256"),
    ]);
    const pem = await importPEM(rsa.pem.pkcs8, "RSA-OAEP-256", { pemType: "pkcs8" });
    const refused = [
      jwkPair,
      { privateKey: jwkPair.privateKey },
      jwkPair.privateKey,
      jwkPair.publicKey,
      cryptoPair,
      { privateKey: cryptoPair.privateKey },
      cryptoPair.publicKey,
      pem,
      { current: jweKey, keys: [jwkPair.privateKey] },
      { current: cryptoPair.privateKey, keys: [] },
    ];

    for (const key of refused) expect(asymmetric(defined(key))).toBe(true);
  });

  it("refuses a rotation set whose keys are not a list or a JWK Set of oct JWKs", () => {
    for (const keys of [undefined, "keys", [{ kty: "oct" }]]) {
      const error = defined({ current: jweKey, keys });
      expect(isJWTError(error, "ERR_SESSION_KEY_INVALID")).toBe(true);
      expect((error as Error).message).toContain('"keys"');
    }
  });

  it("never opens a token sealed with the public half of a former pair", async () => {
    const { publicKey } = await generateJWK("RSA-OAEP-256");
    const onError = vi.fn();
    const session = defineJWESession({ name: "web", key: jweKey, hooks: { onError } });
    const forged = await encrypt({ jti: "forged", iat: nowSeconds(), user: "mallory" }, publicKey, {
      protectedHeader: { typ: "session+jwt" },
    });

    const manager = await session.use({ req: get({ cookie: `web=${forged}` }) });
    expect(manager.id).toBeUndefined();
    expect(manager.data).toEqual({});
    expect(onError).toHaveBeenCalledOnce();
    await expect(session.open(forged)).rejects.toSatisfy((error) =>
      isJWTError(error, "ERR_SESSION_TOKEN_INVALID"),
    );
  });

  describe("rotation set", () => {
    const [current, previous, unknown] = rotation;
    const mint = (key: unknown) =>
      defineJWESession({ name: "web", key: key as JWESessionKey }).issue({ user: "ada" });

    it.each([
      { shape: "a list", keys: [previous] },
      { shape: "a JWK Set", keys: { keys: [previous] } },
      { shape: "a list repeating current", keys: [current, previous] },
    ])("issues under current and opens a token minted under $shape", async ({ keys }) => {
      const session = defineJWESession({ name: "web", key: { current, keys } });
      const issued = await session.issue({ user: "ada" });
      const formerToken = await mint(previous);

      expect(JSON.parse(atob(issued.split(".")[0])).kid).toBe("current");
      expect((await session.open(issued)).data).toEqual({ user: "ada" });
      expect((await session.open(formerToken)).data).toEqual({ user: "ada" });
      const read = await session.use({ req: get({ cookie: `web=${formerToken}` }) });
      expect(read.data).toEqual({ user: "ada" });
    });

    it("a token minted under a key outside the set is a token failure", async () => {
      const onError = vi.fn();
      const session = defineJWESession({
        name: "web",
        key: { current, keys: [previous] },
        hooks: { onError },
      });
      const stranger = await mint(unknown);

      const read = await session.use({ req: get({ cookie: `web=${stranger}` }) });
      expect(read.id).toBeUndefined();
      expect(onError).toHaveBeenCalledOnce();
      const [{ error }] = onError.mock.calls[0] as [{ error: unknown }];
      expect(isJWTError(error, "ERR_SESSION_TOKEN_INVALID")).toBe(true);
    });

    it("a secret CryptoKey current opens its own tokens, and the keys by kid", async () => {
      const secret = await generateKey("A256KW");
      const pinned = { jwe: { encryptOptions: { alg: "A256KW", enc: "A256GCM" } } } as const;
      const session = defineJWESession({
        name: "web",
        key: { current: secret, keys: [previous] },
        ...pinned,
      });
      const issued = await session.issue({ user: "ada" });
      const formerToken = await defineJWESession({ name: "web", key: previous, ...pinned }).issue({
        user: "ada",
      });

      expect((await session.open(issued)).data).toEqual({ user: "ada" });
      expect((await session.open(formerToken)).data).toEqual({ user: "ada" });
      await expect(session.open(await mint(unknown))).rejects.toSatisfy((error) =>
        isJWTError(error, "ERR_SESSION_TOKEN_INVALID"),
      );
    });
  });

  it("types: symmetric keys and rotation sets, never a pair", () => {
    expectTypeOf<typeof jweKey>().toExtend<JWESessionKey>();
    expectTypeOf<CryptoKey>().toExtend<JWESessionKey>();
    expectTypeOf<{ current: typeof jweKey; keys: (typeof jweKey)[] }>().toExtend<JWESessionKey>();
    expectTypeOf<{
      current: CryptoKey;
      keys: { keys: (typeof jweKey)[] };
    }>().toExtend<JWESessionKey>();
    expectTypeOf<{ privateKey: JWEAsymmetricPrivateJWK }>().not.toExtend<JWESessionKey>();
    expectTypeOf<{ privateKey: CryptoKey; publicKey: CryptoKey }>().not.toExtend<JWESessionKey>();
    expectTypeOf<JWEAsymmetricPrivateJWK>().not.toExtend<JWESessionKey>();
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

describe("a throwing onRead", () => {
  it("leaves the session empty for the rest of the request", async () => {
    let reads = 0;
    const define = defineJWSSession({
      name: "web",
      key: jwsKey,
      maxAge: "1h",
      hooks: {
        onRead: () => {
          reads += 1;
          throw new Error("revoked");
        },
      },
    });
    const headers = new Headers();
    const signedIn = await define.use({
      req: new Request("https://app.example/login"),
      res: { headers },
    });
    await signedIn.update({ user: "user_1a2b" });
    const cookie = headers
      .getSetCookie()
      .map((line) => line.split(";")[0])
      .join("; ");

    const event = { req: new Request("https://app.example/me", { headers: { cookie } }) };
    await expect(define.use(event)).rejects.toThrow("revoked");
    const again = await define.use(event);
    expect(again.id).toBeUndefined();
    expect(again.data).toEqual({});
    expect(reads).toBe(1);
  });
});

function thrown(run: () => unknown): unknown {
  try {
    run();
  } catch (error) {
    return error;
  }
  return undefined;
}

describe("SessionDefinition defaults its event to WebSessionEvent", () => {
  it("accepts a definition made without a driver", async () => {
    const typed: SessionDefinition<{ user: string }, "1h"> = defineJWSSession<
      { user: string },
      "1h"
    >({ key: jwsKey, maxAge: "1h" });
    expectTypeOf(typed.use).parameter(0).toEqualTypeOf<WebSessionEvent>();
    const headers = new Headers();
    const session = await typed.use({ req: new Request("https://app.example/"), res: { headers } });
    expect(session.id).toBeUndefined();
  });
});

describe("a pinned algorithm the key cannot serve", () => {
  it("is refused when the session is defined", async () => {
    const hs = await generateJWK("HS256");
    expect(() => defineJWSSession({ key: hs, jws: { signOptions: { alg: "ES256" } } })).toThrow(
      expect.objectContaining({ code: "ERR_SESSION_KEY_INVALID" }),
    );
    const gcm = await generateJWK("A256GCM");
    expect(() =>
      defineJWESession({ key: gcm, jwe: { encryptOptions: { alg: "A256KW", enc: "A256GCM" } } }),
    ).toThrow(expect.objectContaining({ code: "ERR_SESSION_KEY_INVALID" }));
    expect(() =>
      defineJWESession({ key: gcm, jwe: { encryptOptions: { alg: "dir", enc: "A256GCM" } } }),
    ).not.toThrow();
  });
});
