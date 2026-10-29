import { describe, it, expect, expectTypeOf, vi } from "vitest";
import { type H3Event, H3, HTTPError } from "h3";

import type {
  JWEAsymmetricPrivateJWK,
  JWK_HMAC,
  JWK_oct,
  JWKSet,
  JWSHeaderParameters,
} from "../src/core/types/index.ts";
import { type KnownJWTErrorCode, isJWTError } from "../src/error.ts";
import { generateJWK, generateKey, importKey, importPEM } from "../src/core/jwk/index.ts";
import { rsa } from "./keys.ts";
import { base64UrlParse, base64UrlStringify } from "../src/utils/base64.ts";
import { sign } from "../src/core/jws/index.ts";
import { encrypt } from "../src/core/jwe/index.ts";
import {
  type CookieJar,
  type JWESessionKey,
  type JWESessionKeyLookup,
  type JWESessionOctJWK,
  type JWSSessionKey,
  type JWSSessionKeyLookup,
  type SessionConfigJWS,
  type OpenedSessionState,
  type SessionClaims,
  type SessionDefinition,
  type SessionDriver,
  type SessionHandedToken,
  type SessionHooksJWE,
  type SessionHooksJWS,
  type SessionManager,
  type SessionJWE,
  type SessionJWS,
  type SessionRequestEvent,
  type SessionSource,
  type WebSessionEvent,
  defineJWESession,
  defineJWSSession,
  defineSessionDriver,
} from "../src/session/index.ts";
import { resolveTransport } from "../src/session/_internal/transport.ts";
import { webSessionDriver } from "../src/session/_internal/web-driver.ts";

const [jwsKey, jweKey] = await Promise.all([generateJWK("HS256"), generateJWK("A128KW")]);
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
          onKeyLookup: lookup,
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
      expect(context.unjwt).toBeTypeOf("object");
      expect(context.sessions).toBeUndefined();

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
      expect(context.unjwt).toBeTypeOf("object");
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
    "$family: reuses an existing context.unjwt object and leaves context.sessions untouched",
    async ({ define }) => {
      const session = define();
      const unjwt: Record<string, unknown> = Object.create(Object.create(null));
      const sessions: Record<string, unknown> = Object.create(Object.create(null));
      sessions.other = { id: "theirs" };
      const context: Record<string, unknown> = { unjwt, sessions };
      const request = get();
      const manager = await session.use({ req: request, res: { headers: new Headers() }, context });
      await manager.update({ user: "ada" });

      expect(context.unjwt).toBe(unjwt);
      expect(Object.keys(unjwt)).not.toHaveLength(0);
      expect(context.sessions).toBe(sessions);
      expect(Object.keys(sessions)).toEqual(["other"]);
      expect(sessions.other).toEqual({ id: "theirs" });

      const again = await session.use({ req: request, context });
      expect(again.id).toBe(manager.id);
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
    "$family: rolling reissues a cookie session and leaves a header session as sent",
    async ({ family, define }) => {
      const onUpdate = vi.fn();
      const session = define({
        maxAge: 3600,
        rolling: true,
        sessionHeader: true,
        hooks: { onUpdate },
      });
      const iat = nowSeconds() - 30 * 60;
      const old = await foreignToken(family, { jti: "old", iat, exp: iat + 3600, who: "ada" });

      const headers = new Headers();
      const fromHeader = await session.use({
        req: get({ "x-web-session": old }),
        res: { headers },
      });
      expect(fromHeader.id).toBe("old");
      expect(fromHeader.token).toBe(old);
      expect(onUpdate).not.toHaveBeenCalled();
      expect(headers.getSetCookie()).toEqual([]);

      const fromCookie = await session.use({
        req: get({ cookie: `web=${old}` }),
        res: { headers },
      });
      expect(fromCookie.id).not.toBe("old");
      expect(fromCookie.data).toEqual({ who: "ada" });
      expect(onUpdate).toHaveBeenCalledOnce();
      expect(onUpdate.mock.calls[0]?.[0]).toMatchObject({ trigger: "rolling" });
      expect(linesOf(headers, "web")).toEqual([expect.stringContaining(`web=${fromCookie.token}`)]);
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

  it.each(["jws", "jwe"] as const)(
    "%s: a header session updates and clears after the response was sent, and the client keeps its token",
    async (family) => {
      const driver = { ...webSessionDriver, writable: () => false };
      const config = { name: "web", sessionHeader: true };
      const session =
        family === "jws"
          ? defineJWSSession({ ...config, key: jwsKey }, { driver })
          : defineJWESession({ ...config, key: jweKey }, { driver });
      const fromHeader = await session.issue({ who: "header" });
      const headers = new Headers();

      const manager = await session.use({
        req: get({ "x-web-session": fromHeader }),
        res: { headers },
      });
      await manager.update({ who: "updated" });
      expect(manager.token).not.toBe(fromHeader);
      await manager.clear();
      expect(manager.token).toBeUndefined();
      expect(headers.getSetCookie()).toEqual([]);

      const next = await session.use({ req: get({ "x-web-session": fromHeader }) });
      expect(next.data).toEqual({ who: "header" });
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

describe("unjwt/session decides the token source once per request", () => {
  const SOURCES = [
    {
      label: "the header alone",
      event: { req: get({ "x-web-session": "abc" }) },
      config: { sessionHeader: true },
      source: "header",
    },
    {
      label: "the cookie alone",
      event: { req: get({ cookie: "web=abc" }) },
      config: { sessionHeader: true },
      source: "cookie",
    },
    {
      label: "the header and the cookie holding the same token",
      event: { req: get({ "cookie": "web=abc", "x-web-session": "Bearer abc" }) },
      config: { sessionHeader: true },
      source: "cookie",
    },
    {
      label: "the header and a chunked cookie holding the same token",
      event: {
        req: get({ "cookie": "web=__chunked__2; web.1=ab; web.2=c", "x-web-session": "abc" }),
      },
      config: { sessionHeader: true },
      source: "cookie",
    },
    {
      label: "the header and a cookie holding another token",
      event: { req: get({ "cookie": "web=abc", "x-web-session": "abd" }) },
      config: { sessionHeader: true },
      source: "header",
    },
    {
      label: "a malformed header and a cookie",
      event: { req: get({ "cookie": "web=abc", "x-web-session": "Basic abc" }) },
      config: { sessionHeader: true },
      source: "header",
    },
    {
      label: "the header and the same token with cookies off",
      event: { req: get({ "cookie": "web=abc", "x-web-session": "abc" }) },
      config: { sessionHeader: true, cookie: false },
      source: "header",
    },
    {
      label: "the header with sessionHeader unset",
      event: { req: get({ "cookie": "web=abc", "x-web-session": "abd" }) },
      config: {},
      source: "cookie",
    },
    { label: "a token in hand", event: { token: "abc" }, config: {}, source: "token" },
  ] as const;

  it.each(SOURCES)("$label: $source", ({ event, config, source }) => {
    const transport = resolveTransport(webSessionDriver, event, { config, name: "web" });
    expect(transport.source).toBe(source);
  });

  it.each(FAMILIES)(
    "$family: a header holding the cookie's token is a cookie session",
    async ({ define }) => {
      const session = define({ sessionHeader: true });
      const token = await session.issue({ who: "both" });
      const headers = new Headers();
      const manager = await session.use({
        req: get({ "cookie": `web=${token}`, "x-web-session": token }),
        res: { headers },
      });
      expect(manager.data).toEqual({ who: "both" });

      await manager.update({ who: "updated" });
      const [line = ""] = linesOf(headers, "web");
      expect(line.startsWith(`web=${manager.token}`)).toBe(true);
    },
  );

  it.each(FAMILIES)(
    "$family: a header holding the chunked cookie's token is a cookie session",
    async ({ define }) => {
      const session = define({ sessionHeader: true, cookie: { chunkMaxLength: 64 } });
      const signIn = new Headers();
      const signedIn = await session.use({ req: get(), res: { headers: signIn } });
      await signedIn.update({ who: "chunked" });
      expect(chunkCount(signIn)).toBeGreaterThan(1);

      const headers = new Headers();
      const manager = await session.use({
        req: get({ "cookie": replay(signIn), "x-web-session": String(signedIn.token) }),
        res: { headers },
      });
      expect(manager.data).toEqual({ who: "chunked" });
      await manager.update({ who: "updated" });
      expect(chunkCount(headers)).toBeGreaterThan(1);
    },
  );

  it.each(FAMILIES)(
    "$family: a bad token in both the header and the cookie drops the cookie",
    async ({ define }) => {
      const onError = vi.fn();
      const session = define({ sessionHeader: true, hooks: { onError } });
      const headers = new Headers();
      const manager = await session.use({
        req: get({ "cookie": "web=garbage", "x-web-session": "garbage" }),
        res: { headers },
      });
      expect(manager.id).toBeUndefined();
      expect(onError).toHaveBeenCalledOnce();
      expect(linesOf(headers, "web")).toEqual([expect.stringContaining("Max-Age=0")]);
    },
  );

  it.each(FAMILIES)(
    "$family: a header holding another token leaves the cookie untouched",
    async ({ define }) => {
      const session = define({ sessionHeader: true });
      const fromCookie = await session.issue({ who: "cookie" });
      const fromHeader = await session.issue({ who: "header" });
      const headers = new Headers();
      const event = {
        req: get({ "cookie": `web=${fromCookie}`, "x-web-session": fromHeader }),
        res: { headers },
      };

      const manager = await session.use(event);
      expect(manager.data).toEqual({ who: "header" });
      await manager.update({ who: "updated" });
      expect(headers.getSetCookie()).toEqual([]);
    },
  );

  it.each(FAMILIES)(
    "$family: a header token that fails to open does not fall back to the cookie",
    async ({ define }) => {
      const onError = vi.fn();
      const onRead = vi.fn();
      const session = define({ sessionHeader: true, hooks: { onError, onRead } });
      const fromCookie = await session.issue({ who: "cookie" });
      const headers = new Headers();
      const event = {
        req: get({ "cookie": `web=${fromCookie}`, "x-web-session": "garbage" }),
        res: { headers },
      };

      const manager = await session.use(event);
      expect(manager.id).toBeUndefined();
      expect(manager.data).toEqual({});
      expect(session.token(event)).toBeUndefined();
      expect(onRead).not.toHaveBeenCalled();
      expect(onError).toHaveBeenCalledOnce();
      expect(headers.getSetCookie()).toEqual([]);
    },
  );
});

describe("unjwt/session reports the token source", () => {
  const SOURCES = [
    {
      source: "cookie",
      label: "a cookie",
      event: (token: string) => ({
        req: get({ cookie: `web=${token}` }),
        res: { headers: new Headers() },
      }),
    },
    {
      source: "cookie",
      label: "a header holding the cookie's token",
      event: (token: string) => ({
        req: get({ "cookie": `web=${token}`, "x-web-session": token }),
        res: { headers: new Headers() },
      }),
    },
    {
      source: "header",
      label: "a header",
      event: (token: string) => ({
        req: get({ "x-web-session": token }),
        res: { headers: new Headers() },
      }),
    },
    { source: "token", label: "a token in hand", event: (token: string) => ({ token }) },
  ] as const;
  const cases = FAMILIES.flatMap((family) => SOURCES.map((entry) => ({ ...family, ...entry })));

  it.each(cases)(
    "$family, $label: the manager, onRead, onUpdate and onClear see $source",
    async ({ define, event, source }) => {
      const onRead = vi.fn();
      const onUpdate = vi.fn();
      const onClear = vi.fn();
      const session = define({ sessionHeader: true, hooks: { onRead, onUpdate, onClear } });
      const manager = await session.use(event(await session.issue({ user: "ada" })));

      expect(manager.source).toBe(source);
      expect(onRead.mock.calls[0]?.[0].session.source).toBe(source);

      await manager.update({ user: "grace" });
      expect(manager.source).toBe(source);
      expect(onUpdate.mock.calls[0]?.[0].session.source).toBe(source);
      expect(onUpdate.mock.calls[0]?.[0].oldSession).toMatchObject({
        source,
        data: { user: "ada" },
      });

      await manager.clear();
      expect(manager.source).toBe(source);
      expect(onClear.mock.calls[0]?.[0].oldSession).toMatchObject({
        source,
        data: { user: "grace" },
      });
    },
  );

  it.each(cases)(
    "$family, $label: onExpire and onError see $source",
    async ({ family, define, event, source }) => {
      const onExpire = vi.fn();
      const onError = vi.fn();
      const session = define({ sessionHeader: true, hooks: { onExpire, onError } });
      const expired = await foreignToken(family, {
        jti: "gone",
        iat: nowSeconds() - 120,
        exp: nowSeconds() - 60,
      });

      await session.use(event(expired));
      expect(onExpire.mock.calls[0]?.[0].session).toMatchObject({ id: "gone", source });

      await session.use(event("garbage"));
      expect(onError.mock.calls[0]?.[0].session.source).toBe(source);
    },
  );

  it.each(FAMILIES)("$family: open() reports a token in hand", async ({ define }) => {
    const session = define();
    expect((await session.open(await session.issue())).source).toBe("token");
  });

  it("types the source on the manager, the state and every hook", () => {
    expectTypeOf<SessionManager["source"]>().toEqualTypeOf<SessionSource>();
    expectTypeOf<SessionJWS["source"]>().toEqualTypeOf<SessionSource>();
    expectTypeOf<SessionJWE["source"]>().toEqualTypeOf<SessionSource>();
    expectTypeOf<
      OpenedSessionState<SessionClaims, undefined>["source"]
    >().toEqualTypeOf<SessionSource>();
    expectTypeOf<SessionSource>().toEqualTypeOf<"cookie" | "header" | "token">();
    defineJWSSession({
      key: jwsKey,
      hooks: {
        onRead: ({ session }) => {
          expectTypeOf(session.source).toEqualTypeOf<SessionSource>();
        },
        onUpdate: ({ session, oldSession }) => {
          expectTypeOf(session.source).toEqualTypeOf<SessionSource>();
          expectTypeOf(oldSession.source).toEqualTypeOf<SessionSource>();
        },
        onClear: ({ oldSession }) => {
          expectTypeOf(oldSession?.source).toEqualTypeOf<SessionSource | undefined>();
        },
        onExpire: ({ session }) => {
          expectTypeOf(session.source).toEqualTypeOf<SessionSource>();
        },
        onError: ({ session }) => {
          expectTypeOf(session.source).toEqualTypeOf<SessionSource>();
        },
      },
    });
  });
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

  it.each(cases)(
    "$family, $label: never rolls a handed token",
    async ({ family, define, config }) => {
      const onUpdate = vi.fn();
      const session = define({ ...config, maxAge: 3600, rolling: true, hooks: { onUpdate } });
      const iat = nowSeconds() - 30 * 60;
      const old = await foreignToken(family, { jti: "old", iat, exp: iat + 3600, user: "ada" });
      const manager = await session.use({ token: old });

      expect(onUpdate).not.toHaveBeenCalled();
      expect(manager.id).toBe("old");
      expect(manager.token).toBe(old);
      expect(manager.data).toEqual({ user: "ada" });
    },
  );

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

  it("takes an HMAC JWK, a CryptoKey or a pair as a JWS session key", () => {
    expectTypeOf<typeof jwsKey>().toExtend<JWSSessionKey>();
    expectTypeOf<CryptoKey>().toExtend<JWSSessionKey>();
    expectTypeOf<{ privateKey: CryptoKey; publicKey: CryptoKey }>().toExtend<JWSSessionKey>();
    expectTypeOf<typeof jweKey>().not.toExtend<JWSSessionKey>();
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

  it("refuses a JWS key pair whose halves are not what they are named", async () => {
    const [{ publicKey }, ecdsa, hmac] = await Promise.all([
      generateJWK("RS256"),
      generateKey("ES256"),
      generateKey("HS256"),
    ]);
    const signer =
      '[unjwt/session] Invalid JWS session key: "privateKey" must be a private JWK or a private CryptoKey.';
    const verifier =
      '[unjwt/session] Invalid JWS session key: "publicKey" must be a public JWK, a non-empty list or JWK Set of them, or a public CryptoKey.';
    const halves = [
      { key: { privateKey: publicKey, publicKey }, message: signer },
      { key: { privateKey: ecdsa.publicKey, publicKey: ecdsa.publicKey }, message: signer },
      { key: { privateKey: hmac, publicKey: hmac }, message: signer },
      { key: { privateKey: ecdsa.privateKey, publicKey: ecdsa.privateKey }, message: verifier },
      { key: { privateKey: ecdsa.privateKey, publicKey: [] }, message: verifier },
    ];
    for (const { key, message } of halves) {
      expect(refusedWith(() => defineJWSSession({ key: key as never }))).toEqual({
        code: "ERR_SESSION_KEY_INVALID",
        message,
      });
    }
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
    ];

    for (const key of refused) expect(asymmetric(defined(key))).toBe(true);
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

  it("types: an oct JWK or a secret CryptoKey, never a pair", () => {
    expectTypeOf<JWESessionKey>().toEqualTypeOf<
      JWESessionOctJWK | CryptoKey | JWKSet<JWESessionOctJWK[]>
    >();
    expectTypeOf<typeof jweKey>().toExtend<JWESessionKey>();
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

/** The code and message a definition throws with. */
function refusedWith(run: () => unknown): {
  code: string | undefined;
  message: string | undefined;
} {
  const error = thrown(run);
  return {
    code: isJWTError(error) ? error.code : undefined,
    message: (error as Error | undefined)?.message,
  };
}

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
  it("JWE: a CEK JWK serves dir alone", async () => {
    const gcm = await generateJWK("A256GCM");
    expect(() =>
      defineJWESession({ key: gcm, jwe: { encryptOptions: { alg: "A256KW", enc: "A256GCM" } } }),
    ).toThrow(expect.objectContaining({ code: "ERR_SESSION_KEY_INVALID" }));
    expect(() =>
      defineJWESession({ key: gcm, jwe: { encryptOptions: { alg: "dir", enc: "A256GCM" } } }),
    ).not.toThrow();
  });
});

describe("a session key that names no algorithm", () => {
  const silent = async (alg: "A256KW" | "HS512") => {
    const { alg: _alg, kid: _kid, ...key } = await generateJWK(alg);
    return key;
  };
  const roundTrip = async (session: Definition) =>
    (await session.open(await session.issue({ user: "ada" }))).data;

  it("JWE: is refused at definition without a pinned alg and enc", async () => {
    const [oct, wrap] = await Promise.all([silent("A256KW"), generateKey("A256KW")]);
    const cases = [
      { key: oct, jwe: undefined, jwk: true },
      { key: oct, jwe: { encryptOptions: { alg: "A256KW" } }, jwk: true },
      { key: wrap, jwe: { encryptOptions: { alg: "A256KW" } }, jwk: false },
    ] as const;
    for (const { key, jwe, jwk } of cases) {
      expect(refusedWith(() => defineJWESession({ key, jwe }))).toEqual({
        code: "ERR_SESSION_CONFIG_INVALID",
        message: `[unjwt/session] The session key names no algorithm, set "jwe.encryptOptions.alg" and "enc"${jwk ? ', or its "alg"' : ""}.`,
      });
    }
  });

  it("JWE: is refused at definition when its material cannot carry the pinned alg", async () => {
    const [gcm, kw128, oct] = await Promise.all([
      generateKey("A256GCM"),
      generateKey("A128KW"),
      silent("A256KW"),
    ]);
    const pin = { encryptOptions: { alg: "A256KW", enc: "A256GCM" } } as const;
    expect(refusedWith(() => defineJWESession({ key: gcm, jwe: pin }))).toEqual({
      code: "ERR_SESSION_KEY_INVALID",
      message:
        '[unjwt/session] The session key serves A256GCMKW, dir, not the "A256KW" that "jwe.encryptOptions.alg" pins.',
    });
    expect(refusedWith(() => defineJWESession({ key: kw128, jwe: pin })).message).toContain(
      'The session key serves A128KW, not the "A256KW"',
    );
    expect(
      refusedWith(() =>
        defineJWESession({ key: oct, jwe: { encryptOptions: { alg: "A128KW", enc: "A128GCM" } } }),
      ).message,
    ).toContain('The session key serves A256KW, A256GCMKW, dir, not the "A128KW"');
  });

  it("JWE: is refused at definition when a dir key cannot carry the pinned enc", async () => {
    const [gcm, oct, cek] = await Promise.all([
      generateKey("A256GCM"),
      silent("A256KW"),
      generateJWK("A256GCM"),
    ]);
    const dir = { encryptOptions: { alg: "dir", enc: "A128GCM" } } as const;
    expect(refusedWith(() => defineJWESession({ key: gcm, jwe: dir }))).toEqual({
      code: "ERR_SESSION_KEY_INVALID",
      message:
        '[unjwt/session] The session key serves "dir" with A256GCM, not the "A128GCM" that "jwe.encryptOptions.enc" pins.',
    });
    expect(refusedWith(() => defineJWESession({ key: oct, jwe: dir })).message).toContain(
      'serves "dir" with A256GCM, A128CBC-HS256, not the "A128GCM"',
    );
    expect(
      refusedWith(() => defineJWESession({ key: cek, jwe: { encryptOptions: { enc: "A128GCM" } } }))
        .code,
    ).toBe("ERR_SESSION_KEY_INVALID");
  });

  it("JWE: issues and opens with every pin its material carries", async () => {
    const [oct, gcm] = await Promise.all([silent("A256KW"), generateKey("A256GCM")]);
    const pins = [
      { key: oct, alg: "A256KW", enc: "A128GCM" },
      { key: oct, alg: "A256GCMKW", enc: "A256CBC-HS512" },
      { key: oct, alg: "dir", enc: "A128CBC-HS256" },
      { key: gcm, alg: "A256GCMKW", enc: "A256GCM" },
      { key: gcm, alg: "dir", enc: "A256GCM" },
    ] as const;
    for (const { key, alg, enc } of pins) {
      const session = defineJWESession({ name: "web", key, jwe: { encryptOptions: { alg, enc } } });
      expect(await roundTrip(session)).toEqual({ user: "ada" });
    }
  });

  it("JWS: is refused at definition without a pinned alg, or with one it cannot carry", async () => {
    const [oct, hmac, ecdsa] = await Promise.all([
      silent("A256KW"),
      generateKey("HS256"),
      generateKey("ES256"),
    ]);
    expect(refusedWith(() => defineJWSSession({ key: oct }))).toEqual({
      code: "ERR_SESSION_CONFIG_INVALID",
      message:
        '[unjwt/session] The session key names no algorithm, set "jws.signOptions.alg", or its "alg".',
    });
    expect(
      refusedWith(() => defineJWSSession({ key: oct, jws: { signOptions: { alg: "HS384" } } })),
    ).toEqual({
      code: "ERR_SESSION_KEY_INVALID",
      message:
        '[unjwt/session] The session key serves HS256, not the "HS384" that "jws.signOptions.alg" pins.',
    });
    expect(
      refusedWith(() => defineJWSSession({ key: hmac, jws: { signOptions: { alg: "HS512" } } }))
        .message,
    ).toContain('The session key serves HS256, not the "HS512"');
    expect(
      refusedWith(() => defineJWSSession({ key: ecdsa, jws: { signOptions: { alg: "RS256" } } }))
        .message,
    ).toContain('The session key "privateKey" serves ES256, not the "RS256"');
    const { publicKey } = await generateKey("ES384");
    expect(
      refusedWith(() =>
        defineJWSSession({
          key: { privateKey: ecdsa.privateKey, publicKey },
          jws: { signOptions: { alg: "ES256" } },
        }),
      ).message,
    ).toContain('The session key "publicKey" serves ES384, not the "ES256"');

    const hs512 = await silent("HS512");
    for (const alg of ["HS256", "HS384", "HS512"] as const) {
      const session = defineJWSSession({ name: "web", key: hs512, jws: { signOptions: { alg } } });
      expect(await roundTrip(session)).toEqual({ user: "ada" });
    }
  });

  it.each([
    ["ES256", "ES256"],
    ["Ed25519", "EdDSA"],
  ] as const)(
    "JWS: a %s pair without alg defines without a pin and issues with the alg its curve names",
    async (generated, alg) => {
      const { privateKey, publicKey } = await generateJWK(generated);
      const { alg: _private, ...signing } = privateKey;
      const { alg: _public, ...verifying } = publicKey;
      const session = defineJWSSession({
        name: "web",
        key: { privateKey: signing, publicKey: verifying },
      });
      const token = await session.issue({ user: "ada" });
      expect(JSON.parse(base64UrlParse(token.split(".")[0])).alg).toBe(alg);
      expect((await session.open(token)).data).toEqual({ user: "ada" });
    },
  );
});

describe("a pair with one half that names its algorithm", () => {
  const header = (token: string) => JSON.parse(base64UrlParse(token.split(".")[0]));
  const roundTrip = async (session: Definition) => {
    const token = await session.issue({ user: "ada" });
    return { alg: header(token).alg, data: (await session.open(token)).data };
  };

  it("takes the algorithm the private JWK names for a public CryptoKey", async () => {
    const { privateKey, publicKey } = await generateJWK("ES256");
    const session = defineJWSSession({
      name: "web",
      key: { privateKey, publicKey: await importKey(publicKey, { expect: "public" }) },
    });
    expect(await roundTrip(session)).toEqual({ alg: "ES256", data: { user: "ada" } });
  });

  it("takes the algorithm the public JWK names for a private CryptoKey or a private JWK without alg", async () => {
    const [ecdsa, pss] = await Promise.all([
      generateJWK("ES384"),
      generateJWK("PS256", { modulusLength: 2048 }),
    ]);
    const { alg: _alg, ...silent } = pss.privateKey;
    const pairs = [
      {
        privateKey: await importKey(ecdsa.privateKey, { expect: "private" }),
        publicKey: ecdsa.publicKey,
      },
      { privateKey: silent, publicKey: pss.publicKey },
    ];
    for (const [index, key] of pairs.entries()) {
      const session = defineJWSSession({ name: "web", key });
      expect(await roundTrip(session)).toEqual({
        alg: ["ES384", "PS256"][index],
        data: { user: "ada" },
      });
    }
  });

  it("is refused when the other half cannot carry that algorithm", async () => {
    const [{ privateKey }, rsassa] = await Promise.all([
      generateJWK("ES256"),
      generateKey("RS256"),
    ]);
    expect(
      refusedWith(() => defineJWSSession({ key: { privateKey, publicKey: rsassa.publicKey } })),
    ).toEqual({
      code: "ERR_SESSION_KEY_INVALID",
      message:
        '[unjwt/session] The session key "publicKey" serves RS256, not the "ES256" that the session key "privateKey" names.',
    });
  });

  it("needs the pin when neither half names one", async () => {
    const { privateKey, publicKey } = await generateKey("ES256");
    expect(refusedWith(() => defineJWSSession({ key: { privateKey, publicKey } }))).toEqual({
      code: "ERR_SESSION_CONFIG_INVALID",
      message:
        '[unjwt/session] The session key "privateKey" names no algorithm, set "jws.signOptions.alg".',
    });
    const pinned = defineJWSSession({
      name: "web",
      key: { privateKey, publicKey },
      jws: { signOptions: { alg: "ES256" } },
    });
    expect(await roundTrip(pinned)).toEqual({ alg: "ES256", data: { user: "ada" } });
  });
});

describe("the algorithms a session accepts", () => {
  const issued = (key: JWESessionKey, encryptOptions?: Record<string, unknown>) =>
    defineJWESession({ name: "web", key, jwe: { encryptOptions } }).issue({ user: "ada" });
  it("JWE: a wrapping key opens every enc, a pinned one included", async () => {
    const session = defineJWESession({
      name: "web",
      key: jweKey,
      jwe: { encryptOptions: { alg: "A128KW", enc: "A128GCM" } },
    });
    for (const enc of ["A128GCM", "A256GCM", "A128CBC-HS256", "A256CBC-HS512"]) {
      const token = await issued(jweKey, { enc });
      expect((await session.open(token)).data).toEqual({ user: "ada" });
    }
  });

  it("JWS: verifies a former public key of another alg, and tries a key without alg for its own algorithms alone", async () => {
    const [current, former, other] = await Promise.all([
      generateJWK("ES256"),
      generateJWK("PS256"),
      generateJWK("RS256"),
    ]);
    const { alg: _alg, ...silent } = former.publicKey;
    const session = defineJWSSession({
      name: "web",
      key: {
        privateKey: current.privateKey,
        publicKey: [current.publicKey, other.publicKey, silent],
      },
      jws: { signOptions: { alg: "ES256" }, verifyOptions: { algorithms: ["PS256"] } },
    });
    const signed = (privateKey: unknown, alg: string) =>
      sign({ jti: "s", iat: nowSeconds(), user: "ada" }, privateKey as never, {
        alg: alg as never,
        protectedHeader: { typ: "session+jwt" },
      });

    expect((await session.open(await signed(other.privateKey, "RS256"))).data).toEqual({
      user: "ada",
    });
    expect((await session.open(await signed(former.privateKey, "PS256"))).data).toEqual({
      user: "ada",
    });
    const offAlgorithm = await signed({ ...former.privateKey, alg: "RS256" }, "RS256");
    await expect(session.open(offAlgorithm)).rejects.toSatisfy((error) =>
      isJWTError(error, "ERR_SESSION_TOKEN_INVALID"),
    );
  });
});

describe("the key rules both families share", () => {
  interface KeyRuleCase extends FamilyCase {
    label: "JWS" | "JWE";
    /** The configured key and the `alg` it names. */
    key: JWK_oct;
    alg: string;
    /** A `CryptoKey` and an `oct` JWK of `alg`, neither naming it, and the options that pin it. */
    silent: () => Promise<{ crypto: CryptoKey; jwk: JWK_oct; pin: Record<string, unknown> }>;
    /** A `CryptoKey` of `alg`, and an algorithm of the family neither it nor `key` serves. */
    mismatch: () => Promise<{ crypto: CryptoKey; pin: string }>;
    pinning: (alg: string) => Record<string, unknown>;
    listing: (algorithms: string[]) => Record<string, unknown>;
    hint: string;
    pinPath: string;
    listPath: string;
    /** An algorithm of the family no configured key serves. */
    dead: string;
    /** A pair of asymmetric keys of the family, as JWKs and as `CryptoKey`s. */
    asymmetric: () => Promise<{ privateKey: unknown; publicKey: unknown }[]>;
    /** What the refusal of a lone asymmetric key tells the caller to do instead. */
    instead: string;
    notAKey: string;
  }

  const withoutAlg = async (alg: "HS256" | "A128KW"): Promise<JWK_oct> => {
    const { alg: _alg, kid: _kid, ...key } = await generateJWK(alg);
    return key;
  };

  const RULES: KeyRuleCase[] = [
    {
      ...FAMILIES[0],
      label: "JWS",
      key: jwsKey,
      alg: "HS256",
      silent: async () => ({
        crypto: await generateKey("HS256"),
        jwk: await withoutAlg("HS256"),
        pin: { jws: { signOptions: { alg: "HS256" } } },
      }),
      mismatch: async () => ({ crypto: await generateKey("HS256"), pin: "HS512" }),
      pinning: (alg) => ({ jws: { signOptions: { alg } } }),
      listing: (algorithms) => ({ jws: { verifyOptions: { algorithms } } }),
      hint: '"jws.signOptions.alg"',
      pinPath: "jws.signOptions.alg",
      listPath: "jws.verifyOptions.algorithms",
      dead: "ES256",
      asymmetric: () => Promise.all([generateJWK("ES256"), generateKey("ES256")]),
      instead: "pass both as { privateKey, publicKey }",
      notAKey:
        '[unjwt/session] Invalid JWS session key: expected an HMAC "oct" JWK, a JWK Set of them, a secret CryptoKey or a key pair.',
    },
    {
      ...FAMILIES[1],
      label: "JWE",
      key: jweKey,
      alg: "A128KW",
      silent: async () => ({
        crypto: await generateKey("A128KW"),
        jwk: await withoutAlg("A128KW"),
        pin: { jwe: { encryptOptions: { alg: "A128KW", enc: "A128GCM" } } },
      }),
      mismatch: async () => ({ crypto: await generateKey("A128KW"), pin: "A256KW" }),
      pinning: (alg) => ({ jwe: { encryptOptions: { alg, enc: "A128GCM" } } }),
      listing: (algorithms) => ({ jwe: { decryptOptions: { algorithms } } }),
      hint: '"jwe.encryptOptions.alg" and "enc"',
      pinPath: "jwe.encryptOptions.alg",
      listPath: "jwe.decryptOptions.algorithms",
      dead: "A256KW",
      asymmetric: () => Promise.all([generateJWK("RSA-OAEP-256"), generateKey("RSA-OAEP-256")]),
      instead: "or defineJWSSession for a key pair",
      notAKey:
        '[unjwt/session] Invalid JWE session key: expected an "oct" JWK, a JWK Set of them or a secret CryptoKey.',
    },
  ];

  const roundTrip = async (session: Definition) =>
    (await session.open(await session.issue({ user: "ada" }))).data;

  it.each(RULES)(
    "$family: refuses a lone asymmetric key, and what is not a key",
    async ({ define, label, asymmetric, instead, notAKey }) => {
      const pairs = await asymmetric();
      for (const key of pairs.flatMap(({ privateKey, publicKey }) => [privateKey, publicKey])) {
        const { code, message } = refusedWith(() => define({ key }));
        expect(code).toBe("ERR_SESSION_KEY_INVALID");
        expect(message).toContain(`Invalid ${label} session key: an asymmetric key`);
        expect(message).toContain(instead);
      }
      for (const key of [42, true, {}, { kty: "oct" }]) {
        expect(refusedWith(() => define({ key }))).toEqual({
          code: "ERR_SESSION_KEY_INVALID",
          message: notAKey,
        });
      }
    },
  );

  it.each(RULES)(
    "$family: refuses a key that names no algorithm without its pin, and issues with the pin",
    async ({ define, silent, hint }) => {
      const { crypto, jwk, pin } = await silent();
      const unnamed = `[unjwt/session] The session key names no algorithm, set ${hint}`;
      expect(refusedWith(() => define({ key: crypto }))).toEqual({
        code: "ERR_SESSION_CONFIG_INVALID",
        message: `${unnamed}.`,
      });
      expect(refusedWith(() => define({ key: jwk }))).toEqual({
        code: "ERR_SESSION_CONFIG_INVALID",
        message: `${unnamed}, or its "alg".`,
      });
      for (const key of [crypto, jwk]) {
        expect(await roundTrip(define({ key, ...pin }))).toEqual({ user: "ada" });
      }
    },
  );

  it.each(RULES)(
    "$family: refuses a pin that the JWK's alg or the CryptoKey's algorithm cannot serve",
    async ({ define, key, alg, mismatch, pinning, pinPath }) => {
      const { crypto, pin } = await mismatch();
      for (const refused of [key, crypto]) {
        expect(refusedWith(() => define({ key: refused, ...pinning(pin) }))).toEqual({
          code: "ERR_SESSION_KEY_INVALID",
          message: `[unjwt/session] The session key serves ${alg}, not the "${pin}" that "${pinPath}" pins.`,
        });
      }
    },
  );

  it.each(RULES)(
    "$family: refuses an empty algorithms list, and one naming an algorithm no key serves unless onKeyLookup is set",
    ({ define, key, listing, listPath, dead }) => {
      const hooks = { onKeyLookup: () => key };
      for (const withLookup of [undefined, hooks]) {
        expect(refusedWith(() => define({ ...listing([]), hooks: withLookup }))).toEqual({
          code: "ERR_SESSION_CONFIG_INVALID",
          message: `[unjwt/session] "${listPath}" is empty, list the algorithms the session keys serve or leave it unset.`,
        });
      }
      expect(refusedWith(() => define(listing([dead])))).toEqual({
        code: "ERR_SESSION_CONFIG_INVALID",
        message: `[unjwt/session] "${listPath}" lists "${dead}", which no session key serves. Remove it, or add a key for it.`,
      });
      expect(() => define({ ...listing([dead]), hooks })).not.toThrow();
    },
  );

  it.each(RULES)(
    "$family: passes onKeyLookup the header, the config and the event, and opens with the JWK it returns",
    async ({ define, key, alg }) => {
      const onKeyLookup = vi.fn((_args: Record<string, unknown>) => key);
      const session = define({ hooks: { onKeyLookup } });
      const token = await session.issue({ user: "ada" });
      const event = { req: get({ cookie: `web=${token}` }) };

      expect((await session.use(event)).data).toEqual({ user: "ada" });
      expect((await session.open(token)).data).toEqual({ user: "ada" });
      const [[read], [opened]] = onKeyLookup.mock.calls;
      expect(Object.keys(read).toSorted()).toEqual(["config", "event", "header"]);
      expect(read.event).toBe(event);
      expect(read.header).toMatchObject({ alg, typ: "session+jwt" });
      expect(read.config).toMatchObject({ name: "web", key });
      expect(Object.keys(opened).toSorted()).toEqual(["config", "header"]);
    },
  );

  it.each(RULES)(
    "$family: fails the token when onKeyLookup throws, returns nothing or returns a key that does not import",
    async ({ define, key }) => {
      const token = await define().issue({ user: "ada" });
      const boom = new Error("boom");
      const lookups = [
        {
          onKeyLookup: () => {
            throw boom;
          },
          cause: "ERR_JWK_KEY_NOT_FOUND",
          inner: boom,
          keeps: true,
        },
        {
          onKeyLookup: () => undefined,
          cause: "ERR_JWK_KEY_NOT_FOUND",
          inner: undefined,
          keeps: false,
        },
        {
          onKeyLookup: () => ({ ...key, k: "!!!" }),
          cause: "ERR_JWK_INVALID",
          inner: expect.anything(),
          keeps: false,
        },
      ] as const;
      for (const { onKeyLookup, cause, inner, keeps } of lookups) {
        const onError = vi.fn();
        const session = define({ hooks: { onKeyLookup, onError } });
        const error = await caught(session.open(token));
        expect(isJWTError(error, "ERR_SESSION_TOKEN_INVALID")).toBe(true);
        expect(isJWTError((error as Error).cause, cause)).toBe(true);
        expect(((error as Error).cause as Error).cause).toEqual(inner);

        const headers = new Headers();
        const manager = await session.use({
          req: get({ cookie: `web=${token}` }),
          res: { headers },
        });
        expect(manager.id).toBeUndefined();
        expect(onError).toHaveBeenCalledOnce();
        expect(linesOf(headers, "web")).toHaveLength(keeps ? 0 : 1);
      }
    },
  );
});

interface RingCase {
  family: Family;
  define: (config: Record<string, unknown>) => Definition;
  /** An `oct` JWK of the family's ring algorithm, with `kid` when given. */
  key: (kid?: string) => Promise<JWK_oct>;
  /** An `oct` JWK of another algorithm than the ring's, and that algorithm. */
  other: () => Promise<{ key: JWK_oct; alg: string }>;
  /** An `oct` JWK without `alg`, the pin that mints with it, and the algorithm it pins. */
  silent: () => Promise<{ key: JWK_oct; pin: Record<string, unknown>; alg: string }>;
  /** The algorithms the material of `silent` carries, as a message lists them. */
  carries: string;
  /** A secret `CryptoKey` of another algorithm than the ring's, and that algorithm. */
  crypto: () => Promise<{ key: CryptoKey; alg: string }>;
  /** An `oct` JWK of the other family. */
  foreign: () => Promise<JWK_oct>;
  /** The algorithm of `key`, the options that pin an algorithm, and an algorithm no ring key serves. */
  alg: string;
  pinning: (alg: string) => Record<string, unknown>;
  dead: string;
  /** The options an incoming token is opened with, and the option paths messages name. */
  opening: (options: Record<string, unknown>) => Record<string, unknown>;
  listPath: string;
  limitPath: string;
  notAllowed: KnownJWTErrorCode;
  failed: KnownJWTErrorCode;
}

const withKid = (key: JWK_oct, kid?: string): JWK_oct => {
  const { kid: _kid, ...rest } = key;
  return kid === undefined ? rest : { ...rest, kid };
};
const oldWithoutAlg = ({ alg: _alg, ...key }: JWK_oct): JWK_oct => withKid(key, "old");

const RINGS: RingCase[] = [
  {
    family: "jws",
    define: (config) => defineJWSSession({ name: "web", key: jwsKey, ...config }),
    key: async (kid) => withKid(await generateJWK("HS256"), kid),
    other: async () => ({ key: withKid(await generateJWK("HS512"), "old"), alg: "HS512" }),
    silent: async () => ({
      key: oldWithoutAlg(await generateJWK("HS512")),
      pin: { jws: { signOptions: { alg: "HS384" } } },
      alg: "HS384",
    }),
    carries: "HS256, HS384, HS512",
    crypto: async () => ({ key: await generateKey("HS512"), alg: "HS512" }),
    foreign: () => generateJWK("A128KW"),
    alg: "HS256",
    pinning: (alg) => ({ jws: { signOptions: { alg } } }),
    dead: "ES256",
    opening: (options) => ({ jws: { verifyOptions: options } }),
    listPath: "jws.verifyOptions.algorithms",
    limitPath: "jws.verifyOptions.limits.keyCandidates",
    notAllowed: "ERR_JWS_ALG_NOT_ALLOWED",
    failed: "ERR_JWS_SIGNATURE_INVALID",
  },
  {
    family: "jwe",
    define: (config) => defineJWESession({ name: "web", key: jweKey, ...config }),
    key: async (kid) => withKid(await generateJWK("A256KW"), kid),
    other: async () => ({ key: withKid(await generateJWK("A128KW"), "old"), alg: "A128KW" }),
    silent: async () => ({
      key: oldWithoutAlg(await generateJWK("A256KW")),
      pin: { jwe: { encryptOptions: { alg: "A256GCMKW", enc: "A256GCM" } } },
      alg: "A256GCMKW",
    }),
    carries: "A256KW, A256GCMKW, dir",
    crypto: async () => ({ key: await generateKey("A128KW"), alg: "A128KW" }),
    foreign: () => generateJWK("HS256"),
    alg: "A256KW",
    pinning: (alg) => ({ jwe: { encryptOptions: { alg, enc: "A256GCM" } } }),
    dead: "A192KW",
    opening: (options) => ({ jwe: { decryptOptions: options } }),
    listPath: "jwe.decryptOptions.algorithms",
    limitPath: "jwe.decryptOptions.limits.keyCandidates",
    notAllowed: "ERR_JWE_ALG_NOT_ALLOWED",
    failed: "ERR_JWE_DECRYPTION_FAILED",
  },
];

const mint = (ring: RingCase, key: JWK_oct, config?: Record<string, unknown>) =>
  ring.define({ key, ...config }).issue({ user: "ada" });
const refusal = async (session: Definition, token: string) => {
  const error = await caught(session.open(token));
  expect(isJWTError(error, "ERR_SESSION_TOKEN_INVALID")).toBe(true);
  return error as Error;
};

describe("key rotation through onKeyLookup", () => {
  it.each(RINGS)("$family: opens a token of the old key and issues under current", async (ring) => {
    const [current, old] = await Promise.all([ring.key("current"), ring.key("old")]);
    const onKeyLookup = vi.fn(() => ({ keys: [current, old] }));
    const session = ring.define({ key: current, hooks: { onKeyLookup } });
    const issued = await session.issue({ user: "ada" });
    const former = await mint(ring, old);

    expect(JSON.parse(atob(issued.split(".")[0])).kid).toBe("current");
    expect((await session.open(issued)).data).toEqual({ user: "ada" });
    expect((await session.open(former)).data).toEqual({ user: "ada" });
    const read = await session.use({ req: get({ cookie: `web=${former}` }) });
    expect(read.data).toEqual({ user: "ada" });
    expect(onKeyLookup).toHaveBeenLastCalledWith(
      expect.objectContaining({ header: expect.objectContaining({ kid: "old" }) }),
    );
  });

  it.each(RINGS)("$family: refuses a token whose kid names no key", async (ring) => {
    const [current, old, stranger] = await Promise.all([
      ring.key("current"),
      ring.key("old"),
      ring.key("stranger"),
    ]);
    const onError = vi.fn();
    const session = ring.define({
      key: current,
      hooks: { onError, onKeyLookup: () => ({ keys: [current, old] }) },
    });
    const token = await mint(ring, stranger);

    expect((await session.use({ req: get({ cookie: `web=${token}` }) })).id).toBeUndefined();
    expect(onError).toHaveBeenCalledOnce();
    const error = await refusal(session, token);
    expect(error.message).toBe(
      '[unjwt/session] Invalid session token: No key found in JWK Set with kid "stranger".',
    );
    expect(isJWTError(error.cause, "ERR_JWK_KEY_NOT_FOUND")).toBe(true);
  });

  it.each(RINGS)("$family: a ring without current fails a fresh token", async (ring) => {
    const [current, old] = await Promise.all([ring.key("current"), ring.key("old")]);
    const session = ring.define({ key: current, hooks: { onKeyLookup: () => ({ keys: [old] }) } });

    const error = await refusal(session, await session.issue({ user: "ada" }));
    expect(error.message).toBe(
      '[unjwt/session] Invalid session token: No key found in JWK Set with kid "current".',
    );
  });

  it.each(RINGS)(
    "$family: opens an old key of another alg once algorithms lists it",
    async (ring) => {
      const [current, { key: old, alg }] = await Promise.all([ring.key("current"), ring.other()]);
      const token = await mint(ring, old);
      const hooks = { onKeyLookup: () => ({ keys: [current, old] }) };

      const error = await refusal(ring.define({ key: current, hooks }), token);
      expect(isJWTError(error.cause, ring.notAllowed)).toBe(true);
      const listed = ring.define({ key: current, hooks, ...ring.opening({ algorithms: [alg] }) });
      expect((await listed.open(token)).data).toEqual({ user: "ada" });
    },
  );

  it.each(RINGS)(
    "$family: refuses an old key without alg unless algorithms lists what it serves",
    async (ring) => {
      const [current, { key: old, pin, alg }] = await Promise.all([
        ring.key("current"),
        ring.silent(),
      ]);
      const token = await mint(ring, old, pin);
      const hooks = { onKeyLookup: () => ({ keys: [current, old] }) };

      const error = await refusal(ring.define({ key: current, hooks }), token);
      expect(isJWTError(error.cause, ring.notAllowed)).toBe(true);
      const listed = ring.define({ key: current, hooks, ...ring.opening({ algorithms: [alg] }) });
      expect((await listed.open(token)).data).toEqual({ user: "ada" });
    },
  );

  it.each(RINGS)(
    "$family: opens a token of a CryptoKey it returns once algorithms names what the key serves",
    async (ring) => {
      const [current, { key: old, alg }] = await Promise.all([ring.key("current"), ring.crypto()]);
      const token = await ring.define({ key: old, ...ring.pinning(alg) }).issue({ user: "ada" });
      const hooks = { onKeyLookup: () => old };

      const error = await refusal(ring.define({ key: current, hooks }), token);
      expect(isJWTError(error.cause, ring.notAllowed)).toBe(true);
      const listed = ring.define({ key: current, hooks, ...ring.opening({ algorithms: [alg] }) });
      expect((await listed.open(token)).data).toEqual({ user: "ada" });
    },
  );

  it("types its return as the key shapes key takes for opening, a CryptoKey included", () => {
    type JWSLookup = NonNullable<SessionHooksJWS["onKeyLookup"]>;
    type JWELookup = NonNullable<SessionHooksJWE["onKeyLookup"]>;
    expectTypeOf<JWSLookup>().toEqualTypeOf<JWSSessionKeyLookup>();
    expectTypeOf<JWELookup>().toEqualTypeOf<JWESessionKeyLookup>();
    expectTypeOf<Parameters<JWSLookup>[0]>().toEqualTypeOf<{
      header: JWSHeaderParameters;
      config: SessionConfigJWS;
      event?: WebSessionEvent;
    }>();
    expectTypeOf<JWK_oct<JWK_HMAC> | CryptoKey | JWKSet>().toExtend<ReturnType<JWSLookup>>();
    expectTypeOf<Promise<CryptoKey>>().toExtend<ReturnType<JWSLookup>>();
    expectTypeOf<JWESessionOctJWK | CryptoKey | JWKSet>().toExtend<ReturnType<JWELookup>>();
    expectTypeOf<Promise<CryptoKey>>().toExtend<ReturnType<JWELookup>>();
  });

  it.each(RINGS)(
    "$family: tries a ring without kid in order and reports each key's failure",
    async (ring) => {
      const keys = await Promise.all([ring.key(), ring.key(), ring.key()]);
      const session = ring.define({ key: keys[0], hooks: { onKeyLookup: () => ({ keys }) } });
      const stranger = await mint(ring, await ring.key());
      const imported = vi.spyOn(crypto.subtle, "importKey");
      try {
        const error = await refusal(session, stranger);
        expect(rawImports(imported.mock.calls)).toEqual(keys.map((key) => key.k));
        expect(isJWTError(error.cause, ring.failed)).toBe(true);
        expect((error.cause as Error).cause).toHaveLength(3);
      } finally {
        imported.mockRestore();
      }
    },
  );
});

describe("key rotation with a JWK Set", () => {
  const header = (token: string) => JSON.parse(atob(token.split(".")[0]));

  it.each(RINGS)(
    "$family: issues with the first key and opens a token of an older key of another alg",
    async (ring) => {
      const [current, { key: old }] = await Promise.all([ring.key("current"), ring.other()]);
      const session = ring.define({ key: { keys: [current, old] } });
      const issued = await session.issue({ user: "ada" });
      const former = await mint(ring, old);

      expect(header(issued)).toMatchObject({ kid: "current", alg: ring.alg });
      expect((await session.open(issued)).data).toEqual({ user: "ada" });
      expect((await session.open(former)).data).toEqual({ user: "ada" });
      const read = await session.use({ req: get({ cookie: `web=${former}` }) });
      expect(read.data).toEqual({ user: "ada" });
    },
  );

  it.each(RINGS)(
    "$family: opens an older key without alg only when algorithms lists what it serves",
    async (ring) => {
      const [current, { key: old, pin, alg }] = await Promise.all([
        ring.key("current"),
        ring.silent(),
      ]);
      const key = { keys: [current, old] };
      expect(refusedWith(() => ring.define({ key }))).toEqual({
        code: "ERR_SESSION_CONFIG_INVALID",
        message: `[unjwt/session] The session key "keys[1]" (kid "old") names no algorithm, list one it serves (${ring.carries}) in "${ring.listPath}", or set its "alg".`,
      });
      const session = ring.define({ key, ...ring.opening({ algorithms: [alg] }) });
      expect((await session.open(await mint(ring, old, pin))).data).toEqual({ user: "ada" });
    },
  );

  it.each(RINGS)(
    "$family: refuses a Set that is empty or holds what is not its family's key",
    async (ring) => {
      const [current, foreign] = await Promise.all([ring.key("current"), ring.foreign()]);
      const crypto = await generateKey("HS256");
      expect(refusedWith(() => ring.define({ key: { keys: [] } }))).toEqual({
        code: "ERR_SESSION_KEY_INVALID",
        message: "[unjwt/session] The session key is an empty JWK Set.",
      });
      expect(refusedWith(() => ring.define({ key: { keys: [current, crypto] } }))).toEqual({
        code: "ERR_SESSION_KEY_INVALID",
        message: '[unjwt/session] The session key "keys[1]" must be an "oct" JWK.',
      });
      expect(
        refusedWith(() =>
          ring.define({ key: { keys: [current, { ...foreign, kid: "foreign" }] } }),
        ),
      ).toEqual({
        code: "ERR_SESSION_KEY_INVALID",
        message: '[unjwt/session] The session key "keys[1]" (kid "foreign") serves no algorithm.',
      });
    },
  );

  it.each(RINGS)(
    "$family: refuses more keys without kid than limits.keyCandidates",
    async (ring) => {
      const keys = await Promise.all(Array.from({ length: 9 }, () => ring.key()));
      expect(refusedWith(() => ring.define({ key: { keys } }))).toEqual({
        code: "ERR_SESSION_CONFIG_INVALID",
        message: `[unjwt/session] The session key "keys[0]" carries no "kid", so a token of "${ring.alg}" meets 9 keys, over the limit of 8 ("${ring.limitPath}").`,
      });
      const raised = ring.define({
        key: { keys },
        ...ring.opening({ limits: { keyCandidates: 9 } }),
      });
      expect((await raised.open(await raised.issue({ user: "ada" }))).data).toEqual({
        user: "ada",
      });
    },
  );

  it.each(RINGS)(
    "$family: counts every key of its alg that a token without kid meets",
    async (ring) => {
      const named = (alg: () => Promise<JWK_oct>) =>
        Promise.all(
          Array.from({ length: 9 }, async (_, index) => withKid(await alg(), `k${index}`)),
        );
      const kidless = await Promise.all([ring.key(), ring.key()]);
      const same = await named(() => ring.key());
      expect(refusedWith(() => ring.define({ key: { keys: [...kidless, ...same] } }))).toEqual({
        code: "ERR_SESSION_CONFIG_INVALID",
        message: `[unjwt/session] The session key "keys[0]" carries no "kid", so a token of "${ring.alg}" meets 11 keys, over the limit of 8 ("${ring.limitPath}").`,
      });
      const other = await named(async () => (await ring.other()).key);
      const session = ring.define({ key: { keys: [...kidless, ...other] } });
      expect((await session.open(await session.issue({ user: "ada" }))).data).toEqual({
        user: "ada",
      });
    },
  );

  it.each(RINGS)(
    "$family: counts a key without kid or alg under each alg it serves",
    async (ring) => {
      const [{ key: old, alg }, ...named] = await Promise.all([
        ring.silent(),
        ...Array.from({ length: 8 }, (_, index) => ring.key(`k${index}`)),
      ]);
      const key = { keys: [...named, withKid(old)] };
      for (const algorithms of [[ring.alg], [alg, ring.alg]]) {
        expect(refusedWith(() => ring.define({ key, ...ring.opening({ algorithms }) }))).toEqual({
          code: "ERR_SESSION_CONFIG_INVALID",
          message: `[unjwt/session] The session key "keys[8]" carries no "kid", so a token of "${ring.alg}" meets 9 keys, over the limit of 8 ("${ring.limitPath}").`,
        });
      }
      expect(() => ring.define({ key, ...ring.opening({ algorithms: [alg] }) })).not.toThrow();
    },
  );

  it.each(RINGS)("$family: refuses an algorithms entry no key of the Set serves", async (ring) => {
    const [current, { key: old }] = await Promise.all([ring.key("current"), ring.other()]);
    const key = { keys: [current, old] };
    expect(
      refusedWith(() => ring.define({ key, ...ring.opening({ algorithms: [ring.dead] }) })),
    ).toEqual({
      code: "ERR_SESSION_CONFIG_INVALID",
      message: `[unjwt/session] "${ring.listPath}" lists "${ring.dead}", which no session key serves. Remove it, or add a key for it.`,
    });
  });

  it.each(RINGS)("$family: refuses a token whose kid names no key of the Set", async (ring) => {
    const [current, old, stranger] = await Promise.all([
      ring.key("current"),
      ring.key("old"),
      ring.key("stranger"),
    ]);
    const session = ring.define({ key: { keys: [current, old] } });
    const error = await refusal(session, await mint(ring, stranger));
    expect(error.message).toBe(
      '[unjwt/session] Invalid session token: No key found in JWK Set with kid "stranger".',
    );
    expect(isJWTError(error.cause, "ERR_JWK_KEY_NOT_FOUND")).toBe(true);
  });

  it.each(RINGS)("$family: holds the pin to the first key alone", async (ring) => {
    const [current, { key: old, alg }] = await Promise.all([ring.key("current"), ring.other()]);
    const key = { keys: [current, old] };
    expect(refusedWith(() => ring.define({ key, ...ring.pinning(alg) }))).toEqual({
      code: "ERR_SESSION_KEY_INVALID",
      message: `[unjwt/session] The session key "keys[0]" (kid "current") serves ${ring.alg}, not the "${alg}" that "${ring.family}.${ring.family === "jws" ? "signOptions" : "encryptOptions"}.alg" pins.`,
    });
    const pinned = ring.define({ key, ...ring.pinning(ring.alg) });
    expect((await pinned.open(await pinned.issue({ user: "ada" }))).data).toEqual({ user: "ada" });
    expect((await pinned.open(await mint(ring, old))).data).toEqual({ user: "ada" });
  });

  it("types: a JWK Set of the family's oct JWKs, never the other family's", () => {
    expectTypeOf<JWKSet<JWK_oct<JWK_HMAC>[]>>().toExtend<JWSSessionKey>();
    expectTypeOf<{ keys: (typeof jwsKey)[] }>().toExtend<JWSSessionKey>();
    expectTypeOf<JWKSet<JWESessionOctJWK[]>>().toExtend<JWESessionKey>();
    expectTypeOf<{ keys: (typeof jweKey)[] }>().toExtend<JWESessionKey>();
    expectTypeOf<{ keys: (typeof jweKey)[] }>().not.toExtend<JWSSessionKey>();
    expectTypeOf<{ keys: (typeof jwsKey)[] }>().not.toExtend<JWESessionKey>();
    expectTypeOf<{ keys: CryptoKey[] }>().not.toExtend<JWSSessionKey>();
    expectTypeOf<{ keys: CryptoKey[] }>().not.toExtend<JWESessionKey>();
  });
});

/** The base64url secrets `crypto.subtle.importKey` was handed as raw bytes, in call order. */
function rawImports(calls: readonly unknown[][]): string[] {
  return calls
    .filter(([format, data]) => format === "raw" && data instanceof Uint8Array)
    .map(([, data]) => base64UrlStringify(data as Uint8Array));
}
