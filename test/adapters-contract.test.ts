import supertest from "supertest";
import { describe, it, expect, vi } from "vitest";
import { H3 } from "h3v2";
import { createApp, createRouter, createError, toNodeListener, eventHandler, type App } from "h3v1";
import { Elysia } from "elysia";

import { isJWTError } from "../src/core/error";
import { generateJWK } from "../src/core/jwk";
import { sign } from "../src/core/jws";
import { encrypt } from "../src/core/jwe";
import {
  useJWSSession as useJWSSessionV2,
  useJWESession as useJWESessionV2,
} from "../src/adapters/h3v2";
import {
  useJWSSession as useJWSSessionV1,
  useJWESession as useJWESessionV1,
} from "../src/adapters/h3v1";
import { MAX_CHUNK_COUNT } from "../src/adapters/_chunked-cookie";
import { createJWSSession, jwsSession } from "../src/adapters/elysia/session/jws";
import { createJWESession } from "../src/adapters/elysia/session/jwe";
import type { SessionContext } from "../src/adapters/elysia/session/types";
import type { CookieAttributes } from "../src/adapters/elysia/_cookie";

const [jwsKey, jweKey] = await Promise.all([generateJWK("HS256"), generateJWK("A128KW")]);
// PBES2 derives its key from the JWK's bytes, so the JWK declares the PBES2 alg itself.
const pbes2Key = { ...jweKey, alg: "PBES2-HS256+A128KW" } as const;

const SECOND = 1000;
const nowSeconds = () => Math.floor(Date.now() / 1000);

/** A token signed with the session key but minted by something other than the adapter. */
function foreignJWS(claims: Record<string, unknown>, header: Record<string, unknown> = {}) {
  return sign(claims, jwsKey, { protectedHeader: { typ: "JWT", ...header } });
}

/**
 * A JWT whose protected header carries no `cty`: the core writes that default
 * only for object payloads, so the claims go over the wire as raw bytes.
 */
function rawBytes(claims: Record<string, unknown>): Uint8Array<ArrayBuffer> {
  return new TextEncoder().encode(JSON.stringify(claims)) as Uint8Array<ArrayBuffer>;
}

interface MockEntry {
  value: unknown;
  lastWrite?: CookieAttributes & { value: string };
}

function elysiaContext(
  options: { cookies?: Record<string, string>; headers?: Record<string, string> } = {},
) {
  const store = new Map<string, MockEntry>();
  for (const [name, value] of Object.entries(options.cookies ?? {})) store.set(name, { value });

  const cookie = new Proxy({} as SessionContext["cookie"], {
    get(_target, property: string) {
      return {
        get value() {
          return store.get(property)?.value;
        },
        set(config: CookieAttributes & { value: string }) {
          store.set(property, { value: config.value, lastWrite: config });
        },
      };
    },
  });

  return {
    context: { cookie, request: { headers: new Headers(options.headers ?? {}) } } as SessionContext,
    store,
  };
}

async function caught(run: () => Promise<unknown>): Promise<unknown> {
  try {
    await run();
  } catch (error) {
    return error;
  }
  return undefined;
}

/**
 * Fail rather than hang. A hook that reads the same session it was dispatched
 * from would otherwise await a promise that is waiting on the hook itself, and
 * the request would never settle.
 */
function within<T>(promise: Promise<T> | T, label: string, ms = 2000): Promise<T> {
  return Promise.race([
    Promise.resolve(promise),
    new Promise<never>((_resolve, reject) =>
      setTimeout(() => reject(new Error(`${label} did not settle within ${ms}ms`)), ms),
    ),
  ]);
}

/** Session data long enough to need `count` cookie chunks at `chunkMaxLength`. */
function bulkyData(count: number, chunkMaxLength: number): Record<string, string> {
  return { pad: "x".repeat(count * chunkMaxLength) };
}

const EXPIRED_CLAIMS = {
  jti: "expired-session",
  iat: nowSeconds() - 120,
  exp: nowSeconds() - 60,
};

describe("session adapters — shared contract", () => {
  // #region h3 v2
  describe("h3 v2", () => {
    const jwsConfig = { name: "contract-jws", key: jwsKey } as const;
    const jweConfig = { name: "contract-jwe", key: jweKey } as const;

    function tokenApp() {
      const app = new H3({ debug: true });
      app.post("/mint", async (event) => {
        const session = await useJWSSessionV2(event, jwsConfig);
        await session.update(await event.req.json());
        return { token: session.token };
      });
      app.get("/read", async (event) => {
        const session = await useJWSSessionV2(event, jwsConfig);
        return { who: (session.data as Record<string, unknown>).who ?? null };
      });
      return app;
    }

    async function mint(app: H3, who: string): Promise<string> {
      const response = await app.request("/mint", {
        method: "POST",
        body: JSON.stringify({ who }),
      });
      return ((await response.json()) as { token: string }).token;
    }

    it("reads the cookie in preference to the session header", async () => {
      const app = tokenApp();
      const cookieToken = await mint(app, "cookie");
      const headerToken = await mint(app, "header");

      const response = await app.request("/read", {
        headers: {
          "cookie": `contract-jws=${cookieToken}`,
          "x-contract-jws-session": `Bearer ${headerToken}`,
        },
      });

      expect(await response.json()).toEqual({ who: "cookie" });
    });

    it("falls back to the session header when no cookie carries a token", async () => {
      const app = tokenApp();
      const headerToken = await mint(app, "header");

      const response = await app.request("/read", {
        headers: { "x-contract-jws-session": headerToken },
      });

      expect(await response.json()).toEqual({ who: "header" });
    });

    it("a blank session header never hides the cookie", async () => {
      const app = tokenApp();
      const cookieToken = await mint(app, "cookie");

      const response = await app.request("/read", {
        headers: {
          "cookie": `contract-jws=${cookieToken}`,
          "x-contract-jws-session": "   ",
        },
      });

      expect(await response.json()).toEqual({ who: "cookie" });
    });

    it("matches the Bearer prefix case-insensitively", async () => {
      const app = tokenApp();
      const headerToken = await mint(app, "header");

      const response = await app.request("/read", {
        headers: { "x-contract-jws-session": `bearer ${headerToken}` },
      });

      expect(await response.json()).toEqual({ who: "header" });
    });

    it("rejects a session with neither a cookie nor a header to read from", async () => {
      const app = new H3({ debug: true });
      app.get("/", async (event) => {
        const error = await caught(() =>
          useJWSSessionV2(event, { ...jwsConfig, cookie: false, sessionHeader: false }),
        );
        return { config: isJWTError(error, "ERR_SESSION_CONFIG_INVALID") };
      });

      expect(await (await app.request("/")).json()).toEqual({ config: true });
    });

    it("rejects a password string where key material is required", async () => {
      const app = new H3({ debug: true });
      app.get("/", async (event) => {
        const error = await caught(() =>
          useJWESessionV2(event, { name: "contract-jwe-str", key: "a password" as never }),
        );
        return {
          key: isJWTError(error, "ERR_SESSION_KEY_INVALID"),
          message: (error as Error).message,
        };
      });

      const body = (await (await app.request("/")).json()) as { key: boolean; message: string };
      expect(body.key).toBe(true);
      expect(body.message).toMatch(/deriveJWKFromPassword/);
    });

    it("strips the adapter-owned claims from an update payload", async () => {
      const app = new H3({ debug: true });
      app.get("/", async (event) => {
        const session = await useJWSSessionV2(event, jwsConfig);
        await session.update({
          user: "alice",
          jti: "forged",
          iat: 1,
          exp: 2,
          nbf: 3,
        } as never);
        return { data: session.data, id: session.id };
      });

      const body = (await (await app.request("/")).json()) as {
        data: Record<string, unknown>;
        id: string;
      };
      expect(body.data).toEqual({ user: "alice" });
      expect(body.id).not.toBe("forged");
    });

    it("strips the adapter-owned claims from an updater function's result", async () => {
      const app = new H3({ debug: true });
      app.get("/", async (event) => {
        const session = await useJWSSessionV2(event, jwsConfig);
        await session.update(() => ({ user: "bob", exp: 2 }) as never);
        return { data: session.data };
      });

      expect(await (await app.request("/")).json()).toEqual({ data: { user: "bob" } });
    });

    it("rejects prototype-poisoning keys in an update", async () => {
      const app = new H3({ debug: true });
      app.get("/", async (event) => {
        const session = await useJWSSessionV2(event, jwsConfig);
        const error = await caught(() =>
          session.update({ ["__proto__"]: { admin: true } } as never),
        );
        return {
          option: isJWTError(error, "ERR_INVALID_OPTION"),
          message: (error as Error).message,
        };
      });

      const body = (await (await app.request("/")).json()) as { option: boolean; message: string };
      expect(body.option).toBe(true);
      expect(body.message).toMatch(/__proto__/);
    });

    it("gives one issue a lifetime of its own", async () => {
      const app = new H3({ debug: true });
      app.get("/", async (event) => {
        const session = await useJWSSessionV2(event, { ...jwsConfig, maxAge: 60 });
        const before = session.expiresAt;
        await session.update({ user: "alice" }, { maxAge: 3600 });
        return { before, after: session.expiresAt, createdAt: session.createdAt };
      });

      const body = (await (await app.request("/")).json()) as {
        before: number;
        after: number;
        createdAt: number;
      };
      expect(body.after - body.createdAt).toBe(3600 * SECOND);
      expect(body.before).toBeLessThan(body.after);
    });

    it("refuses a year-old foreign JWT signed with the session key", async () => {
      const onError = vi.fn();
      const token = await foreignJWS({
        jti: "foreign",
        iat: nowSeconds() - 365 * 24 * 60 * 60,
        sub: "attacker",
      });

      const app = new H3({ debug: true });
      app.get("/", async (event) => {
        const session = await useJWSSessionV2(event, {
          ...jwsConfig,
          maxAge: 3600,
          hooks: { onError },
        });
        return { id: session.id ?? null };
      });

      const response = await app.request("/", {
        headers: { cookie: `contract-jws=${token}` },
      });

      expect(await response.json()).toEqual({ id: null });
      expect(isJWTError(onError.mock.calls[0]![0].error, "ERR_SESSION_TOKEN_INVALID")).toBe(true);
    });

    it("refuses a token that carries no session content marker", async () => {
      const onError = vi.fn();
      const token = await sign(rawBytes({ jti: "foreign", iat: nowSeconds() }), jwsKey, {
        protectedHeader: { typ: "JWT" },
      });

      const app = new H3({ debug: true });
      app.get("/", async (event) => {
        const session = await useJWSSessionV2(event, { ...jwsConfig, hooks: { onError } });
        return { id: session.id ?? null };
      });

      await app.request("/", { headers: { cookie: `contract-jws=${token}` } });

      const error = onError.mock.calls[0]![0].error;
      expect(isJWTError(error, "ERR_SESSION_TOKEN_INVALID")).toBe(true);
      expect(error.message).toMatch(/cty/);
    });

    it("refuses a token without exp when the session has a maxAge", async () => {
      const onError = vi.fn();
      const token = await foreignJWS(
        { jti: "foreign", iat: nowSeconds() },
        { cty: "application/json" },
      );

      const app = new H3({ debug: true });
      app.get("/", async (event) => {
        const session = await useJWSSessionV2(event, {
          ...jwsConfig,
          maxAge: 3600,
          hooks: { onError },
        });
        return { id: session.id ?? null };
      });

      await app.request("/", { headers: { cookie: `contract-jws=${token}` } });

      expect(isJWTError(onError.mock.calls[0]![0].error, "ERR_SESSION_TOKEN_INVALID")).toBe(true);
    });

    it("refuses a token whose content marker is not the session one", async () => {
      const onError = vi.fn();
      const token = await foreignJWS({ jti: "foreign", iat: nowSeconds() }, { cty: "text/plain" });

      const app = new H3({ debug: true });
      app.get("/", async (event) => {
        const session = await useJWSSessionV2(event, { ...jwsConfig, hooks: { onError } });
        return { id: session.id ?? null };
      });

      await app.request("/", { headers: { cookie: `contract-jws=${token}` } });

      const error = onError.mock.calls[0]![0].error;
      expect(isJWTError(error, "ERR_SESSION_TOKEN_INVALID")).toBe(true);
      expect(error.message).toMatch(/cty/);
    });

    it("keeps the underlying failure as the cause of an invalid token", async () => {
      const onError = vi.fn();
      const otherKey = await generateJWK("HS256");
      const token = await sign({ jti: "foreign", iat: nowSeconds() }, otherKey, {
        protectedHeader: { typ: "JWT", cty: "application/json" },
      });

      const app = new H3({ debug: true });
      app.get("/", async (event) => {
        const session = await useJWSSessionV2(event, { ...jwsConfig, hooks: { onError } });
        return { id: session.id ?? null };
      });

      await app.request("/", { headers: { cookie: `contract-jws=${token}` } });

      const error = onError.mock.calls[0]![0].error;
      expect(isJWTError(error, "ERR_SESSION_TOKEN_INVALID")).toBe(true);
      expect(isJWTError(error.cause, "ERR_JWS_SIGNATURE_INVALID")).toBe(true);
    });

    it("refuses a JWE session token that carries no session content marker", async () => {
      const onError = vi.fn();
      const token = await encrypt(rawBytes({ jti: "foreign", iat: nowSeconds() }), jweKey, {
        protectedHeader: { typ: "JWT" },
      });

      const app = new H3({ debug: true });
      app.get("/", async (event) => {
        const session = await useJWESessionV2(event, { ...jweConfig, hooks: { onError } });
        return { id: session.id ?? null };
      });

      await app.request("/", { headers: { cookie: `contract-jwe=${token}` } });

      expect(isJWTError(onError.mock.calls[0]![0].error, "ERR_SESSION_TOKEN_INVALID")).toBe(true);
    });

    it("does not restore a cleared session from the request cookie", async () => {
      const app = new H3({ debug: true });
      const minted = tokenApp();
      const token = await mint(minted, "cookie");

      app.get("/", async (event) => {
        const session = await useJWSSessionV2(event, jwsConfig);
        await session.clear();
        const again = await useJWSSessionV2(event, jwsConfig);
        return { id: again.id ?? null, token: again.token ?? null, data: again.data };
      });

      const response = await app.request("/", {
        headers: { cookie: `contract-jws=${token}` },
      });

      expect(await response.json()).toEqual({ id: null, token: null, data: {} });
    });

    it("does not read an unrelated Set-Cookie as the session token", async () => {
      const app = tokenApp();
      const headerToken = await mint(app, "header");

      const reader = new H3({ debug: true });
      reader.get("/", async (event) => {
        event.res.headers.append("set-cookie", "unrelated=value; Path=/");
        const session = await useJWSSessionV2(event, jwsConfig);
        return { who: (session.data as Record<string, unknown>).who ?? null };
      });

      const response = await reader.request("/", {
        headers: { "x-contract-jws-session": headerToken },
      });

      expect(await response.json()).toEqual({ who: "header" });
    });

    it("reassembles a chunked session written earlier in the same response", async () => {
      const app = new H3({ debug: true });
      app.get("/", async (event) => {
        const session = await useJWSSessionV2(event, {
          ...jwsConfig,
          cookie: { chunkMaxLength: 24 },
        });
        await session.update({ user: "alice" });
        const again = await useJWSSessionV2(event, {
          ...jwsConfig,
          name: "contract-jws-echo",
          cookie: { chunkMaxLength: 24 },
        });
        return {
          token: session.token,
          chunks: event.res.headers.getSetCookie().length,
          echo: again.id ?? null,
        };
      });

      const body = (await (await app.request("/")).json()) as { token: string; chunks: number };
      expect(body.chunks).toBeGreaterThan(2);

      const reader = new H3({ debug: true });
      reader.get("/", async (event) => {
        const session = await useJWSSessionV2(event, jwsConfig);
        return { user: (session.data as Record<string, unknown>).user ?? null };
      });

      const chunkCount = Math.ceil(body.token.length / 24);
      const cookies = [
        `contract-jws=__chunked__${chunkCount}`,
        ...Array.from(
          { length: chunkCount },
          (_value, index) =>
            `contract-jws.${index + 1}=${body.token.slice(index * 24, (index + 1) * 24)}`,
        ),
      ].join("; ");

      const response = await reader.request("/", { headers: { cookie: cookies } });
      expect(await response.json()).toEqual({ user: "alice" });
    });

    it("drops the cookie when the incoming token has expired", async () => {
      const onExpire = vi.fn();
      const expired = await foreignJWS(
        { jti: "expired", iat: nowSeconds() - 120, exp: nowSeconds() - 60 },
        { cty: "application/json" },
      );

      const app = new H3({ debug: true });
      app.get("/", async (event) => {
        const session = await useJWSSessionV2(event, {
          ...jwsConfig,
          maxAge: 3600,
          hooks: { onExpire },
        });
        return { token: session.token ?? null };
      });

      const response = await app.request("/", {
        headers: { cookie: `contract-jws=${expired}` },
      });

      expect(await response.json()).toEqual({ token: null });
      expect(onExpire).toHaveBeenCalledOnce();
      expect(
        response.headers.getSetCookie().some((cookie) => cookie.startsWith("contract-jws=;")),
      ).toBe(true);
    });

    it("reports the expiry instant of an in-memory session in milliseconds", async () => {
      const onExpire = vi.fn();
      const app = new H3({ debug: true });
      app.get("/", async (event) => {
        const config = { ...jwsConfig, maxAge: 1, hooks: { onExpire } };
        const session = await useJWSSessionV2(event, config);
        await session.update({ user: "alice" });
        vi.setSystemTime(Date.now() + 5000);
        await useJWSSessionV2(event, config);
        vi.useRealTimers();
        return { fired: onExpire.mock.calls.length };
      });

      vi.useFakeTimers({ shouldAdvanceTime: true });
      await app.request("/");
      vi.useRealTimers();

      const { error, session } = onExpire.mock.calls[0]![0];
      expect(error.message).toContain(new Date(session.expiresAt).toISOString());
      expect(new Date(session.expiresAt).getUTCFullYear()).toBe(new Date().getUTCFullYear());
    });

    it("refuses a JWE session under a name a JWS session already holds", async () => {
      const app = new H3({ debug: true });
      app.get("/", async (event) => {
        const jws = await useJWSSessionV2(event, { name: "shared", key: jwsKey });
        await jws.update({ family: "jws" });
        const error = await caught(() => useJWESessionV2(event, { name: "shared", key: jweKey }));
        return {
          config: isJWTError(error, "ERR_SESSION_CONFIG_INVALID"),
          message: (error as Error).message,
          jws: (jws.data as Record<string, unknown>).family,
        };
      });

      const body = (await (await app.request("/")).json()) as Record<string, unknown>;
      expect(body.config).toBe(true);
      expect(body.message).toContain('"shared"');
      expect(body.message).toContain("already used by a JWS session");
      expect(body.jws).toBe("jws");
    });
  });
  // #endregion

  // #region h3 v1
  describe("h3 v1", () => {
    const jwsConfig = { name: "contract-jws", key: jwsKey } as const;

    function h3v1App(handler: Parameters<typeof eventHandler>[0]): App {
      const router = createRouter({ preemptive: true });
      const app = createApp({ debug: true }).use(router);
      router.use("/", eventHandler(handler));
      return app;
    }

    it("keeps the session cookie on an error response", async () => {
      const app = h3v1App(async (event) => {
        const session = await useJWSSessionV1(event, jwsConfig);
        await session.update({ user: "alice" });
        throw createError({ statusCode: 418 });
      });

      const response = await supertest(toNodeListener(app)).get("/");
      const cookies = (response.headers["set-cookie"] as unknown as string[]).filter((cookie) =>
        cookie.startsWith("contract-jws="),
      );

      expect(response.status).toBe(418);
      expect(cookies).toHaveLength(1);
      expect(cookies[0]).toMatch(/^contract-jws=[\w-]+\.[\w-]+\.[\w-]+;/);
    });

    it("keeps the cookie deletion on an error response after clear()", async () => {
      const app = h3v1App(async (event) => {
        const session = await useJWSSessionV1(event, jwsConfig);
        await session.update({ user: "alice" });
        await session.clear();
        throw createError({ statusCode: 500 });
      });

      const response = await supertest(toNodeListener(app)).get("/");
      const cookies = (response.headers["set-cookie"] as unknown as string[]).filter((cookie) =>
        cookie.startsWith("contract-jws="),
      );

      expect(response.status).toBe(500);
      expect(cookies).toHaveLength(1);
      expect(cookies[0]).toMatch(/^contract-jws=;/);
    });

    it("writes a lax session cookie", async () => {
      const app = h3v1App(async (event) => {
        const session = await useJWSSessionV1(event, jwsConfig);
        await session.update({ user: "alice" });
        return { ok: true };
      });

      const response = await supertest(toNodeListener(app)).get("/");
      expect(response.headers["set-cookie"]![0]).toMatch(/SameSite=Lax/i);
    });

    it("splits a long session across chunk cookies and reads them back", async () => {
      const chunked = { ...jwsConfig, cookie: { chunkMaxLength: 24 } };
      const app = h3v1App(async (event) => {
        const session = await useJWSSessionV1(event, chunked);
        if (!session.id) await session.update({ user: "alice" });
        return { user: (session.data as Record<string, unknown>).user ?? null };
      });

      const request = supertest(toNodeListener(app));
      const minted = await request.get("/");
      const cookies = (minted.headers["set-cookie"] as unknown as string[]).map(
        (cookie) => cookie.split(";")[0]!,
      );

      expect(cookies.length).toBeGreaterThan(2);
      expect(cookies[0]).toMatch(/^contract-jws=__chunked__\d+$/);
      expect(cookies[1]).toMatch(/^contract-jws\.1=/);

      const replayed = await request.get("/").set("cookie", cookies.join("; "));
      expect(replayed.body).toEqual({ user: "alice" });
    });

    it("does not restore a cleared session from the request cookie", async () => {
      const minted = await supertest(
        toNodeListener(
          h3v1App(async (event) => {
            const session = await useJWSSessionV1(event, jwsConfig);
            await session.update({ user: "alice" });
            return { ok: true };
          }),
        ),
      ).get("/");
      const cookie = (minted.headers["set-cookie"] as unknown as string[])[0]!.split(";")[0]!;

      const app = h3v1App(async (event) => {
        const session = await useJWSSessionV1(event, jwsConfig);
        await session.clear();
        const again = await useJWSSessionV1(event, jwsConfig);
        return { id: again.id ?? null, token: again.token ?? null };
      });

      const response = await supertest(toNodeListener(app)).get("/").set("cookie", cookie);
      expect(response.body).toEqual({ id: null, token: null });
    });

    it("rejects a password string where key material is required", async () => {
      const app = h3v1App(async (event) => {
        const error = await caught(() =>
          useJWESessionV1(event, { name: "contract-jwe-str", key: "a password" as never }),
        );
        return { key: isJWTError(error, "ERR_SESSION_KEY_INVALID") };
      });

      const response = await supertest(toNodeListener(app)).get("/");
      expect(response.body).toEqual({ key: true });
    });

    it("refuses to write a session on an event with no writable response", async () => {
      const readOnlyEvent = { request: new Request("http://localhost/"), context: {} };
      const session = await useJWSSessionV1(readOnlyEvent, jwsConfig);
      const error = await caught(() => session.update({ user: "alice" }));

      expect(isJWTError(error, "ERR_SESSION_READONLY_EVENT")).toBe(true);
    });

    it("refuses a JWE session under a name a JWS session already holds", async () => {
      const app = h3v1App(async (event) => {
        const jws = await useJWSSessionV1(event, { name: "shared", key: jwsKey });
        await jws.update({ family: "jws" });
        const error = await caught(() => useJWESessionV1(event, { name: "shared", key: jweKey }));
        return {
          config: isJWTError(error, "ERR_SESSION_CONFIG_INVALID"),
          message: (error as Error).message,
        };
      });

      const response = await supertest(toNodeListener(app)).get("/");
      expect(response.body.config).toBe(true);
      expect(response.body.message).toContain("already used by a JWS session");
    });
  });
  // #endregion

  // #region Elysia
  describe("elysia", () => {
    it("reads the cookie in preference to the session header", async () => {
      const minted = elysiaContext();
      const cookieSession = await createJWSSession(minted.context, { key: jwsKey });
      await cookieSession.update({ who: "cookie" });

      const headerContext = elysiaContext();
      const headerSession = await createJWSSession(headerContext.context, { key: jwsKey });
      await headerSession.update({ who: "header" });

      const { context } = elysiaContext({
        cookies: { "elysia-jws": cookieSession.token! },
        headers: { "x-elysia-jws-session": `Bearer ${headerSession.token!}` },
      });
      const session = await createJWSSession(context, { key: jwsKey });

      expect((session.data as Record<string, unknown>).who).toBe("cookie");
    });

    it("a blank session header never hides the cookie", async () => {
      const minted = elysiaContext();
      const cookieSession = await createJWSSession(minted.context, { key: jwsKey });
      await cookieSession.update({ who: "cookie" });

      const { context } = elysiaContext({
        cookies: { "elysia-jws": cookieSession.token! },
        headers: { "x-elysia-jws-session": " " },
      });
      const session = await createJWSSession(context, { key: jwsKey });

      expect((session.data as Record<string, unknown>).who).toBe("cookie");
    });

    it("rejects a session with neither a cookie nor a header to read from", async () => {
      const { context } = elysiaContext();
      const error = await caught(() =>
        createJWSSession(context, { key: jwsKey, cookie: false, sessionHeader: false }),
      );

      expect(isJWTError(error, "ERR_SESSION_CONFIG_INVALID")).toBe(true);
    });

    it("rejects a password string where key material is required", async () => {
      const { context } = elysiaContext();
      const error = await caught(() => createJWESession(context, { key: "a password" as never }));

      expect(isJWTError(error, "ERR_SESSION_KEY_INVALID")).toBe(true);
      expect((error as Error).message).toMatch(/deriveJWKFromPassword/);
    });

    it("rejects a cookie jar that holds no reactive cookie", async () => {
      const context = {
        cookie: {} as SessionContext["cookie"],
        request: { headers: new Headers() },
      };
      const session = await createJWSSession(context, { key: jwsKey });
      const error = await caught(() => session.update({ user: "alice" }));

      expect(isJWTError(error, "ERR_SESSION_CONFIG_INVALID")).toBe(true);
      expect((error as Error).message).toMatch(/reactive cookie/);
    });

    it("strips the adapter-owned claims from an update payload", async () => {
      const { context } = elysiaContext();
      const session = await createJWSSession(context, { key: jwsKey });
      await session.update({ user: "alice", jti: "forged", exp: 2, nbf: 3 } as never);

      expect({ ...session.data }).toEqual({ user: "alice" });
      expect(session.id).not.toBe("forged");
    });

    it("rejects prototype-poisoning keys in an update", async () => {
      const { context } = elysiaContext();
      const session = await createJWSSession(context, { key: jwsKey });
      const error = await caught(() => session.update({ ["constructor"]: 1 } as never));

      expect(isJWTError(error, "ERR_INVALID_OPTION")).toBe(true);
      expect((error as Error).message).toMatch(/constructor/);
    });

    it("gives one issue a lifetime of its own", async () => {
      const { context } = elysiaContext();
      const session = await createJWSSession(context, { key: jwsKey, maxAge: 60 });
      await session.update({ user: "alice" }, { maxAge: 3600 });

      expect(session.expiresAt - session.createdAt).toBe(3600 * SECOND);
    });

    it("refuses a year-old foreign JWT signed with the session key", async () => {
      const onError = vi.fn();
      const token = await foreignJWS({
        jti: "foreign",
        iat: nowSeconds() - 365 * 24 * 60 * 60,
        sub: "attacker",
      });
      const { context } = elysiaContext({ cookies: { "elysia-jws": token } });

      const session = await createJWSSession(context, {
        key: jwsKey,
        maxAge: 3600,
        hooks: { onError },
      });

      expect(session.id).toBeUndefined();
      expect(isJWTError(onError.mock.calls[0]![0].error, "ERR_SESSION_TOKEN_INVALID")).toBe(true);
    });

    it("drops the cookie when the incoming token has expired", async () => {
      const onExpire = vi.fn();
      const expired = await foreignJWS(
        { jti: "expired", iat: nowSeconds() - 120, exp: nowSeconds() - 60 },
        { cty: "application/json" },
      );
      const { context, store } = elysiaContext({ cookies: { "elysia-jws": expired } });

      const session = await createJWSSession(context, {
        key: jwsKey,
        maxAge: 3600,
        hooks: { onExpire },
      });

      expect(session.token).toBeUndefined();
      expect(onExpire).toHaveBeenCalledOnce();
      expect(store.get("elysia-jws")?.lastWrite?.maxAge).toBe(0);
    });

    it("caps PBES2 unwrap at the iteration count the session itself mints", async () => {
      const onError = vi.fn();
      const pinned = {
        key: pbes2Key,
        jwe: {
          encryptOptions: { alg: "PBES2-HS256+A128KW", enc: "A128GCM", p2c: 2048 },
        },
      } as const;

      const costly = await encrypt({ jti: "costly", iat: nowSeconds() }, pbes2Key, {
        alg: "PBES2-HS256+A128KW",
        enc: "A128GCM",
        p2c: 200_000,
        protectedHeader: { typ: "JWT" },
      });
      const { context } = elysiaContext({ cookies: { "elysia-jwe": costly } });

      const session = await createJWESession(context, { ...pinned, hooks: { onError } });

      expect(session.id).toBeUndefined();
      expect(isJWTError(onError.mock.calls[0]![0].error, "ERR_SESSION_TOKEN_INVALID")).toBe(true);
    });

    it("accepts a token minted at the session's own iteration count", async () => {
      const pinned = {
        key: pbes2Key,
        jwe: {
          encryptOptions: { alg: "PBES2-HS256+A128KW", enc: "A128GCM", p2c: 2048 },
        },
      } as const;

      const minted = elysiaContext();
      const first = await createJWESession(minted.context, pinned);
      await first.update({ user: "alice" });

      const { context } = elysiaContext({ cookies: { "elysia-jwe": first.token! } });
      const second = await createJWESession(context, pinned);

      expect(second.id).toBe(first.id);
    });

    it("refuses a JWE session under a name a JWS session already holds", async () => {
      const { context } = elysiaContext();
      const jws = await createJWSSession(context, { name: "shared", key: jwsKey });
      await jws.update({ family: "jws" });

      const error = await caught(() => createJWESession(context, { name: "shared", key: jweKey }));

      expect(isJWTError(error, "ERR_SESSION_CONFIG_INVALID")).toBe(true);
      expect((error as Error).message).toContain("already used by a JWS session");
    });

    it("lets a second JWS session under the same name keep the name", async () => {
      const { context } = elysiaContext();
      const first = await createJWSSession(context, { name: "shared", key: jwsKey });
      await first.update({ who: "first" });
      const second = await createJWSSession(context, { name: "shared", key: jwsKey });

      expect(second.id).toBe(first.id);
    });

    it("registers two differently-named session plugins side by side", async () => {
      const app = new Elysia()
        .use(jwsSession({ key: jwsKey, name: "first", cookie: { secure: false } }))
        .use(
          jwsSession<Record<string, any>, undefined, "admin">({
            key: jwsKey,
            name: "second",
            contextKey: "admin",
            cookie: { secure: false },
          }),
        )
        .get("/", async ({ session, admin }) => {
          await session.update({ who: "first" });
          await admin.update({ who: "second" });
          return { session: session.id, admin: admin.id };
        });

      const response = await app.handle(new Request("http://localhost/"));
      const cookies = response.headers.getSetCookie();

      expect(cookies.some((cookie) => cookie.startsWith("first="))).toBe(true);
      expect(cookies.some((cookie) => cookie.startsWith("second="))).toBe(true);
    });
  });
  // #endregion

  // #region re-entrant hooks
  describe("re-entrant hooks", () => {
    const readerConfig = { name: "reentrant-jws", key: jwsKey, maxAge: "1m" } as const;

    it("h3 v2: an onExpire hook may read the same session", async () => {
      const seen: Array<string | undefined> = [];
      const app = new H3({ debug: true });
      app.get("/", async (event) => {
        const config = {
          ...readerConfig,
          hooks: {
            onExpire: async () => {
              const again = await useJWSSessionV2(event, { ...readerConfig });
              seen.push(again.id);
            },
          },
        };
        const session = await useJWSSessionV2(event, config);
        return { id: session.id ?? null };
      });

      const token = await foreignJWS(EXPIRED_CLAIMS);
      const response = await within(
        app.request("/", { headers: { cookie: `reentrant-jws=${token}` } }),
        "h3 v2 onExpire",
      );

      expect(await response.json()).toEqual({ id: null });
      expect(seen).toEqual([undefined]);
    });

    it("h3 v2: an onError hook may read the same session", async () => {
      const seen: Array<string | undefined> = [];
      const app = new H3({ debug: true });
      app.get("/", async (event) => {
        const config = {
          ...readerConfig,
          hooks: {
            onError: async () => {
              const again = await useJWSSessionV2(event, { ...readerConfig });
              seen.push(again.id);
            },
          },
        };
        const session = await useJWSSessionV2(event, config);
        return { id: session.id ?? null };
      });

      const response = await within(
        app.request("/", { headers: { cookie: "reentrant-jws=not.a.token" } }),
        "h3 v2 onError",
      );

      expect(await response.json()).toEqual({ id: null });
      expect(seen).toEqual([undefined]);
    });

    it("h3 v1: an onExpire hook may read the same session", async () => {
      const seen: Array<string | undefined> = [];
      const router = createRouter({ preemptive: true });
      const app = createApp({ debug: true }).use(router);
      router.use(
        "/",
        eventHandler(async (event) => {
          const config = {
            ...readerConfig,
            hooks: {
              onExpire: async () => {
                const again = await useJWSSessionV1(event, { ...readerConfig });
                seen.push(again.id);
              },
            },
          };
          const session = await useJWSSessionV1(event, config);
          return { id: session.id ?? null };
        }),
      );

      const token = await foreignJWS(EXPIRED_CLAIMS);
      const response = await within(
        supertest(toNodeListener(app)).get("/").set("cookie", `reentrant-jws=${token}`),
        "h3 v1 onExpire",
      );

      expect(response.body).toEqual({ id: null });
      expect(seen).toEqual([undefined]);
    });

    it("h3 v1: an onError hook may read the same session", async () => {
      const seen: Array<string | undefined> = [];
      const router = createRouter({ preemptive: true });
      const app = createApp({ debug: true }).use(router);
      router.use(
        "/",
        eventHandler(async (event) => {
          const config = {
            ...readerConfig,
            hooks: {
              onError: async () => {
                const again = await useJWSSessionV1(event, { ...readerConfig });
                seen.push(again.id);
              },
            },
          };
          const session = await useJWSSessionV1(event, config);
          return { id: session.id ?? null };
        }),
      );

      const response = await within(
        supertest(toNodeListener(app)).get("/").set("cookie", "reentrant-jws=not.a.token"),
        "h3 v1 onError",
      );

      expect(response.body).toEqual({ id: null });
      expect(seen).toEqual([undefined]);
    });

    it("elysia: an onExpire hook may read the same session", async () => {
      const seen: Array<string | undefined> = [];
      const token = await foreignJWS(EXPIRED_CLAIMS);
      const { context } = elysiaContext({ cookies: { "reentrant-jws": token } });
      const config = {
        ...readerConfig,
        hooks: {
          onExpire: async () => {
            const again = await createJWSSession(context, { ...readerConfig });
            seen.push(again.id);
          },
        },
      };

      const session = await within(createJWSSession(context, config), "elysia onExpire");

      expect(session.id).toBeUndefined();
      expect(seen).toEqual([undefined]);
    });

    it("elysia: an onError hook may read the same session", async () => {
      const seen: Array<string | undefined> = [];
      const { context } = elysiaContext({ cookies: { "reentrant-jws": "not.a.token" } });
      const config = {
        ...readerConfig,
        hooks: {
          onError: async () => {
            const again = await createJWSSession(context, { ...readerConfig });
            seen.push(again.id);
          },
        },
      };

      const session = await within(createJWSSession(context, config), "elysia onError");

      expect(session.id).toBeUndefined();
      expect(seen).toEqual([undefined]);
    });
  });
  // #endregion

  // #region chunk bounds
  describe("cookie chunk bounds", () => {
    const chunkMaxLength = 64;
    const chunked = {
      name: "chunk-jws",
      key: jwsKey,
      cookie: { chunkMaxLength, secure: false },
    } as const;

    it("h3 v2: refuses a token needing more chunks than the limit", async () => {
      const app = new H3({ debug: true });
      app.get("/", async (event) => {
        const session = await useJWSSessionV2(event, chunked);
        const error = await caught(() =>
          session.update(bulkyData(MAX_CHUNK_COUNT + 14, chunkMaxLength)),
        );
        return { config: isJWTError(error, "ERR_SESSION_CONFIG_INVALID") };
      });

      const response = await app.request("/");
      expect(await response.json()).toEqual({ config: true });
    });

    it("h3 v1: refuses a token needing more chunks than the limit", async () => {
      const router = createRouter({ preemptive: true });
      const app = createApp({ debug: true }).use(router);
      router.use(
        "/",
        eventHandler(async (event) => {
          const session = await useJWSSessionV1(event, chunked);
          const error = await caught(() =>
            session.update(bulkyData(MAX_CHUNK_COUNT + 14, chunkMaxLength)),
          );
          return { config: isJWTError(error, "ERR_SESSION_CONFIG_INVALID") };
        }),
      );

      const response = await supertest(toNodeListener(app)).get("/");
      expect(response.body).toEqual({ config: true });
    });

    it("h3 v2: bounds cleanup of a forged chunk marker", async () => {
      const app = new H3({ debug: true });
      app.get("/", async (event) => {
        const session = await useJWSSessionV2(event, chunked);
        await session.update({ user: "alice" });
        return { ok: true };
      });

      const response = await app.request("/", {
        headers: { cookie: "chunk-jws=__chunked__100" },
      });
      expect(response.headers.getSetCookie().length).toBeLessThanOrEqual(MAX_CHUNK_COUNT + 1);
    });

    it("h3 v1: bounds cleanup of a forged chunk marker", async () => {
      const router = createRouter({ preemptive: true });
      const app = createApp({ debug: true }).use(router);
      router.use(
        "/",
        eventHandler(async (event) => {
          const session = await useJWSSessionV1(event, chunked);
          await session.update({ user: "alice" });
          return { ok: true };
        }),
      );

      const response = await supertest(toNodeListener(app))
        .get("/")
        .set("cookie", "chunk-jws=__chunked__100");
      const setCookies = response.headers["set-cookie"] as unknown as string[];
      expect(setCookies.length).toBeLessThanOrEqual(MAX_CHUNK_COUNT + 1);
    });
  });
  // #endregion

  // #region key and payload failures
  describe("misconfigured keys and payloads", () => {
    it("h3 v2: a missing key fails the read, not the first update", async () => {
      const app = new H3({ debug: true });
      app.get("/", async (event) => {
        const error = await caught(() =>
          useJWSSessionV2(event, { name: "nokey", key: undefined as never }),
        );
        return { key: isJWTError(error, "ERR_SESSION_KEY_INVALID") };
      });

      const response = await app.request("/");
      expect(await response.json()).toEqual({ key: true });
    });

    it("h3 v1: a public-only JWS key fails the read", async () => {
      const router = createRouter({ preemptive: true });
      const app = createApp({ debug: true }).use(router);
      router.use(
        "/",
        eventHandler(async (event) => {
          const error = await caught(() =>
            useJWSSessionV1(event, {
              name: "publiconly",
              key: { publicKey: {} } as never,
            }),
          );
          return { key: isJWTError(error, "ERR_SESSION_KEY_INVALID") };
        }),
      );

      const response = await supertest(toNodeListener(app)).get("/");
      expect(response.body).toEqual({ key: true });
    });

    it("elysia: an empty key object fails the read", async () => {
      const { context } = elysiaContext();
      const error = await caught(() =>
        createJWSSession(context, { name: "emptykey", key: {} as never }),
      );

      expect(isJWTError(error, "ERR_SESSION_KEY_INVALID")).toBe(true);
    });

    it("h3 v2: session data that is not JSON-serializable is an option error", async () => {
      const app = new H3({ debug: true });
      app.get("/", async (event) => {
        const session = await useJWSSessionV2(event, { name: "bigint", key: jwsKey });
        const error = await caught(() => session.update({ n: 1n as unknown as string }));
        return { option: isJWTError(error, "ERR_INVALID_OPTION") };
      });

      const response = await app.request("/");
      expect(await response.json()).toEqual({ option: true });
    });

    it("elysia: a cookie name outside the RFC 6265 token characters is a config error", async () => {
      const { context } = elysiaContext();
      const error = await caught(() =>
        createJWSSession(context, { name: "bad name", key: jwsKey }),
      );

      expect(isJWTError(error, "ERR_SESSION_CONFIG_INVALID")).toBe(true);
    });

    it("h3 v2: a cookie name outside the RFC 6265 token characters is a config error", async () => {
      const app = new H3({ debug: true });
      app.get("/", async (event) => {
        const error = await caught(() => useJWSSessionV2(event, { name: "bad;name", key: jwsKey }));
        return { config: isJWTError(error, "ERR_SESSION_CONFIG_INVALID") };
      });

      const response = await app.request("/");
      expect(await response.json()).toEqual({ config: true });
    });

    it("h3 v1: a cookie name outside the RFC 6265 token characters is a config error", async () => {
      const router = createRouter({ preemptive: true });
      const app = createApp({ debug: true }).use(router);
      router.use(
        "/",
        eventHandler(async (event) => {
          const error = await caught(() =>
            useJWSSessionV1(event, { name: "bad name", key: jwsKey }),
          );
          return { config: isJWTError(error, "ERR_SESSION_CONFIG_INVALID") };
        }),
      );

      const response = await supertest(toNodeListener(app)).get("/");
      expect(response.body).toEqual({ config: true });
    });

    it("leaves session.token undefined after a failed verification", async () => {
      const { context } = elysiaContext({ cookies: { "elysia-jws": "not.a.token" } });
      const session = await createJWSSession(context, { key: jwsKey });

      expect(session.token).toBeUndefined();
    });
  });
  // #endregion

  // #region elysia cookie chunk bounds
  describe("elysia cookie chunk bounds", () => {
    const chunkMaxLength = 64;
    const chunked = {
      name: "chunk-jws",
      key: jwsKey,
      cookie: { chunkMaxLength, secure: false },
    } as const;

    it("refuses a token needing more chunks than the limit", async () => {
      const { context } = elysiaContext();
      const session = await createJWSSession(context, chunked);
      const error = await caught(() =>
        session.update(bulkyData(MAX_CHUNK_COUNT + 14, chunkMaxLength)),
      );

      expect(isJWTError(error, "ERR_SESSION_CONFIG_INVALID")).toBe(true);
      expect((error as Error).message).toContain(String(MAX_CHUNK_COUNT));
    });

    it.each(["__chunked__99", "__chunked__0", "__chunked__abc"])(
      "reads a forged %s marker as no session",
      async (marker) => {
        const { context } = elysiaContext({ cookies: { "chunk-jws": marker } });
        const session = await createJWSSession(context, chunked);

        expect(session.id).toBeUndefined();
        expect(session.token).toBeUndefined();
      },
    );

    it("bounds cleanup of a forged chunk marker", async () => {
      const { context, store } = elysiaContext({ cookies: { "chunk-jws": "__chunked__100" } });
      const session = await createJWSSession(context, chunked);
      await session.update({ user: "alice" });

      const written = [...store.keys()].filter((name) => name.startsWith("chunk-jws"));
      expect(written.length).toBeLessThanOrEqual(MAX_CHUNK_COUNT + 1);
    });

    it("round-trips a token across the chunks it needs", async () => {
      const minted = elysiaContext();
      const session = await createJWSSession(minted.context, chunked);
      await session.update(bulkyData(3, chunkMaxLength));

      const cookies: Record<string, string> = {};
      for (const [name, entry] of minted.store) cookies[name] = entry.value as string;
      const { context } = elysiaContext({ cookies });
      const again = await createJWSSession(context, chunked);

      expect(again.id).toBe(session.id);
    });
  });
  // #endregion

  // #region cookie attribute parity
  describe("cookie attributes", () => {
    const expected = {
      jws: { path: "/", secure: true, httpOnly: false, sameSite: "lax" },
      jwe: { path: "/", secure: true, httpOnly: true, sameSite: "lax" },
    } as const;

    it.each(["jws", "jwe"] as const)("h3 v2 writes the %s defaults", async (family) => {
      const app = new H3({ debug: true });
      app.get("/", async (event) => {
        const session =
          family === "jws"
            ? await useJWSSessionV2(event, { name: `attr-${family}`, key: jwsKey })
            : await useJWESessionV2(event, { name: `attr-${family}`, key: jweKey });
        await session.update({ user: "alice" });
        return { ok: true };
      });

      const setCookie = (await app.request("/")).headers.getSetCookie()[0]!;
      expect(setCookieAttributes(setCookie)).toEqual(expected[family]);
    });

    it.each(["jws", "jwe"] as const)("h3 v1 writes the %s defaults", async (family) => {
      const router = createRouter({ preemptive: true });
      const app = createApp({ debug: true }).use(router);
      router.use(
        "/",
        eventHandler(async (event) => {
          const session =
            family === "jws"
              ? await useJWSSessionV1(event, { name: `attr-${family}`, key: jwsKey })
              : await useJWESessionV1(event, { name: `attr-${family}`, key: jweKey });
          await session.update({ user: "alice" });
          return { ok: true };
        }),
      );

      const response = await supertest(toNodeListener(app)).get("/");
      const setCookie = (response.headers["set-cookie"] as unknown as string[])[0]!;
      expect(setCookieAttributes(setCookie)).toEqual(expected[family]);
    });

    it.each(["jws", "jwe"] as const)("elysia writes the %s defaults", async (family) => {
      const { context, store } = elysiaContext();
      const session =
        family === "jws"
          ? await createJWSSession(context, { name: `attr-${family}`, key: jwsKey })
          : await createJWESession(context, { name: `attr-${family}`, key: jweKey });
      await session.update({ user: "alice" });

      const write = store.get(`attr-${family}`)!.lastWrite!;
      expect({
        path: write.path,
        secure: Boolean(write.secure),
        httpOnly: Boolean(write.httpOnly),
        sameSite: write.sameSite,
      }).toEqual(expected[family]);
    });
  });
  // #endregion

  // #region one contract across adapters and families
  describe("one contract across adapters and families", () => {
    it.each(portFamilyCases())("$label: a token that does not open is invalid", async (port) => {
      const body = await port.run(
        port.family,
        { name: port.name, key: port.key, cookie: { secure: false }, hooks: {} },
        async (open) => {
          const session = await open();
          return { id: session.id ?? null, token: session.token ?? null };
        },
        { cookies: { [port.name]: "not.a.token" } },
      );

      expect(body).toEqual({ id: null, token: null });
    });

    it.each(portFamilyCases())("$label: reports an unopenable token to onError", async (port) => {
      let seen: unknown;
      const body = await port.run(
        port.family,
        {
          name: port.name,
          key: port.key,
          cookie: { secure: false },
          hooks: {
            onError: ({ error }: { error: unknown }) => {
              seen = error;
            },
          },
        },
        async (open) => {
          await open();
          return { code: isJWTError(seen, "ERR_SESSION_TOKEN_INVALID") };
        },
        { cookies: { [port.name]: "not.a.token" } },
      );

      expect(body).toEqual({ code: true });
    });

    it.each(portFamilyCases())("$label: a missing key fails the read", async (port) => {
      const body = await port.run(
        port.family,
        { name: port.name, key: undefined, cookie: { secure: false } },
        async (open) => {
          const error = await caught(open);
          return { code: isJWTError(error, "ERR_SESSION_KEY_INVALID") };
        },
      );

      expect(body).toEqual({ code: true });
    });

    it.each(portFamilyCases())("$label: an unusable name is a config failure", async (port) => {
      const body = await port.run(
        port.family,
        { name: "bad name", key: port.key, cookie: { secure: false } },
        async (open) => {
          const error = await caught(open);
          return { code: isJWTError(error, "ERR_SESSION_CONFIG_INVALID") };
        },
      );

      expect(body).toEqual({ code: true });
    });

    it.each(portFamilyCases())("$label: three concurrent reads share one jti", async (port) => {
      const config = { name: port.name, key: port.key, cookie: { secure: false } };

      const minted = await port.run(port.family, config, async (open) => {
        const session = await open();
        await session.update({ user: "alice" });
        return { token: session.token! };
      });

      const body = await port.run(
        port.family,
        config,
        async (open) => {
          const sessions = await Promise.all([open(), open(), open()]);
          const ids = sessions.map((session) => session.id);
          return { ids, distinct: new Set(ids).size };
        },
        { cookies: { [port.name]: minted.token as string } },
      );

      expect(body.distinct).toBe(1);
      expect((body.ids as (string | undefined)[])[0]).toBeDefined();
    });
  });
  // #endregion

  // #region elysia session lifecycle
  describe("elysia session lifecycle", () => {
    it("reads a cleared session back as empty", async () => {
      const { context, store } = elysiaContext();
      const session = await createJWSSession(context, { key: jwsKey, cookie: { secure: false } });
      await session.update({ user: "alice" });
      await session.clear();

      expect(session.id).toBeUndefined();
      expect(session.data).toEqual({});
      expect(store.get("elysia-jws")?.lastWrite?.maxAge).toBe(0);

      const again = await createJWSSession(context, { key: jwsKey, cookie: { secure: false } });
      expect(again.id).toBeUndefined();
    });

    it("gives an issue after a clear a lifetime of its own", async () => {
      const { context } = elysiaContext();
      const session = await createJWSSession(context, {
        key: jwsKey,
        maxAge: 60,
        cookie: { secure: false },
      });
      await session.update({ user: "alice" });
      await session.clear();
      await session.update({ user: "bob" }, { maxAge: 3600 });

      expect(session.id).toBeDefined();
      expect({ ...session.data }).toEqual({ user: "bob" });
      expect(session.expiresAt - session.createdAt).toBe(3600 * SECOND);
    });
  });
  // #endregion

  // #region re-entrant hook matrix
  describe("re-entrant hook matrix", () => {
    it.each(hookMatrix())("h3 v2: $hook may $operation the same session", async (entry) => {
      const seen: unknown[] = [];
      const app = new H3({ debug: true });
      app.get("/", async (event) => {
        const config: Record<string, unknown> = {
          name: "matrix-jws",
          key: jwsKey,
          maxAge: "1h",
          cookie: { secure: false },
        };
        config.hooks = reentrantHooks(entry, () => useJWSSessionV2(event, config as never), seen);
        const session = await useJWSSessionV2(event, config as never);
        await triggerHook(entry, session);
        return { ok: true };
      });

      const cookie = await matrixCookie(entry.hook);
      const response = await within(
        app.request("/", { headers: cookie ? { cookie: `matrix-jws=${cookie}` } : {} }),
        `h3 v2 ${entry.hook} / ${entry.operation}`,
      );

      expect(await response.json()).toEqual({ ok: true });
      expect(seen).toHaveLength(1);
    });

    it.each(hookMatrix())("elysia: $hook may $operation the same session", async (entry) => {
      const seen: unknown[] = [];
      const cookie = await matrixCookie(entry.hook);
      const { context } = elysiaContext({
        cookies: cookie ? { "matrix-jws": cookie } : {},
      });
      const config: Record<string, unknown> = {
        name: "matrix-jws",
        key: jwsKey,
        maxAge: "1h",
        cookie: { secure: false },
      };
      config.hooks = reentrantHooks(entry, () => createJWSSession(context, config as never), seen);

      const session = await within(
        createJWSSession(context, config as never),
        `elysia ${entry.hook} read`,
      );
      await within(triggerHook(entry, session), `elysia ${entry.hook} / ${entry.operation}`);

      expect(seen).toHaveLength(1);
    });
  });
  // #endregion

  // #region cookie expiry precedence
  describe("cookie expiry", () => {
    it("lets the token lifetime decide the cookie expiry on every port", async () => {
      const far = new Date(Date.now() + 10 * 365 * 24 * 3600 * 1000);
      const config = {
        name: "expiry-jws",
        key: jwsKey,
        maxAge: "1m",
        cookie: { secure: false, expires: far },
      } as const;

      const v2 = new H3({ debug: true });
      v2.get("/", async (event) => {
        const session = await useJWSSessionV2(event, config);
        await session.update({ user: "alice" });
        return { ok: true };
      });
      const v2Cookie = (await v2.request("/")).headers.getSetCookie()[0]!;

      const router = createRouter({ preemptive: true });
      const v1 = createApp({ debug: true }).use(router);
      router.use(
        "/",
        eventHandler(async (event) => {
          const session = await useJWSSessionV1(event, config);
          await session.update({ user: "alice" });
          return { ok: true };
        }),
      );
      const v1Cookie = (
        (await supertest(toNodeListener(v1)).get("/")).headers["set-cookie"] as unknown as string[]
      )[0]!;

      const { context, store } = elysiaContext();
      const elysia = await createJWSSession(context, config);
      await elysia.update({ user: "alice" });
      const elysiaExpires = store.get("expiry-jws")!.lastWrite!.expires!;

      const farYear = String(far.getUTCFullYear());
      expect(v2Cookie).not.toContain(farYear);
      expect(v1Cookie).not.toContain(farYear);
      expect(elysiaExpires.getTime()).toBeLessThan(far.getTime());
    });
  });
  // #endregion
});

/** The attributes a `Set-Cookie` header carries, normalized for comparison. */
function setCookieAttributes(setCookie: string): Record<string, unknown> {
  const attributes = setCookie
    .split(";")
    .slice(1)
    .map((part) => part.trim().toLowerCase());
  return {
    path: attributes.find((a) => a.startsWith("path="))?.slice("path=".length),
    secure: attributes.includes("secure"),
    httpOnly: attributes.includes("httponly"),
    sameSite: attributes.find((a) => a.startsWith("samesite="))?.slice("samesite=".length),
  };
}

type Family = "jws" | "jwe";

interface PortFamilyCase {
  label: string;
  family: Family;
  name: string;
  key: unknown;
  run: (
    family: Family,
    config: Record<string, unknown>,
    body: (open: () => Promise<any>) => Promise<Record<string, unknown>>,
    options?: { cookies?: Record<string, string> },
  ) => Promise<Record<string, unknown>>;
}

/** The same session case on every adapter and both families. */
function portFamilyCases(): PortFamilyCase[] {
  const runners: [string, PortFamilyCase["run"]][] = [
    [
      "h3 v2",
      async (family, config, body, options) => {
        const app = new H3({ debug: true });
        app.get("/", async (event) =>
          body(() =>
            family === "jws"
              ? useJWSSessionV2(event, config as never)
              : useJWESessionV2(event, config as never),
          ),
        );
        const response = await app.request("/", { headers: cookieHeader(options?.cookies) });
        return (await response.json()) as Record<string, unknown>;
      },
    ],
    [
      "h3 v1",
      async (family, config, body, options) => {
        const router = createRouter({ preemptive: true });
        const app = createApp({ debug: true }).use(router);
        router.use(
          "/",
          eventHandler(async (event) =>
            body(() =>
              family === "jws"
                ? useJWSSessionV1(event, config as never)
                : useJWESessionV1(event, config as never),
            ),
          ),
        );
        let request = supertest(toNodeListener(app)).get("/");
        const headers = cookieHeader(options?.cookies);
        if (headers.cookie) request = request.set("cookie", headers.cookie);
        const response = await request;
        return response.body as Record<string, unknown>;
      },
    ],
    [
      "elysia",
      async (family, config, body, options) => {
        const { context } = elysiaContext({ cookies: options?.cookies });
        return body(() =>
          family === "jws"
            ? createJWSSession(context, config as never)
            : createJWESession(context, config as never),
        );
      },
    ],
  ];

  return runners.flatMap(([port, run]) =>
    (["jws", "jwe"] as const).map((family) => ({
      label: `${port} ${family}`,
      family,
      name: `contract-${family}`,
      key: family === "jws" ? jwsKey : jweKey,
      run,
    })),
  );
}

function cookieHeader(cookies: Record<string, string> | undefined): Record<string, string> {
  if (!cookies) return {};
  const cookie = Object.entries(cookies)
    .map(([name, value]) => `${name}=${value}`)
    .join("; ");
  return cookie ? { cookie } : {};
}

const HOOK_NAMES = ["onRead", "onUpdate", "onClear", "onExpire", "onError"] as const;
const HOOK_OPERATIONS = ["read", "update", "clear", "token"] as const;

interface MatrixEntry {
  hook: (typeof HOOK_NAMES)[number];
  operation: (typeof HOOK_OPERATIONS)[number];
}

/** Every hook against every operation it might perform on its own session. */
function hookMatrix(): MatrixEntry[] {
  return HOOK_NAMES.flatMap((hook) => HOOK_OPERATIONS.map((operation) => ({ hook, operation })));
}

/** The cookie a request must carry for `hook` to be dispatched at all. */
async function matrixCookie(hook: MatrixEntry["hook"]): Promise<string | undefined> {
  if (hook === "onRead") {
    return foreignJWS(
      { jti: "matrix", iat: nowSeconds(), exp: nowSeconds() + 3600 },
      { cty: "application/json" },
    );
  }
  if (hook === "onExpire") return foreignJWS(EXPIRED_CLAIMS, { cty: "application/json" });
  if (hook === "onError") return "not.a.token";
  return undefined;
}

/**
 * Hooks that run their operation against the session they were dispatched from,
 * once — a hook that updated on every `onUpdate` would never stop.
 */
function reentrantHooks(
  entry: MatrixEntry,
  open: () => Promise<any>,
  seen: unknown[],
): Record<string, () => Promise<void>> {
  let entered = false;
  return {
    [entry.hook]: async () => {
      if (entered) return;
      entered = true;
      const session = await open();
      if (entry.operation === "update") await session.update({ hook: entry.hook });
      else if (entry.operation === "clear") await session.clear();
      seen.push(entry.operation === "token" ? (session.token ?? null) : entry.operation);
    },
  };
}

/** The call that dispatches `hook` once the request has been read. */
async function triggerHook(entry: MatrixEntry, session: any): Promise<void> {
  if (entry.hook === "onUpdate") await session.update({ user: "alice" });
  else if (entry.hook === "onClear") await session.clear();
}
