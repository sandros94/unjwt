import supertest from "supertest";
import { describe, it, expect, expectTypeOf, vi } from "vitest";
import { H3, toNodeHandler } from "h3v2";
import {
  createApp,
  createRouter,
  createError,
  toNodeListener,
  eventHandler,
  readBody,
  getQuery,
  type App,
} from "h3v1";
import { Elysia } from "elysia";

import { isJWTError } from "../src/core/error";
import { generateJWK } from "../src/core/jwk";
import { sign, verify } from "../src/core/jws";
import { encrypt, decrypt } from "../src/core/jwe";
import type { ExpiresIn } from "../src/core/types";
import { base64UrlDecode } from "../src/core/utils";
import {
  useJWSSession as useJWSSessionV2,
  useJWESession as useJWESessionV2,
  signJWSSession as signJWSSessionV2,
  verifyJWSSession as verifyJWSSessionV2,
  sealJWESession as sealJWESessionV2,
  unsealJWESession as unsealJWESessionV2,
  clearJWSSession as clearJWSSessionV2,
  clearJWESession as clearJWESessionV2,
  getJWSSessionToken as getJWSSessionTokenV2,
  getJWESessionToken as getJWESessionTokenV2,
  type SessionDecryptOptions,
  type SessionVerifyOptions,
} from "../src/adapters/h3v2";
import {
  useJWSSession as useJWSSessionV1,
  useJWESession as useJWESessionV1,
  signJWSSession as signJWSSessionV1,
  verifyJWSSession as verifyJWSSessionV1,
  sealJWESession as sealJWESessionV1,
  unsealJWESession as unsealJWESessionV1,
  clearJWSSession as clearJWSSessionV1,
  clearJWESession as clearJWESessionV1,
  getJWSSessionToken as getJWSSessionTokenV1,
  getJWESessionToken as getJWESessionTokenV1,
} from "../src/adapters/h3v1";
import { MAX_CHUNK_COUNT, parseChunkCount, readChunkedFrom } from "../src/adapters/_chunked-cookie";
import { createJWSSession, jwsSession } from "../src/adapters/elysia/session/jws";
import { createJWESession, jweSession } from "../src/adapters/elysia/session/jwe";
import type { SessionContext } from "../src/adapters/elysia/session/types";
import type { CookieAttributes } from "../src/adapters/elysia/_cookie";
import { createJWSCodec } from "../src/adapters/_codec-jws";
import { createJWECodec } from "../src/adapters/_codec-jwe";
import {
  type SessionBinding,
  type SessionCodec,
  type SessionCoreConfig,
  type SessionPort,
  bindSession,
} from "../src/adapters/_session-core";
import { loadSession } from "../src/adapters/_session-read";
import { dropSession, issueSession } from "../src/adapters/_session-write";
import type { SessionManager } from "../src/adapters/_session-types";

const [jwsKey, jweKey] = await Promise.all([generateJWK("HS256"), generateJWK("A128KW")]);
// PBES2 derives its key from the JWK's bytes, so the JWK declares the PBES2 alg itself.
const pbes2Key = { ...jweKey, alg: "PBES2-HS256+A128KW" } as const;

const SECOND = 1000;
const nowSeconds = () => Math.floor(Date.now() / 1000);

/**
 * A token signed with the session key and carrying the session `typ`, but
 * minted by something other than the adapter.
 */
function foreignJWS(claims: Record<string, unknown>, header: Record<string, unknown> = {}) {
  return sign(claims, jwsKey, {
    protectedHeader: { typ: "session+jwt", ...header },
  });
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

  const cookie = new Proxy(
    {},
    {
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
    },
  );

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

    it("reads the cookie in preference to the session header", async () => {
      const app = tokenApp();
      const cookieToken = await mintOnH3(app, "cookie");
      const headerToken = await mintOnH3(app, "header");

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
      const headerToken = await mintOnH3(app, "header");

      const response = await app.request("/read", {
        headers: { "x-contract-jws-session": headerToken },
      });

      expect(await response.json()).toEqual({ who: "header" });
    });

    it("a blank session header never hides the cookie", async () => {
      const app = tokenApp();
      const cookieToken = await mintOnH3(app, "cookie");

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
      const headerToken = await mintOnH3(app, "header");

      const response = await app.request("/read", {
        headers: { "x-contract-jws-session": `bearer ${headerToken}` },
      });

      expect(await response.json()).toEqual({ who: "header" });
    });

    it.each(["__Host-", "__Secure-", "__host-"])(
      "derives the default session header from a %s cookie name without its prefix",
      async (prefix) => {
        const config = { name: `${prefix}contract-jws`, key: jwsKey } as const;
        const app = new H3({ debug: true });
        app.post("/mint", async (event) => {
          const session = await useJWSSessionV2(event, config);
          await session.update({ who: "header" });
          return { token: session.token };
        });
        app.get("/read", async (event) => {
          const session = await useJWSSessionV2(event, config);
          return { who: (session.data as Record<string, unknown>).who ?? null };
        });
        const minted = await app.request("/mint", { method: "POST" });
        const { token } = (await minted.json()) as { token: string };

        const response = await app.request("/read", {
          headers: { "x-contract-jws-session": `Bearer ${token}` },
        });

        expect(await response.json()).toEqual({ who: "header" });
      },
    );

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
        });
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
        await session.update(() => ({ user: "bob", exp: 2 }));
        return { data: session.data };
      });

      expect(await (await app.request("/")).json()).toEqual({ data: { user: "bob" } });
    });

    it("rejects prototype-poisoning keys in an update", async () => {
      const app = new H3({ debug: true });
      app.get("/", async (event) => {
        const session = await useJWSSessionV2(event, jwsConfig);
        const error = await caught(() => session.update({ ["__proto__"]: { admin: true } }));
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

    it("refuses a JWT-typed token signed with the session key, even with a live exp", async () => {
      const onError = vi.fn();
      const onExpire = vi.fn();
      const token = await sign(
        {
          jti: "foreign",
          iat: nowSeconds() - 365 * 24 * 60 * 60,
          exp: nowSeconds() + 3600,
          sub: "attacker",
        },
        jwsKey,
        { protectedHeader: { typ: "JWT" } },
      );

      const app = new H3({ debug: true });
      app.get("/", async (event) => {
        const session = await useJWSSessionV2(event, {
          ...jwsConfig,
          maxAge: 3600,
          hooks: { onError, onExpire },
        });
        return { id: session.id ?? null };
      });

      const response = await app.request("/", {
        headers: { cookie: `contract-jws=${token}` },
      });

      expect(await response.json()).toEqual({ id: null });
      expect(onExpire).not.toHaveBeenCalled();
      const error = onError.mock.calls[0][0].error;
      expect(isJWTError(error, "ERR_SESSION_TOKEN_INVALID")).toBe(true);
      expect(error.message).toMatch(/typ/);
    });

    it("refuses a token that carries no typ", async () => {
      const onError = vi.fn();
      const token = await sign(
        new TextEncoder().encode(JSON.stringify({ jti: "foreign", iat: nowSeconds() })),
        jwsKey,
      );

      const app = new H3({ debug: true });
      app.get("/", async (event) => {
        const session = await useJWSSessionV2(event, { ...jwsConfig, hooks: { onError } });
        return { id: session.id ?? null };
      });

      await app.request("/", { headers: { cookie: `contract-jws=${token}` } });

      const error = onError.mock.calls[0][0].error;
      expect(isJWTError(error, "ERR_SESSION_TOKEN_INVALID")).toBe(true);
      expect(error.message).toMatch(/typ/);
    });

    it("refuses a token without exp when the session has a maxAge", async () => {
      const onError = vi.fn();
      const token = await foreignJWS({ jti: "foreign", iat: nowSeconds() });

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

      expect(isJWTError(onError.mock.calls[0][0].error, "ERR_SESSION_TOKEN_INVALID")).toBe(true);
    });

    it("refuses a token typed for another JWT profile", async () => {
      const onError = vi.fn();
      const token = await foreignJWS({ jti: "foreign", iat: nowSeconds() }, { typ: "at+jwt" });

      const app = new H3({ debug: true });
      app.get("/", async (event) => {
        const session = await useJWSSessionV2(event, { ...jwsConfig, hooks: { onError } });
        return { id: session.id ?? null };
      });

      await app.request("/", { headers: { cookie: `contract-jws=${token}` } });

      const error = onError.mock.calls[0][0].error;
      expect(isJWTError(error, "ERR_SESSION_TOKEN_INVALID")).toBe(true);
      expect(error.message).toMatch(/typ/);
    });

    it("keeps the underlying failure as the cause of an invalid token", async () => {
      const onError = vi.fn();
      const otherKey = await generateJWK("HS256");
      const token = await sign({ jti: "foreign", iat: nowSeconds() }, otherKey, {
        protectedHeader: { typ: "session+jwt" },
      });

      const app = new H3({ debug: true });
      app.get("/", async (event) => {
        const session = await useJWSSessionV2(event, { ...jwsConfig, hooks: { onError } });
        return { id: session.id ?? null };
      });

      await app.request("/", { headers: { cookie: `contract-jws=${token}` } });

      const error = onError.mock.calls[0][0].error;
      expect(isJWTError(error, "ERR_SESSION_TOKEN_INVALID")).toBe(true);
      expect(isJWTError(error.cause, "ERR_JWS_SIGNATURE_INVALID")).toBe(true);
    });

    it("refuses a JWE token typed as a plain JWT", async () => {
      const onError = vi.fn();
      const token = await encrypt({ jti: "foreign", iat: nowSeconds() }, jweKey, {
        protectedHeader: { typ: "JWT" },
      });

      const app = new H3({ debug: true });
      app.get("/", async (event) => {
        const session = await useJWESessionV2(event, { ...jweConfig, hooks: { onError } });
        return { id: session.id ?? null };
      });

      await app.request("/", { headers: { cookie: `contract-jwe=${token}` } });

      expect(isJWTError(onError.mock.calls[0][0].error, "ERR_SESSION_TOKEN_INVALID")).toBe(true);
    });

    it("does not restore a cleared session from the request cookie", async () => {
      const app = new H3({ debug: true });
      const minted = tokenApp();
      const token = await mintOnH3(minted, "cookie");

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
      const headerToken = await mintOnH3(app, "header");

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
      const expired = await foreignJWS({
        jti: "expired",
        iat: nowSeconds() - 120,
        exp: nowSeconds() - 60,
      });

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

      const { error, session } = onExpire.mock.calls[0][0];
      expect(error.message).toContain(new Date(session.expiresAt).toISOString());
      expect(new Date(session.expiresAt).getUTCFullYear()).toBe(new Date().getUTCFullYear());
    });

    it("reports an in-memory expiry with the message claim validation gives for the same instant", async () => {
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

      const { error, session } = onExpire.mock.calls[0][0];
      const token = await sign({ exp: session.expiresAt / 1000 }, jwsKey);
      const coreError = await verify(token, jwsKey, {
        currentDate: new Date(session.expiresAt + 5000),
      }).catch((e) => e);
      expect(isJWTError(coreError, "ERR_JWT_EXPIRED")).toBe(true);
      expect(error.message).toBe(coreError.message);
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
      expect(response.headers["set-cookie"][0]).toMatch(/SameSite=Lax/i);
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
        (cookie) => cookie.split(";")[0],
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
      const cookie = (minted.headers["set-cookie"] as unknown as string[])[0].split(";")[0];

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

    it("refuses to write a session once the response has been sent", async () => {
      const issued = await supertest(
        toNodeListener(
          h3v1App(async (event) => {
            const session = await useJWSSessionV1(event, jwsConfig);
            await session.update({ user: "alice" });
            return { id: session.id };
          }),
        ),
      ).get("/");
      const cookie = (issued.headers["set-cookie"] as unknown as string[])[0].split(";")[0];

      const onError = vi.fn();
      let settle!: (outcome: Record<string, unknown>) => void;
      const outcome = new Promise<Record<string, unknown>>((resolve) => {
        settle = resolve;
      });
      const app = h3v1App(async (event) => {
        const session = await useJWSSessionV1(event, { ...jwsConfig, hooks: { onError } });
        event.node.res.end("sent");
        const update = await caught(() => session.update({ user: "mallory" }));
        const clear = await caught(() => session.clear());
        settle({
          update: isJWTError(update, "ERR_SESSION_READONLY_EVENT"),
          clear: isJWTError(clear, "ERR_SESSION_READONLY_EVENT"),
          id: session.id,
          user: session.data.user,
        });
      });

      const response = await supertest(toNodeListener(app)).get("/").set("cookie", cookie);

      expect(response.text).toBe("sent");
      expect(response.headers["set-cookie"]).toBeUndefined();
      expect(await within(outcome, "h3 v1 write after send")).toEqual({
        update: true,
        clear: true,
        id: issued.body.id,
        user: "alice",
      });
      expect(onError).not.toHaveBeenCalled();
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
      await session.update({ user: "alice", jti: "forged", exp: 2, nbf: 3 });

      expect({ ...session.data }).toEqual({ user: "alice" });
      expect(session.id).not.toBe("forged");
    });

    it("rejects prototype-poisoning keys in an update", async () => {
      const { context } = elysiaContext();
      const session = await createJWSSession(context, { key: jwsKey });
      const error = await caught(() => session.update({ ["constructor"]: 1 }));

      expect(isJWTError(error, "ERR_INVALID_OPTION")).toBe(true);
      expect((error as Error).message).toMatch(/constructor/);
    });

    it("gives one issue a lifetime of its own", async () => {
      const { context } = elysiaContext();
      const session = await createJWSSession(context, { key: jwsKey, maxAge: 60 });
      await session.update({ user: "alice" }, { maxAge: 3600 });

      expect(session.expiresAt - session.createdAt).toBe(3600 * SECOND);
    });

    it("refuses a JWT-typed token signed with the session key, even with a live exp", async () => {
      const onError = vi.fn();
      const onExpire = vi.fn();
      const token = await sign(
        {
          jti: "foreign",
          iat: nowSeconds() - 365 * 24 * 60 * 60,
          exp: nowSeconds() + 3600,
          sub: "attacker",
        },
        jwsKey,
        { protectedHeader: { typ: "JWT" } },
      );
      const { context } = elysiaContext({ cookies: { "elysia-jws": token } });

      const session = await createJWSSession(context, {
        key: jwsKey,
        maxAge: 3600,
        hooks: { onError, onExpire },
      });

      expect(session.id).toBeUndefined();
      expect(onExpire).not.toHaveBeenCalled();
      const error = onError.mock.calls[0][0].error;
      expect(isJWTError(error, "ERR_SESSION_TOKEN_INVALID")).toBe(true);
      expect(error.message).toMatch(/typ/);
    });

    it("drops the cookie when the incoming token has expired", async () => {
      const onExpire = vi.fn();
      const expired = await foreignJWS({
        jti: "expired",
        iat: nowSeconds() - 120,
        exp: nowSeconds() - 60,
      });
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
        protectedHeader: { typ: "session+jwt" },
      });
      const { context } = elysiaContext({ cookies: { "elysia-jwe": costly } });

      const session = await createJWESession(context, { ...pinned, hooks: { onError } });

      expect(session.id).toBeUndefined();
      expect(isJWTError(onError.mock.calls[0][0].error, "ERR_SESSION_TOKEN_INVALID")).toBe(true);
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

    it("shares one state between two sessions bound under the same name", async () => {
      const { context } = elysiaContext();
      const first = await createJWSSession(context, { name: "shared", key: jwsKey });
      await first.update({ who: "first" });
      const second = await createJWSSession(context, { name: "shared", key: jwsKey });

      expect(second.id).toBe(first.id);
      expect({ ...second.data }).toEqual({ who: "first" });

      await second.clear();
      expect(first.id).toBeUndefined();
      expect(first.token).toBeUndefined();
    });

    it("registers two differently-named session plugins under one context key", async () => {
      const app = new Elysia()
        .use(jwsSession({ key: jwsKey, name: "first", cookie: { secure: false } }))
        .get("/first", async ({ session }) => {
          await session.update({ who: "first" });
          return { id: session.id };
        })
        .use(jwsSession({ key: jwsKey, name: "second", cookie: { secure: false } }))
        .get("/second", async ({ session }) => {
          await session.update({ who: "second" });
          return { id: session.id };
        });

      const first = await app.handle(new Request("http://localhost/first"));
      const second = await app.handle(new Request("http://localhost/second"));
      expect(setCookieNames(first)).toEqual(["first"]);
      expect(setCookieNames(second)).toEqual(["second"]);
    });

    it("registers two differently-named session plugins side by side", async () => {
      const app = new Elysia()
        .use(jwsSession({ key: jwsKey, name: "first", cookie: { secure: false } }))
        .use(
          jwsSession<Record<string, unknown>, undefined, "admin">({
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

    it("h3 v2: an undecodable configured key fails every request, not only the first", async () => {
      const config = { name: "badk", key: { ...jwsKey, k: "!!" } } as const;
      const app = new H3({ debug: true });
      app.get("/", async (event) => {
        const error = await caught(() => useJWSSessionV2(event, config));
        return { key: isJWTError(error, "ERR_SESSION_KEY_INVALID") };
      });

      for (let request = 0; request < 3; request++) {
        const response = await app.request("/");
        expect(await response.json()).toEqual({ key: true });
      }
    });

    it("h3 v2: the same key object serves request after request", async () => {
      const config = { name: "samekey", key: { ...jwsKey } } as const;
      const app = new H3({ debug: true });
      app.post("/mint", async (event) => {
        const session = await useJWSSessionV2(event, config);
        await session.update({ who: "ada" });
        return { token: session.token };
      });
      app.get("/read", async (event) => {
        const session = await useJWSSessionV2(event, config);
        return { who: (session.data as Record<string, unknown>).who ?? null };
      });

      const minted = await app.request("/mint", { method: "POST" });
      const { token } = (await minted.json()) as { token: string };
      const read = await app.request("/read", { headers: { cookie: `samekey=${token}` } });
      expect(await read.json()).toEqual({ who: "ada" });
    });

    it("h3 v2: a configured key is checked on its first use, not again for the same object", async () => {
      const key: { kty: "oct"; k: string; alg: "HS256" } = { ...jwsKey };
      const app = new H3({ debug: true });
      app.get("/:which", async (event) => {
        const configured = event.context.params?.which === "copy" ? { ...key } : key;
        const error = await caught(() =>
          useJWSSessionV2(event, { name: "checkedonce", key: configured }),
        );
        return { key: isJWTError(error, "ERR_SESSION_KEY_INVALID") };
      });

      expect(await (await app.request("/same")).json()).toEqual({ key: false });
      key.k = "!!";
      expect(await (await app.request("/same")).json()).toEqual({ key: false });
      expect(await (await app.request("/copy")).json()).toEqual({ key: true });
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

      const setCookie = (await app.request("/")).headers.getSetCookie()[0];
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
      const setCookie = (response.headers["set-cookie"] as unknown as string[])[0];
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

      const minted = await port.run(config, async (open) => {
        const session = await open();
        await session.update({ user: "alice" });
        return { token: session.token! };
      });

      const body = await port.run(
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

  // #region one session state per request
  describe("one session state per request", () => {
    it.each(portFamilyCases())(
      "$label: a hook that clears the session on read leaves the handler without one",
      async (port) => {
        const token = await mintToken(port, baseConfig(port), { user: "alice" });
        const config = {
          ...baseConfig(port),
          hooks: {
            onRead: async (args: Record<string, unknown>) => {
              await (await port.reopen(args, baseConfig(port))).clear();
            },
          },
        };

        const handled = await port.run(
          config,
          async (open) => {
            const session = await open();
            return { id: session.id ?? null, data: { ...session.data } };
          },
          { cookies: { [port.name]: token } },
        );
        const guarded = await port.guarded(config, { cookies: { [port.name]: token } });

        expect(handled).toEqual({ id: null, data: {} });
        expect(guarded.status).toBe(401);
      },
    );

    it.each(portFamilyCases())(
      "$label: a hook that reissues an expired session hands the handler the new one",
      async (port) => {
        const expired = await foreignToken(port.family, EXPIRED_CLAIMS);
        const issued: string[] = [];
        const config = {
          ...baseConfig(port),
          hooks: {
            onExpire: async (args: Record<string, unknown>) => {
              const session = await port.reopen(args, baseConfig(port));
              await session.update({ refreshed: true });
              issued.push(session.id!);
            },
          },
        };

        const handled = await port.run(
          config,
          async (open) => {
            const session = await open();
            return { id: session.id ?? null, data: { ...session.data } };
          },
          { cookies: { [port.name]: expired } },
        );
        const guarded = await port.guarded(config, { cookies: { [port.name]: expired } });

        expect(handled).toEqual({ id: issued[0], data: { refreshed: true } });
        expect(guarded.status).toBe(200);
        expect(guarded.body).toEqual({ id: issued[1] });
      },
    );

    it.each(portFamilyCases())(
      "$label: a cleared session stays cleared while the request still carries a header token",
      async (port) => {
        const cookieToken = await mintToken(port, baseConfig(port), { who: "cookie" });
        const headerToken = await mintToken(port, baseConfig(port), { who: "header" });

        const body = await port.run(
          baseConfig(port),
          async (open) => {
            const session = await open();
            const before = session.id;
            await session.clear();
            const again = await open();
            return { before, id: again.id ?? null, token: again.token ?? null };
          },
          {
            cookies: { [port.name]: cookieToken },
            headers: { [`x-${port.name}-session`]: headerToken },
          },
        );

        expect(body.before).toBeTypeOf("string");
        expect(body).toMatchObject({ id: null, token: null });
      },
    );

    it.each(portFamilyCases())(
      "$label: reports one unopenable token to onError once however often it is opened",
      async (port) => {
        const onError = vi.fn();
        const body = await port.run(
          { ...baseConfig(port), hooks: { onError } },
          async (open) => {
            await open();
            await open();
            return { calls: onError.mock.calls.length };
          },
          { cookies: { [port.name]: "not.a.token" } },
        );

        expect(body).toEqual({ calls: 1 });
      },
    );
  });
  // #endregion

  // #region key halves
  describe("asymmetric JWE key halves", () => {
    const jweCases = () => portFamilyCases().filter((port) => port.family === "jwe");

    it.each(jweCases())(
      "$label: refuses a password string as the private half before any token is opened",
      async (port) => {
        const { publicKey } = await generateJWK("RSA-OAEP-256");
        const onError = vi.fn();
        const forged = await encrypt(
          { jti: "forged", iat: nowSeconds(), exp: nowSeconds() + 3600, sub: "attacker" },
          "hunter2",
          {
            alg: "PBES2-HS256+A128KW",
            enc: "A128GCM",
            p2c: 2048,
            protectedHeader: { typ: "session+jwt" },
          },
        );

        const body = await port.run(
          {
            name: port.name,
            key: { publicKey, privateKey: "hunter2" },
            cookie: { secure: false },
            hooks: { onError },
          },
          async (open) => {
            const error = await caught(open);
            return {
              code: isJWTError(error, "ERR_SESSION_KEY_INVALID"),
              message: (error as Error | undefined)?.message ?? null,
            };
          },
          { cookies: { [port.name]: forged } },
        );

        expect(body.code).toBe(true);
        expect(body.message).toMatch(/privateKey/);
        expect(onError).not.toHaveBeenCalled();
      },
    );
  });
  // #endregion

  // #region writes that fail
  describe("a cookie write that fails", () => {
    it.each(portFamilyCases())(
      "$label: rolls the session back and reports to onError",
      async (port) => {
        const onError = vi.fn();
        const chunkMaxLength = 64;
        const body = await port.run(
          {
            name: port.name,
            key: port.key,
            cookie: { secure: false, chunkMaxLength },
            hooks: { onError },
          },
          async (open) => {
            const session = await open();
            await session.update({ user: "alice" });
            const before = { id: session.id, token: session.token };
            const error = await caught(() =>
              session.update(bulkyData(MAX_CHUNK_COUNT + 14, chunkMaxLength)),
            );
            return {
              config: isJWTError(error, "ERR_SESSION_CONFIG_INVALID"),
              unchanged: session.id === before.id && session.token === before.token,
              user: session.data.user,
              pad: "pad" in session.data,
              reported: isJWTError(onError.mock.calls[0]?.[0].error, "ERR_SESSION_CONFIG_INVALID"),
            };
          },
        );

        expect(body).toEqual({
          config: true,
          unchanged: true,
          user: "alice",
          pad: false,
          reported: true,
        });
        expect(onError).toHaveBeenCalledOnce();
      },
    );
  });
  // #endregion

  // #region token lifetime
  describe("token lifetime on read", () => {
    it.each(portFamilyCases())(
      "$label: a per-issue lifetime longer than the config's outlives the config maxAge",
      async (port) => {
        const onExpire = vi.fn();
        const onError = vi.fn();
        const issuedAt = new Date(Date.now() - 5 * SECOND);
        const token = await mintToken(
          port,
          {
            ...baseConfig(port),
            maxAge: 1,
            ...issueOptions(port.family, { currentDate: issuedAt }),
          },
          { user: "alice" },
          { maxAge: 3600 },
        );

        const body = await port.run(
          { ...baseConfig(port), maxAge: 1, hooks: { onExpire, onError } },
          async (open) => {
            const session = await open();
            return { user: session.data.user ?? null };
          },
          { cookies: { [port.name]: token } },
        );

        expect(body).toEqual({ user: "alice" });
        expect(onExpire).not.toHaveBeenCalled();
        expect(onError).not.toHaveBeenCalled();
      },
    );

    it.each(portFamilyCases())(
      "$label: a token without exp is refused when the session has a maxAge",
      async (port) => {
        const onExpire = vi.fn();
        const onError = vi.fn();
        const token = await foreignToken(port.family, { jti: "no-exp", iat: nowSeconds() });

        const body = await port.run(
          { ...baseConfig(port), maxAge: 3600, hooks: { onExpire, onError } },
          async (open) => ({ id: (await open()).id ?? null }),
          { cookies: { [port.name]: token } },
        );

        expect(body).toEqual({ id: null });
        expect(onExpire).not.toHaveBeenCalled();
        expect(isJWTError(onError.mock.calls[0]?.[0].error, "ERR_SESSION_TOKEN_INVALID")).toBe(
          true,
        );
      },
    );

    it.each(portFamilyCases())(
      "$label: a token whose exp has passed goes to onExpire",
      async (port) => {
        const onExpire = vi.fn();
        const onError = vi.fn();
        const token = await foreignToken(port.family, EXPIRED_CLAIMS);

        const body = await port.run(
          { ...baseConfig(port), maxAge: 3600, hooks: { onExpire, onError } },
          async (open) => ({ id: (await open()).id ?? null }),
          { cookies: { [port.name]: token } },
        );

        expect(body).toEqual({ id: null });
        expect(onError).not.toHaveBeenCalled();
        expect(onExpire).toHaveBeenCalledOnce();
        expect(isJWTError(onExpire.mock.calls[0][0].error, "ERR_JWT_EXPIRED")).toBe(true);
      },
    );
  });
  // #endregion

  // #region adapter-owned claims
  describe("claims the adapter owns", () => {
    it.each(portFamilyCases())("$label: issue options cannot set exp or nbf", async (port) => {
      const later = new Date(Date.now() + 365 * 24 * 3600 * SECOND);
      for (const options of [{ expiresAt: later }, { notBeforeIn: 30 }, { notBeforeAt: later }]) {
        const token = await mintToken(
          port,
          {
            name: port.name,
            key: port.key,
            maxAge: 60,
            cookie: { secure: false },
            ...issueOptions(port.family, options),
          },
          { user: "alice" },
        );
        const claims = await claimsOf(port.family, token);

        expect((claims.exp as number) - (claims.iat as number)).toBe(60);
        expect(claims).not.toHaveProperty("nbf");
      }
    });
  });
  // #endregion

  // #region PBES2 iteration cap
  describe("PBES2 iteration cap", () => {
    const jweCases = () => portFamilyCases().filter((port) => port.family === "jwe");

    it.each(jweCases())(
      "$label: caps unwrap at the session's own count when the key carries the alg",
      async (port) => {
        const onError = vi.fn();
        const config = {
          name: port.name,
          key: pbes2Key,
          cookie: { secure: false },
          jwe: { encryptOptions: { p2c: 2048 } },
          hooks: { onError },
        };
        const own = await mintToken(port, config, { user: "alice" });
        const costly = await encrypt(
          { jti: "costly", iat: nowSeconds(), user: "mallory" },
          pbes2Key,
          { p2c: 4096, protectedHeader: { typ: "session+jwt" } },
        );

        const read = (token: string) =>
          port.run(config, async (open) => ({ user: (await open()).data.user ?? null }), {
            cookies: { [port.name]: token },
          });

        expect(await read(own)).toEqual({ user: "alice" });
        expect(onError).not.toHaveBeenCalled();
        expect(await read(costly)).toEqual({ user: null });
        expect(onError.mock.calls[0][0].error.cause.message).toMatch(/p2c/);
      },
    );
  });
  // #endregion

  // #region lower-level token functions
  describe("one-off tokens from the lower-level functions", () => {
    const magicLink = { maxAge: "15m", cookie: false, sessionHeader: false } as const;
    const magicLinkConfig = {
      jws: { key: jwsKey, ...magicLink },
      jwe: { key: jweKey, ...magicLink },
    };

    it.each(["jws", "jwe"] as const)(
      "h3 v2 %s: mints a token with no cookie and no session header, and opens it back",
      async (family) => {
        const sent: { email: string; token: string }[] = [];
        const app = new H3({ debug: true });
        app.post("/request-magic-link", async (event) => {
          const email = ((await event.req.json()) as { email: string }).email;

          const token =
            family === "jws"
              ? await signJWSSessionV2(event, magicLinkConfig.jws)
              : await sealJWESessionV2(event, magicLinkConfig.jwe);

          sent.push({ email, token });
          return { ok: true };
        });
        app.get("/login", async (event) => {
          const token = new URL(event.req.url).searchParams.get("token")!;
          const session =
            family === "jws"
              ? await verifyJWSSessionV2(event, magicLinkConfig.jws, token)
              : await unsealJWESessionV2(event, magicLinkConfig.jwe, token);
          return { id: session.id, lifetime: session.expiresAt! - session.createdAt! };
        });

        const requested = await app.request("/request-magic-link", {
          method: "POST",
          body: JSON.stringify({ email: "alice@example.com" }),
        });
        expect(await requested.json()).toEqual({ ok: true });
        expect(requested.headers.getSetCookie()).toEqual([]);
        expect(sent[0].email).toBe("alice@example.com");

        const login = await app.request(`/login?token=${sent[0].token}`);
        const body = (await login.json()) as { id: string; lifetime: number };
        expect(body.id).toBeTypeOf("string");
        expect(body.lifetime).toBe(15 * 60 * SECOND);
      },
    );

    it.each(["jws", "jwe"] as const)(
      "h3 v1 %s: mints a token with no cookie and no session header, and opens it back",
      async (family) => {
        const sent: { email: string; token: string }[] = [];
        const router = createRouter({ preemptive: true });
        const app = createApp({ debug: true }).use(router);
        router.post(
          "/request-magic-link",
          eventHandler(async (event) => {
            const email = (await readBody<{ email: string }>(event)).email;

            const token =
              family === "jws"
                ? await signJWSSessionV1(event, magicLinkConfig.jws)
                : await sealJWESessionV1(event, magicLinkConfig.jwe);

            sent.push({ email, token });
            return { ok: true };
          }),
        );
        router.get(
          "/login",
          eventHandler(async (event) => {
            const token = getQuery(event).token as string;
            const session =
              family === "jws"
                ? await verifyJWSSessionV1(event, magicLinkConfig.jws, token)
                : await unsealJWESessionV1(event, magicLinkConfig.jwe, token);
            return { id: session.id, lifetime: session.expiresAt! - session.createdAt! };
          }),
        );

        const request = supertest(toNodeListener(app));
        const requested = await request
          .post("/request-magic-link")
          .send({ email: "alice@example.com" });
        expect(requested.body).toEqual({ ok: true });
        expect(requested.headers["set-cookie"]).toBeUndefined();
        expect(sent[0].email).toBe("alice@example.com");

        const login = await request.get("/login").query({ token: sent[0].token });
        expect(login.body.id).toBeTypeOf("string");
        expect(login.body.lifetime).toBe(15 * 60 * SECOND);
      },
    );

    it.each(portFamilyCases().filter((port) => port.port !== "elysia"))(
      "$label: a session manager still needs a token source",
      async (port) => {
        const body = await port.run(
          { name: port.name, key: port.key, cookie: false, sessionHeader: false },
          async (open) => ({
            code: isJWTError(await caught(open), "ERR_SESSION_CONFIG_INVALID"),
          }),
        );

        expect(body).toEqual({ code: true });
      },
    );
  });
  // #endregion

  // #region elysia session lifecycle
  describe("elysia session lifecycle", () => {
    it("reads a cleared session back as empty while the header still carries its token", async () => {
      const config = { key: jwsKey, cookie: { secure: false } } as const;
      const minted = elysiaContext();
      const issued = await createJWSSession(minted.context, config);
      await issued.update({ user: "alice" });

      const { context, store } = elysiaContext({
        headers: { "x-elysia-jws-session": issued.token! },
      });
      const session = await createJWSSession(context, config);
      expect(session.id).toBe(issued.id);
      await session.clear();

      expect(session.id).toBeUndefined();
      expect(session.data).toEqual({});
      expect(store.get("elysia-jws")?.lastWrite?.maxAge).toBe(0);

      const again = await createJWSSession(context, config);
      expect(again.id).toBeUndefined();
      expect(again.token).toBeUndefined();
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
    const matrixCases = () =>
      portFamilyCases()
        .filter((port) => port.family === "jws")
        .flatMap((port) => hookMatrix().map((entry) => ({ ...entry, port, label: port.port })));

    it.each(matrixCases())(
      "$label: $hook may $operation the same session",
      async ({ port, ...entry }) => {
        const seen: unknown[] = [];
        const config: Record<string, unknown> = {
          name: "matrix-jws",
          key: jwsKey,
          maxAge: "1h",
          cookie: { secure: false },
        };
        config.hooks = reentrantHooks(entry, (args) => port.reopen(args, config), seen);

        const cookie = await matrixCookie(entry.hook);
        const body = await within(
          port.run(
            config,
            async (open) => {
              const session = await open();
              await triggerHook(entry, session);
              return {
                id: session.id ?? null,
                token: session.token ?? null,
                hook: session.data.hook ?? null,
              };
            },
            { cookies: cookie ? { "matrix-jws": cookie } : {} },
          ),
          `${port.port} ${entry.hook} / ${entry.operation}`,
        );

        expect(seen).toHaveLength(1);
        expect(body).toMatchObject(handlerView(entry, seen[0]));
      },
    );
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
      const v2Cookie = (await v2.request("/")).headers.getSetCookie()[0];

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
      )[0];

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

  // #region PBES2 cap with a key lookup
  describe("PBES2 iteration cap with a key lookup hook", () => {
    const jweCases = () => portFamilyCases().filter((port) => port.family === "jwe");

    it.each(jweCases())(
      "$label: caps unwrap at the session's own count when a hook supplies the key",
      async (port) => {
        const onError = vi.fn();
        const config = {
          name: port.name,
          key: pbes2Key,
          cookie: { secure: false },
          jwe: { encryptOptions: { p2c: 2048 } },
          hooks: { onError, onUnsealKeyLookup: () => pbes2Key },
        };
        const own = await mintToken(port, config, { user: "alice" });
        const costly = await encrypt(
          { jti: "costly", iat: nowSeconds(), user: "mallory" },
          pbes2Key,
          { p2c: 4096, protectedHeader: { typ: "session+jwt" } },
        );

        const read = (token: string) =>
          port.run(config, async (open) => ({ user: (await open()).data.user ?? null }), {
            cookies: { [port.name]: token },
          });

        expect(await read(own)).toEqual({ user: "alice" });
        expect(onError).not.toHaveBeenCalled();
        expect(await read(costly)).toEqual({ user: null });
        expect(onError.mock.calls[0][0].error.cause.message).toMatch(/p2c/);
      },
    );
  });
  // #endregion

  // #region writes once the response is sent
  describe("writes once the response is sent", () => {
    it("h3 v2 under Node: an update after the response was sent is refused and rolled back", async () => {
      let settle!: (outcome: Record<string, unknown>) => void;
      const outcome = new Promise<Record<string, unknown>>((resolve) => {
        settle = resolve;
      });
      const config = { name: "late-jws", key: jwsKey, cookie: { secure: false } } as const;

      const app = new H3({ debug: true });
      app.get("/", async (event) => {
        const session = await useJWSSessionV2(event, config);
        await session.update({ user: "alice" });
        const before = { id: session.id, token: session.token };
        event.runtime!.node!.res!.once("finish", async () => {
          const error = await caught(() => session.update({ late: true }));
          settle({
            readonly: isJWTError(error, "ERR_SESSION_READONLY_EVENT"),
            unchanged: session.id === before.id && session.token === before.token,
            late: "late" in session.data,
          });
        });
        return { ok: true };
      });

      const response = await supertest(toNodeHandler(app)).get("/");
      const cookies = (response.headers["set-cookie"] as unknown as string[] | undefined) ?? [];

      expect(response.body).toEqual({ ok: true });
      expect(cookies.some((cookie) => cookie.startsWith("late-jws="))).toBe(true);
      expect(await outcome).toEqual({ readonly: true, unchanged: true, late: false });
    });
  });
  // #endregion

  // #region one clock
  describe("one clock per session", () => {
    it.each(portFamilyCases())(
      "$label: a session issued under a past currentDate stays live for the rest of the request",
      async (port) => {
        const onExpire = vi.fn();
        const config = {
          name: port.name,
          key: port.key,
          maxAge: 60,
          cookie: { secure: false },
          ...issueOptions(port.family, { currentDate: new Date(Date.now() - 3600 * SECOND) }),
          hooks: { onExpire },
        };

        const body = await port.run(config, async (open) => {
          const session = await open();
          await session.update({ user: "alice" });
          const again = await open();
          return { same: again.id === session.id, user: again.data.user ?? null };
        });

        expect(body).toEqual({ same: true, user: "alice" });
        expect(onExpire).not.toHaveBeenCalled();
      },
    );
  });
  // #endregion

  // #region session typ
  describe("session typ", () => {
    const live = () => ({ jti: "live", iat: nowSeconds(), exp: nowSeconds() + 3600 });

    it.each(portFamilyCases())("$label: writes typ session+jwt and no cty", async (port) => {
      const token = await mintToken(port, expiringConfig(port), { user: "alice" });
      const header = protectedHeaderOf(token);

      expect(header.typ).toBe("session+jwt");
      expect(header).not.toHaveProperty("cty");
    });

    it.each(portFamilyCases())(
      "$label: passes a configured cty through untouched",
      async (port) => {
        const config = {
          ...expiringConfig(port),
          ...issueOptions(port.family, { protectedHeader: { cty: "application/json" } }),
        };
        const token = await mintToken(port, config, { user: "alice" });
        const read = await port.run(
          config,
          async (open) => ({ user: (await open()).data.user ?? null }),
          { cookies: { [port.name]: token } },
        );

        expect(protectedHeaderOf(token)).toMatchObject({
          typ: "session+jwt",
          cty: "application/json",
        });
        expect(read).toEqual({ user: "alice" });
      },
    );

    it.each(portFamilyCases())(
      "$label: accepts the session typ written as a full media type",
      async (port) => {
        for (const typ of ["application/session+jwt", "Application/Session+JWT"]) {
          const onError = vi.fn();
          const body = await port.run(
            { ...expiringConfig(port), hooks: { onError } },
            async (open) => ({ id: (await open()).id ?? null }),
            { cookies: { [port.name]: await foreignToken(port.family, live(), { typ }) } },
          );

          expect(body).toEqual({ id: "live" });
          expect(onError).not.toHaveBeenCalled();
        }
      },
    );

    it.each(portFamilyCases())(
      "$label: refuses a JWT-typed token through onError, never onExpire, expired or not",
      async (port) => {
        const tokens = [
          await foreignPlainToken(port.family, live()),
          await foreignPlainToken(port.family, EXPIRED_CLAIMS),
          await foreignToken(port.family, EXPIRED_CLAIMS, { typ: "at+jwt" }),
        ];

        for (const token of tokens) {
          const onError = vi.fn();
          const onExpire = vi.fn();
          const response = await port.serve(
            { ...expiringConfig(port), hooks: { onError, onExpire } },
            async (open) => ({ id: (await open()).id ?? null }),
            { cookies: { [port.name]: token } },
          );

          expect(response.body).toEqual({ id: null });
          expect(response.cookies).toEqual([]);
          expect(onExpire).not.toHaveBeenCalled();
          const error = onError.mock.calls[0][0].error;
          expect(isJWTError(error, "ERR_SESSION_TOKEN_INVALID")).toBe(true);
          expect(error.message).toMatch(/typ/);
        }
      },
    );

    it.each(portFamilyCases())(
      "$label: an expired session token still goes to onExpire",
      async (port) => {
        const onError = vi.fn();
        const onExpire = vi.fn();
        const response = await port.serve(
          { ...expiringConfig(port), hooks: { onError, onExpire } },
          async (open) => ({ id: (await open()).id ?? null }),
          { cookies: { [port.name]: await foreignToken(port.family, EXPIRED_CLAIMS) } },
        );

        expect(response.body).toEqual({ id: null });
        expect(onError).not.toHaveBeenCalled();
        expect(onExpire.mock.calls[0][0].session.id).toBe(EXPIRED_CLAIMS.jti);
      },
    );
  });
  // #endregion

  // #region configured key material
  describe("configured key material that cannot be imported", () => {
    const unusableKeys: Record<Family, Record<string, unknown>> = {
      jws: { kty: "oct", k: "!!!not-base64url!!!", alg: "HS256" },
      jwe: { kty: "oct", k: "A".repeat(27), alg: "A128KW" },
    };

    it.each(portFamilyCases())(
      "$label: fails the read with a key error instead of reporting the token",
      async (port) => {
        const onError = vi.fn();
        const token = await foreignToken(port.family, {
          jti: "live",
          iat: nowSeconds(),
          exp: nowSeconds() + 3600,
        });

        const body = await port.run(
          {
            name: port.name,
            key: unusableKeys[port.family],
            cookie: { secure: false },
            hooks: { onError },
          },
          async (open) => {
            const error = await caught(open);
            return {
              code: isJWTError(error, "ERR_SESSION_KEY_INVALID"),
              cause: isJWTError((error as Error | undefined)?.cause, "ERR_JWK_INVALID"),
            };
          },
          { cookies: { [port.name]: token } },
        );

        expect(body).toEqual({ code: true, cause: true });
        expect(onError).not.toHaveBeenCalled();
      },
    );
  });
  // #endregion

  // #region update payloads and typ
  describe("update payloads and the session typ", () => {
    it.each(portFamilyCases())(
      "$label: refuses update data that is not a plain object",
      async (port) => {
        const body = await port.run(baseConfig(port), async (open) => {
          const session = await open();
          await session.update({ user: "alice" });
          const before = { id: session.id, token: session.token };
          const errors = [
            await caught(() => session.update("abc" as never)),
            await caught(() => session.update([1, 2] as never)),
            await caught(() => session.update((() => "abc") as never)),
            await caught(() => session.update(new URLSearchParams("user=mallory") as never)),
          ];
          return {
            codes: errors.map((error) => isJWTError(error, "ERR_INVALID_OPTION")),
            data: { ...session.data },
            unchanged: session.id === before.id && session.token === before.token,
          };
        });

        expect(body).toEqual({
          codes: [true, true, true, true],
          data: { user: "alice" },
          unchanged: true,
        });
      },
    );

    it.each(
      portFamilyCases().flatMap((port) =>
        ["secevent+jwt", "app-session"].map((typ) => ({ ...port, typ })),
      ),
    )(
      "$label: signs with a configured typ ($typ) and requires it back",
      async ({ typ, ...port }) => {
        const onError = vi.fn();
        const typed = {
          ...baseConfig(port),
          ...issueOptions(port.family, { protectedHeader: { typ } }),
        };
        const own = await mintToken(port, typed, { user: "alice" });
        const plain = await mintToken(port, baseConfig(port), { user: "bob" });

        const read = (token: string) =>
          port.run(
            { ...typed, hooks: { onError } },
            async (open) => ({ user: (await open()).data.user ?? null }),
            { cookies: { [port.name]: token } },
          );

        expect(protectedHeaderOf(own).typ).toBe(typ);
        expect(await read(own)).toEqual({ user: "alice" });
        expect(onError).not.toHaveBeenCalled();
        expect(await read(plain)).toEqual({ user: null });
        expect(isJWTError(onError.mock.calls[0][0].error, "ERR_SESSION_TOKEN_INVALID")).toBe(true);
      },
    );
  });
  // #endregion

  // #region clearing without a token source
  describe("clearing a session", () => {
    it.each(portFamilyCases().filter((port) => port.port !== "elysia"))(
      "$label: a clear with neither a cookie nor a session header is a config failure",
      async (port) => {
        const clear = CLEARERS[port.port as Exclude<Port, "elysia">][port.family];
        const response = await serveOn(port.port, async (event) => ({
          code: isJWTError(
            await caught(() =>
              clear(
                event as never,
                {
                  name: port.name,
                  key: port.key,
                  cookie: false,
                  sessionHeader: false,
                } as never,
              ),
            ),
            "ERR_SESSION_CONFIG_INVALID",
          ),
        }));

        expect(response.body).toEqual({ code: true });
      },
    );
  });
  // #endregion

  // #region cookie lifetime
  describe("cookie lifetime", () => {
    const far = new Date(Date.now() + 10 * 365 * 24 * 3600 * SECOND);

    it.each(portFamilyCases())(
      "$label: a token with a lifetime drops a configured cookie maxAge and expires with the token",
      async (port) => {
        const response = await port.serve(
          {
            ...baseConfig(port),
            maxAge: "1m",
            cookie: { secure: false, maxAge: 10 * 365 * 24 * 3600 },
          },
          async (open) => {
            const session = await open();
            await session.update({ user: "alice" });
            return { expiresAt: session.expiresAt };
          },
        );

        const cookie = liveSetCookie(response.cookies, port.name)!;
        expect(cookieAttribute(cookie, "max-age")).toBeUndefined();
        expect(Date.parse(cookieAttribute(cookie, "expires")!)).toBe(response.body.expiresAt);
      },
    );

    it.each(portFamilyCases())(
      "$label: a token without a lifetime keeps the configured cookie expires and maxAge",
      async (port) => {
        const response = await port.serve(
          { ...baseConfig(port), cookie: { secure: false, expires: far, maxAge: 3600 } },
          async (open) => {
            const session = await open();
            await session.update({ user: "alice" });
            return { expiresAt: session.expiresAt ?? null };
          },
        );

        const cookie = liveSetCookie(response.cookies, port.name)!;
        expect(response.body.expiresAt).toBeNull();
        expect(cookieAttribute(cookie, "max-age")).toBe("3600");
        expect(new Date(cookieAttribute(cookie, "expires")!).getUTCFullYear()).toBe(
          far.getUTCFullYear(),
        );
      },
    );

    it.each(portFamilyCases())(
      "$label: a request that carried no token never reports an expiry",
      async (port) => {
        const onExpire = vi.fn();
        const config = { ...baseConfig(port), maxAge: 1, hooks: { onExpire } };
        const response = await port.serve(config, async (open) => {
          await open({
            ...config,
            ...issueOptions(port.family, { currentDate: new Date(Date.now() - 5 * SECOND) }),
          });
          const again = await open();
          return { id: again.id ?? null, token: again.token ?? null };
        });

        expect(response.body).toEqual({ id: null, token: null });
        expect(onExpire).not.toHaveBeenCalled();
        expect(response.cookies).toEqual([]);
      },
    );

    it.each(portFamilyCases())(
      "$label: a chunk set that shrinks within one request expires the chunks it no longer uses",
      async (port) => {
        const chunkMaxLength = 64;
        const response = await port.serve(
          { ...baseConfig(port), cookie: { secure: false, chunkMaxLength } },
          async (open) => {
            const session = await open();
            await session.update(bulkyData(6, chunkMaxLength));
            const longest = session.token!.length;
            await session.update({ pad: "x" });
            return { token: session.token, shrunk: session.token!.length < longest };
          },
        );

        const live = liveCookies(response.cookies);
        const count = parseChunkCount(live[port.name]);
        const chunks = Object.keys(live).filter((name) => name.startsWith(`${port.name}.`));
        expect(response.body.shrunk).toBe(true);
        expect(readChunkedFrom(live, port.name)).toBe(response.body.token);
        expect(chunks.toSorted()).toEqual(
          Array.from({ length: count }, (_, index) => `${port.name}.${index + 1}`).toSorted(),
        );
      },
    );
  });
  // #endregion

  // #region session names
  describe("session names", () => {
    it.each(portFamilyCases())(
      "$label: a name spelling another name's chunk cookie is a config failure",
      async (port) => {
        const body = await port.run(
          { name: port.name, key: port.key, cookie: { secure: false } },
          async (open) => {
            const codes: boolean[] = [];
            for (const name of [`${port.name}.1`, `${port.name}.16`]) {
              const error = await caught(() =>
                open({ name, key: port.key, cookie: { secure: false } }),
              );
              codes.push(isJWTError(error, "ERR_SESSION_CONFIG_INVALID"));
            }
            const dotted = await open({
              name: `${port.name}.v1`,
              key: port.key,
              cookie: { secure: false },
            });
            return { codes, dotted: dotted.id ?? null };
          },
        );

        expect(body).toEqual({ codes: [true, true], dotted: null });
      },
    );

    it.each(portFamilyCases())(
      "$label: a __Host- prefixed name round-trips under its prefix rules",
      async (port) => {
        const config = { name: `__Host-${port.name}`, key: port.key };
        const minted = await port.serve(config, async (open) => {
          const session = await open();
          await session.update({ user: "alice" });
          return { token: session.token };
        });
        const cookie = liveSetCookie(minted.cookies, config.name)!;

        const body = await port.run(
          config,
          async (open) => ({ user: (await open()).data.user ?? null }),
          { cookies: { [config.name]: minted.body.token as string } },
        );

        expect(setCookieAttributes(cookie)).toMatchObject({ path: "/", secure: true });
        expect(cookieAttribute(cookie, "domain")).toBeUndefined();
        expect(body).toEqual({ user: "alice" });
      },
    );
  });
  // #endregion

  // #region session header
  describe("session header", () => {
    it.each(portFamilyCases())(
      "$label: a session header that is not a header name is a config failure",
      async (port) => {
        const body = await port.run(baseConfig(port), async (open) => {
          const codes: boolean[] = [];
          for (const sessionHeader of ["bad header", "", "x-session\r\n", "x-sess:ion"]) {
            const error = await caught(() => open({ ...baseConfig(port), sessionHeader }));
            codes.push(isJWTError(error, "ERR_SESSION_CONFIG_INVALID"));
          }
          return { codes };
        });

        expect(body).toEqual({ codes: [true, true, true, true] });
      },
    );

    it.each(portFamilyCases())(
      "$label: an Authorization header without a Bearer token carries no token",
      async (port) => {
        const onError = vi.fn();
        const config = { ...baseConfig(port), sessionHeader: "authorization", hooks: { onError } };
        const bodies: Record<string, unknown>[] = [];
        for (const value of ["Bearer", "Bearer   ", "Basic dXNlcjpwYXNz", "Bearer a b"]) {
          bodies.push(
            await port.run(config, async (open) => ({ id: (await open()).id ?? null }), {
              headers: { authorization: value },
            }),
          );
        }

        expect(bodies).toEqual([{ id: null }, { id: null }, { id: null }, { id: null }]);
        expect(onError).not.toHaveBeenCalled();
      },
    );

    it.each(portFamilyCases().filter((port) => port.port !== "elysia"))(
      "$label: the session token reads as absent once the session is cleared",
      async (port) => {
        const cookieToken = await mintToken(port, baseConfig(port), { who: "cookie" });
        const headerToken = await mintToken(port, baseConfig(port), { who: "header" });
        const { read, clear } = h3TokenFunctions(port);

        const response = await serveOn(
          port.port,
          async (event) => {
            const before = read(event) ?? null;
            await clear(event);
            return { before, after: read(event) ?? null };
          },
          {
            cookies: { [port.name]: cookieToken },
            headers: { [`x-${port.name}-session`]: headerToken },
          },
        );

        expect(response.body).toEqual({ before: cookieToken, after: null });
      },
    );
  });
  // #endregion

  // #region update hooks and payload round trip
  describe("update hooks and the data round trip", () => {
    it.each(portFamilyCases())(
      "$label: an onUpdate hook that throws rejects the update, which stays issued",
      async (port) => {
        const onError = vi.fn();
        const config = {
          ...baseConfig(port),
          hooks: {
            onUpdate: () => {
              throw new Error("hook failed");
            },
            onError,
          },
        };
        const response = await port.serve(config, async (open) => {
          const session = await open();
          const error = await caught(() => session.update({ user: "alice" }));
          return {
            message: (error as Error).message,
            id: session.id ?? null,
            user: session.data.user ?? null,
            token: session.token ?? null,
          };
        });

        expect(response.body).toMatchObject({ message: "hook failed", user: "alice" });
        expect(response.body.id).toBeTypeOf("string");
        expect(liveCookies(response.cookies)[port.name]).toBe(response.body.token);
        expect(onError).not.toHaveBeenCalled();
      },
    );

    it.each(portFamilyCases())(
      "$label: session data reads back as its JSON round trip",
      async (port) => {
        const token = await mintToken(port, baseConfig(port), {
          at: new Date(0),
          ratio: Number.NaN,
          gone: undefined,
        });

        const body = await port.run(
          baseConfig(port),
          async (open) => ({ data: { ...(await open()).data } }),
          { cookies: { [port.name]: token } },
        );

        expect(body).toEqual({ data: { at: "1970-01-01T00:00:00.000Z", ratio: null } });
      },
    );
  });
  // #endregion

  // #region session kid
  describe("session kid", () => {
    it.each(portFamilyCases())(
      "$label: a configured protectedHeader.kid wins over the key's kid",
      async (port) => {
        const config = {
          ...kidConfig(port),
          ...issueOptions(port.family, { protectedHeader: { kid: "header-kid" } }),
        };
        const token = await mintToken(port, config, { user: "alice" });
        const read = await port.run(
          config,
          async (open) => ({ user: (await open()).data.user ?? null }),
          { cookies: { [port.name]: token } },
        );

        expect(protectedHeaderOf(token).kid).toBe("header-kid");
        expect(read).toEqual({ user: "alice" });
      },
    );

    it.each(portFamilyCases())(
      "$label: the key's kid is written when the config names none",
      async (port) => {
        const token = await mintToken(port, kidConfig(port), { user: "alice" });

        expect(protectedHeaderOf(token).kid).toBe("key-kid");
      },
    );
  });
  // #endregion

  // #region options reaching the token check
  describe("options reaching the token check", () => {
    it.each(portFamilyCases())(
      "$label: a symmetric key set from the lookup hook opens only with allowSymmetricJWKSet",
      async (port) => {
        const token = await mintToken(port, baseConfig(port), { user: "alice" });
        const lookup = () => ({ keys: [port.key] });
        const hooks =
          port.family === "jws" ? { onVerifyKeyLookup: lookup } : { onUnsealKeyLookup: lookup };

        const reads: Record<string, unknown>[] = [];
        for (const allowSymmetricJWKSet of [false, true]) {
          reads.push(
            await port.run(
              {
                ...baseConfig(port),
                ...openOptions(port.family, { allowSymmetricJWKSet }),
                hooks,
              },
              async (open) => ({ user: (await open()).data.user ?? null }),
              { cookies: { [port.name]: token } },
            ),
          );
        }

        expect(reads).toEqual([{ user: null }, { user: "alice" }]);
      },
    );

    it.each(portFamilyCases())(
      "$label: limits.keyCandidates bounds the key set a token is tried against",
      async (port) => {
        const token = await mintToken(port, baseConfig(port), { user: "alice" });
        const other = {
          ...(await generateJWK(port.family === "jws" ? "HS256" : "A128KW")),
          kid: (port.key as { kid?: string }).kid,
        };
        const lookup = () => ({ keys: [other, port.key] });
        const hooks =
          port.family === "jws" ? { onVerifyKeyLookup: lookup } : { onUnsealKeyLookup: lookup };

        const reads: Record<string, unknown>[] = [];
        for (const keyCandidates of [1, 2]) {
          reads.push(
            await port.run(
              {
                ...baseConfig(port),
                ...openOptions(port.family, {
                  allowSymmetricJWKSet: true,
                  limits: { keyCandidates },
                }),
                hooks,
              },
              async (open) => ({ user: (await open()).data.user ?? null }),
              { cookies: { [port.name]: token } },
            ),
          );
        }

        expect(reads).toEqual([{ user: null }, { user: "alice" }]);
      },
    );

    it("JWS verify options and JWE decrypt options take the same core options", () => {
      expectTypeOf<SessionVerifyOptions>().toHaveProperty("allowSymmetricJWKSet");
      expectTypeOf<SessionVerifyOptions>().toHaveProperty("limits");
      expectTypeOf<SessionDecryptOptions>().toHaveProperty("allowSymmetricJWKSet");
      expectTypeOf<SessionDecryptOptions>().toHaveProperty("limits");
      expectTypeOf<SessionVerifyOptions>().not.toHaveProperty("typ");
      expectTypeOf<SessionVerifyOptions>().not.toHaveProperty("maxTokenAge");
      expectTypeOf<SessionVerifyOptions>().not.toHaveProperty("payload");
      expectTypeOf<SessionVerifyOptions>().not.toHaveProperty("validateClaims");
      expectTypeOf<SessionVerifyOptions>().not.toHaveProperty("algorithms");
      expectTypeOf<SessionDecryptOptions>().not.toHaveProperty("typ");
      expectTypeOf<SessionDecryptOptions>().not.toHaveProperty("maxTokenAge");
      expectTypeOf<SessionDecryptOptions>().not.toHaveProperty("payload");
      expectTypeOf<SessionDecryptOptions>().not.toHaveProperty("validateClaims");
      expectTypeOf<SessionDecryptOptions>().not.toHaveProperty("algorithms");
    });

    it("h3 v2: the JWS and JWE sessions take the same event type", () => {
      expectTypeOf<Parameters<typeof useJWESessionV2>[0]>().toEqualTypeOf<
        Parameters<typeof useJWSSessionV2>[0]
      >();
    });
  });
  // #endregion

  // #region key pair halves
  describe("key pair halves", () => {
    const refusal = (port: PortFamilyCase, key: unknown) =>
      port.run({ name: port.name, key, cookie: { secure: false } }, async (open) => {
        const error = await caught(open);
        return {
          code: isJWTError(error, "ERR_SESSION_KEY_INVALID"),
          message: (error as Error | undefined)?.message ?? null,
        };
      });

    it.each(portFamilyCases())(
      "$label: names the private half when it is not a private key",
      async (port) => {
        const { publicKey } = await rsaPairFor(port);
        const body = await refusal(port, { publicKey, privateKey: publicKey });

        expect(body.code).toBe(true);
        expect(body.message).toMatch(/"privateKey"/);
      },
    );

    it.each(portFamilyCases())(
      "$label: names the public half when it is not a public key",
      async (port) => {
        const { privateKey } = await rsaPairFor(port);
        const body = await refusal(port, { publicKey: "hunter2", privateKey });

        expect(body.code).toBe(true);
        expect(body.message).toMatch(/"publicKey"/);
      },
    );

    it.each(portFamilyCases().filter((port) => port.family === "jwe"))(
      "$label: names the public half when the pair has none",
      async (port) => {
        const { privateKey } = await rsaPairFor(port);
        const body = await refusal(port, { privateKey });

        expect(body.code).toBe(true);
        expect(body.message).toMatch(/"publicKey"/);
      },
    );

    it.each(portFamilyCases().filter((port) => port.family === "jws"))(
      "$label: refuses a public key list or set carrying an entry that is not a public key",
      async (port) => {
        const { privateKey, publicKey } = await rsaPairFor(port);
        const bodies = [
          await refusal(port, { privateKey, publicKey: [publicKey, privateKey] }),
          await refusal(port, { privateKey, publicKey: { keys: [publicKey, jwsKey] } }),
          await refusal(port, { privateKey, publicKey: [] }),
        ];

        for (const body of bodies) {
          expect(body.code).toBe(true);
          expect(body.message).toMatch(/"publicKey"/);
        }
      },
    );
  });
  // #endregion

  // #region cookie attributes on the wire
  describe("cookie attributes on the wire", () => {
    const COOKIE_ATTRIBUTES = [
      "expires",
      "max-age",
      "domain",
      "path",
      "secure",
      "httponly",
      "samesite",
      "partitioned",
      "priority",
    ];

    it.each(portFamilyCases())(
      "$label: writes and expires its cookie with cookie attributes only",
      async (port) => {
        const config = {
          name: port.name,
          key: port.key,
          maxAge: 60,
          cookie: { secure: false, chunkMaxLength: 4000 },
        };
        const written = await port.serve(config, async (open) => {
          const session = await open();
          await session.update({ user: "alice" });
          return { token: session.token };
        });
        const cleared = await port.serve(
          config,
          async (open) => {
            await (await open()).clear();
            return { ok: true };
          },
          { cookies: { [port.name]: written.body.token as string } },
        );

        const headers = [...written.cookies, ...cleared.cookies];
        expect(written.cookies.length).toBeGreaterThan(0);
        expect(cleared.cookies.length).toBeGreaterThan(0);
        for (const header of headers) {
          for (const attribute of attributeNames(header)) {
            expect(COOKIE_ATTRIBUTES).toContain(attribute);
          }
        }
      },
    );

    it.each(portFamilyCases())(
      "$label: an expired cookie carries Max-Age=0 and an epoch Expires",
      async (port) => {
        const config = {
          name: port.name,
          key: port.key,
          maxAge: 3600,
          cookie: { secure: false, maxAge: 3600 },
        };
        const token = await mintToken(port, config, { user: "alice" });
        const cleared = await port.serve(
          config,
          async (open) => {
            await (await open()).clear();
            return { ok: true };
          },
          { cookies: { [port.name]: token } },
        );
        const dropped = await port.serve(
          config,
          async (open) => ({ id: (await open()).id ?? null }),
          {
            cookies: { [port.name]: await foreignToken(port.family, EXPIRED_CLAIMS) },
          },
        );

        for (const response of [cleared, dropped]) {
          const expired = expiredSetCookie(response.cookies, port.name);
          expect(expired).toBeDefined();
          expect(cookieAttribute(expired!, "max-age")).toBe("0");
          expect(Date.parse(cookieAttribute(expired!, "expires")!)).toBe(0);
        }
      },
    );

    it.each(["jws", "jwe"] as const)(
      "elysia %s: chunkMaxLength never reaches the cookie jar",
      async (family) => {
        const { context, store } = elysiaContext();
        const name = `jar-${family}`;
        const cookie = { secure: false, chunkMaxLength: 4000 };
        const session =
          family === "jws"
            ? await createJWSSession(context, { name, key: jwsKey, cookie })
            : await createJWESession(context, { name, key: jweKey, cookie });
        await session.update({ user: "alice" });
        const set = store.get(`jar-${family}`)!.lastWrite!;
        await session.clear();
        const expired = store.get(`jar-${family}`)!.lastWrite!;

        expect(set).not.toHaveProperty("chunkMaxLength");
        expect(expired).not.toHaveProperty("chunkMaxLength");
        expect(expired.value).toBe("");
      },
    );
  });
  // #endregion

  // #region cookie writes from the session core
  describe("cookie writes from the session core", () => {
    it.each(["jws", "jwe"] as const)(
      "%s: every write hands the port cookie attributes, with chunkMaxLength apart",
      async (family) => {
        const recorder = recordingPort({ token: await foreignToken(family, EXPIRED_CLAIMS) });
        const binding = coreBinding(family, recorder.port, {
          maxAge: 60,
          cookie: { secure: false, chunkMaxLength: 64 },
        });

        await loadSession(binding);
        const issued = await issueSession(binding, { user: "alice" });
        await dropSession(binding);

        expect(recorder.writes.map((write) => write.op)).toEqual(["delete", "set", "delete"]);
        for (const write of recorder.writes) {
          expect(write.attrs).not.toHaveProperty("chunkMaxLength");
          expect(write.attrs).toMatchObject({ path: "/", secure: false, sameSite: "lax" });
        }
        expect(recorder.writes[1]).toMatchObject({
          chunkMaxLength: 64,
          attrs: { expires: new Date(issued.expiresAt!) },
        });
      },
    );

    it.each(["jws", "jwe"] as const)(
      "%s: an expired session on a response that takes no cookie warns instead of writing",
      async (family) => {
        const warn = vi.spyOn(console, "warn").mockImplementation(() => {});
        try {
          const recorder = recordingPort({
            token: await foreignToken(family, EXPIRED_CLAIMS),
            writable: false,
          });
          const binding = coreBinding(family, recorder.port, { maxAge: 60 });
          const session = await loadSession(binding);

          expect(session.token).toBeUndefined();
          expect(recorder.writes).toEqual([]);
          expect(warn).toHaveBeenCalledOnce();
          expect(String(warn.mock.calls[0][0])).toMatch(/^\[test\] /);
        } finally {
          warn.mockRestore();
        }
      },
    );
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

/** The cookies a response leaves set, last write winning, without the ones it expires. */
function liveCookies(setCookies: string[]): Record<string, string> {
  const cookies: Record<string, string> = {};
  for (const setCookie of setCookies) {
    const pair = setCookie.split(";", 1)[0];
    const separator = pair.indexOf("=");
    cookies[pair.slice(0, separator).trim()] = decodeURIComponent(pair.slice(separator + 1).trim());
  }
  for (const [name, value] of Object.entries(cookies)) if (!value) delete cookies[name];
  return cookies;
}

/** The last `Set-Cookie` header a response writes for `name` with a value. */
function liveSetCookie(setCookies: string[], name: string): string | undefined {
  return setCookies.findLast(
    (setCookie) => setCookie.startsWith(`${name}=`) && !setCookie.startsWith(`${name}=;`),
  );
}

/** One attribute of a `Set-Cookie` header, matched case-insensitively. */
function cookieAttribute(setCookie: string, attribute: string): string | undefined {
  for (const part of setCookie.split(";").slice(1)) {
    const [key = "", ...value] = part.trim().split("=");
    if (key.toLowerCase() === attribute) return value.join("=");
  }
  return undefined;
}

type Family = "jws" | "jwe";
type Port = "h3 v2" | "h3 v1" | "elysia";
type Opener = (carrier: never, config: never) => Promise<unknown>;

interface ServeOptions {
  cookies?: Record<string, string>;
  headers?: Record<string, string>;
}

interface Served {
  status: number;
  body: Record<string, unknown>;
  cookies: string[];
}

/** What a handler returns to answer `401` the way its framework does. */
const UNAUTHORIZED: unique symbol = Symbol("unauthorized");

type Handler = (carrier: unknown) => Promise<Record<string, unknown> | typeof UNAUTHORIZED>;

interface PortFamilyCase {
  label: string;
  port: Port;
  family: Family;
  name: string;
  key: unknown;
  /** One request whose handler opens this session; resolves to the JSON body. */
  run: (
    config: Record<string, unknown>,
    body: (
      open: (override?: Record<string, unknown>) => Promise<SessionManager>,
    ) => Promise<Record<string, unknown>>,
    options?: ServeOptions,
  ) => Promise<Record<string, unknown>>;
  /** Like `run`, resolving to the whole response. */
  serve: (
    config: Record<string, unknown>,
    body: (
      open: (override?: Record<string, unknown>) => Promise<SessionManager>,
    ) => Promise<Record<string, unknown> | typeof UNAUTHORIZED>,
    options?: ServeOptions,
  ) => Promise<Served>;
  /** Open this session from inside a hook, through the request the hook names. */
  reopen: (
    args: Record<string, unknown>,
    config: Record<string, unknown>,
  ) => Promise<SessionManager>;
  /**
   * One request behind the framework's session guard: Elysia's session plugin
   * and its `requireSession` macro, an h3 handler answering `401` without a
   * session id.
   */
  guarded: (config: Record<string, unknown>, options?: ServeOptions) => Promise<Served>;
}

const OPENERS: Record<Port, Record<Family, Opener>> = {
  "h3 v2": { jws: useJWSSessionV2, jwe: useJWESessionV2 },
  "h3 v1": { jws: useJWSSessionV1, jwe: useJWESessionV1 },
  "elysia": { jws: createJWSSession, jwe: createJWESession },
};

const CLEARERS: Record<Exclude<Port, "elysia">, Record<Family, Opener>> = {
  "h3 v2": { jws: clearJWSSessionV2, jwe: clearJWESessionV2 },
  "h3 v1": { jws: clearJWSSessionV1, jwe: clearJWESessionV1 },
};

/** The same session case on every adapter and both families, each through a real app. */
function portFamilyCases(): PortFamilyCase[] {
  return (["h3 v2", "h3 v1", "elysia"] as const).flatMap((port) =>
    (["jws", "jwe"] as const).map((family) => portFamilyCase(port, family)),
  );
}

function portFamilyCase(port: Port, family: Family): PortFamilyCase {
  const openWith = (carrier: unknown, config: Record<string, unknown>) =>
    OPENERS[port][family](carrier as never, config as never) as Promise<SessionManager>;

  const serve: PortFamilyCase["serve"] = (config, body, options) =>
    serveOn(port, (carrier) => body((override) => openWith(carrier, override ?? config)), options);

  return {
    label: `${port} ${family}`,
    port,
    family,
    name: `contract-${family}`,
    key: family === "jws" ? jwsKey : jweKey,
    run: async (config, body, options) => (await serve(config, body, options)).body,
    serve,
    reopen: (args, config) => openWith(port === "elysia" ? args.context : args.event, config),
    guarded: async (config, options) => {
      if (port !== "elysia") {
        return serve(
          config,
          async (open) => {
            const session = await open();
            return session.id ? { id: session.id } : UNAUTHORIZED;
          },
          options,
        );
      }
      const plugin =
        family === "jws"
          ? jwsSession<Record<string, unknown>>(config as never)
          : jweSession<Record<string, unknown>>(config as never);
      const app = new Elysia()
        .use(plugin)
        .get("/", ({ session }) => ({ id: session.id ?? null }), { requireSession: true });
      const response = await app.handle(new Request("http://localhost/", requestInit(options)));
      return served(response.status, await response.text(), response.headers.getSetCookie());
    },
  };
}

async function serveOn(port: Port, handler: Handler, options?: ServeOptions): Promise<Served> {
  if (port === "h3 v2") {
    const app = new H3({ debug: true });
    app.get("/", async (event) => {
      const out = await handler(event);
      return out === UNAUTHORIZED ? new Response("Unauthorized", { status: 401 }) : out;
    });
    const response = await app.request("/", requestInit(options));
    return served(response.status, await response.text(), response.headers.getSetCookie());
  }

  if (port === "h3 v1") {
    const router = createRouter({ preemptive: true });
    const app = createApp({ debug: true }).use(router);
    router.use(
      "/",
      eventHandler(async (event) => {
        const out = await handler(event);
        if (out === UNAUTHORIZED) throw createError({ statusCode: 401 });
        return out;
      }),
    );
    let request = supertest(toNodeListener(app)).get("/");
    for (const [name, value] of Object.entries(requestInit(options).headers)) {
      request = request.set(name, value);
    }
    const response = await request;
    const cookies = (response.headers["set-cookie"] as unknown as string[] | undefined) ?? [];
    return served(response.status, response.text, cookies);
  }

  const app = new Elysia().get("/", async ({ cookie, request, status }) => {
    const out = await handler({ cookie, request });
    return out === UNAUTHORIZED ? status(401, "Unauthorized") : out;
  });
  const response = await app.handle(new Request("http://localhost/", requestInit(options)));
  return served(response.status, await response.text(), response.headers.getSetCookie());
}

function requestInit(options: ServeOptions | undefined): { headers: Record<string, string> } {
  return { headers: { ...options?.headers, ...cookieHeader(options?.cookies) } };
}

function served(status: number, text: string, cookies: string[]): Served {
  let body: unknown = text;
  try {
    body = JSON.parse(text);
  } catch {}
  return { status, body: body as Record<string, unknown>, cookies };
}

/** The h3 lower-level token reader and clearer of `port`, bound to its session. */
function h3TokenFunctions(port: PortFamilyCase): {
  read: (event: unknown) => string | undefined;
  clear: (event: unknown) => Promise<void>;
} {
  const jws = { name: port.name, key: jwsKey, cookie: { secure: false } };
  const jwe = { name: port.name, key: jweKey, cookie: { secure: false } };
  if (port.port === "h3 v2") {
    return port.family === "jws"
      ? {
          read: (event) => getJWSSessionTokenV2(event as never, jws),
          clear: (event) => clearJWSSessionV2(event as never, jws),
        }
      : {
          read: (event) => getJWESessionTokenV2(event as never, jwe),
          clear: (event) => clearJWESessionV2(event as never, jwe),
        };
  }
  return port.family === "jws"
    ? {
        read: (event) => getJWSSessionTokenV1(event as never, jws),
        clear: (event) => clearJWSSessionV1(event as never, jws),
      }
    : {
        read: (event) => getJWESessionTokenV1(event as never, jwe),
        clear: (event) => clearJWESessionV1(event as never, jwe),
      };
}

/** A token minted by the adapter itself, through one request of `port`. */
async function mintToken(
  port: PortFamilyCase,
  config: Record<string, unknown>,
  data: Record<string, unknown>,
  options?: { maxAge?: ExpiresIn },
): Promise<string> {
  const body = await port.run(config, async (open) => {
    const session = await open();
    await session.update(data, options);
    return { token: session.token };
  });
  return body.token as string;
}

/** A session-shaped token of `family` sealed with the session key, but minted outside the adapter. */
function foreignToken(
  family: Family,
  claims: Record<string, unknown>,
  header: Record<string, unknown> = {},
): Promise<string> {
  return family === "jws"
    ? foreignJWS(claims, header)
    : encrypt(claims, jweKey, {
        protectedHeader: { typ: "session+jwt", ...header },
      });
}

/** A plain JWT of `family` sealed with the session key, typed `JWT` as `sign()` / `encrypt()` mint it. */
function foreignPlainToken(family: Family, claims: Record<string, unknown>): Promise<string> {
  const options = { protectedHeader: { typ: "JWT" } };
  return family === "jws" ? sign(claims, jwsKey, options) : encrypt(claims, jweKey, options);
}

/** The protected header of a compact token. */
function protectedHeaderOf(token: string): Record<string, unknown> {
  return JSON.parse(base64UrlDecode(token.split(".")[0])) as Record<string, unknown>;
}

/** The claims a session token carries, opened with the session key. */
async function claimsOf(family: Family, token: string): Promise<Record<string, unknown>> {
  const opened =
    family === "jws"
      ? await verify(token, jwsKey, { validateClaims: false })
      : await decrypt(token, jweKey, { validateClaims: false });
  return opened.payload;
}

/** The `jws.signOptions` / `jwe.encryptOptions` block of a session config. */
function issueOptions(family: Family, options: Record<string, unknown>): Record<string, unknown> {
  return family === "jws"
    ? { jws: { signOptions: options } }
    : { jwe: { encryptOptions: options } };
}

/** The `jws.verifyOptions` / `jwe.decryptOptions` block of a session config. */
function openOptions(family: Family, options: Record<string, unknown>): Record<string, unknown> {
  return family === "jws"
    ? { jws: { verifyOptions: options } }
    : { jwe: { decryptOptions: options } };
}

/** The attribute names a `Set-Cookie` header carries, lowercased. */
function attributeNames(setCookie: string): string[] {
  return setCookie
    .split(";")
    .slice(1)
    .map((part) => (part.trim().split("=")[0] ?? "").toLowerCase());
}

/** The last `Set-Cookie` header a response expires `name` with. */
function expiredSetCookie(setCookies: string[], name: string): string | undefined {
  return setCookies.findLast(
    (setCookie) => setCookie.startsWith(`${name}=;`) || setCookie === `${name}=`,
  );
}

interface RecordedWrite {
  op: "set" | "delete";
  name: string;
  attrs: Record<string, unknown>;
  chunkMaxLength?: number;
}

/** A session port over a plain object, recording every cookie write the core asks of it. */
function recordingPort(options: { token?: string; writable?: boolean }): {
  port: SessionPort<object>;
  writes: RecordedWrite[];
} {
  const writes: RecordedWrite[] = [];
  const sessions: Record<string, unknown> = {};
  const port: SessionPort<object> = {
    prefix: "[test]",
    carrier: () => ({}),
    store: (_carrier, slot) => ({
      get: () => sessions[slot],
      set: (state) => {
        sessions[slot] = state;
      },
    }),
    readToken: () => options.token,
    scope: (carrier) => carrier,
    writable: () => options.writable ?? true,
    setCookie: (_carrier, name, _token, { attrs, chunkMaxLength }) => {
      writes.push({ op: "set", name, attrs, chunkMaxLength });
    },
    deleteCookie: (_carrier, name, { attrs }) => {
      writes.push({ op: "delete", name, attrs });
    },
  };
  return { port, writes };
}

/** A session of `family` bound to `port` straight through the session core. */
function coreBinding(
  family: Family,
  port: SessionPort<object>,
  config: Record<string, unknown>,
): SessionBinding<object, SessionCoreConfig> {
  const codec =
    family === "jws"
      ? createJWSCodec({ prefix: "[test]", defaultName: "core-jws" })
      : createJWECodec({ prefix: "[test]", defaultName: "core-jwe" });
  return bindSession<object, SessionCoreConfig>(
    {},
    { key: family === "jws" ? jwsKey : jweKey, ...config } as SessionCoreConfig,
    { port, codec: codec as unknown as SessionCodec<SessionCoreConfig> },
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
    return foreignJWS({ jti: "matrix", iat: nowSeconds(), exp: nowSeconds() + 3600 });
  }
  if (hook === "onExpire") return foreignJWS(EXPIRED_CLAIMS);
  if (hook === "onError") return "not.a.token";
  return undefined;
}

/**
 * Hooks that run their operation against the session they were dispatched from,
 * once — a hook that updated on every `onUpdate` would never stop. Each records
 * what it left the session as, for the handler to be compared against.
 */
function reentrantHooks(
  entry: MatrixEntry,
  open: (args: Record<string, unknown>) => Promise<SessionManager>,
  seen: unknown[],
): Record<string, (args: Record<string, unknown>) => Promise<void>> {
  let entered = false;
  return {
    [entry.hook]: async (args) => {
      if (entered) return;
      entered = true;
      const session = await open(args);
      if (entry.operation === "update") await session.update({ hook: entry.hook });
      else if (entry.operation === "clear") await session.clear();
      seen.push(entry.operation === "token" ? (session.token ?? null) : (session.id ?? null));
    },
  };
}

/** What the handler's own session must show once the hook has run its operation. */
function handlerView(entry: MatrixEntry, recorded: unknown): Record<string, unknown> {
  if (entry.operation === "update") return { id: recorded, hook: entry.hook };
  if (entry.operation === "clear") return { id: null, token: null };
  if (entry.operation === "token") return { token: recorded };
  return { id: recorded };
}

/** The call that dispatches `hook` once the request has been read. */
async function triggerHook(entry: MatrixEntry, session: SessionManager): Promise<void> {
  if (entry.hook === "onUpdate") await session.update({ user: "alice" });
  else if (entry.hook === "onClear") await session.clear();
}

/** The session config a contract case starts from: its name and key, cookies over plain HTTP. */
function baseConfig(port: PortFamilyCase) {
  return { name: port.name, key: port.key, cookie: { secure: false } };
}

/** {@link baseConfig} with a one-hour `maxAge`. */
function expiringConfig(port: PortFamilyCase) {
  return { name: port.name, key: port.key, maxAge: 3600, cookie: { secure: false } };
}

/** {@link baseConfig} with a `kid` on the session key. */
function kidConfig(port: PortFamilyCase) {
  return {
    name: port.name,
    key: { ...(port.key as Record<string, unknown>), kid: "key-kid" },
    cookie: { secure: false },
  };
}

/** A session token minted by the `/mint` route of an h3 v2 app. */
async function mintOnH3(app: H3, who: string): Promise<string> {
  const response = await app.request("/mint", {
    method: "POST",
    body: JSON.stringify({ who }),
  });
  return ((await response.json()) as { token: string }).token;
}

/** An h3 v1 app serving `handler` on every path. */
function h3v1App(handler: Parameters<typeof eventHandler>[0]): App {
  const router = createRouter({ preemptive: true });
  const app = createApp({ debug: true }).use(router);
  router.use("/", eventHandler(handler));
  return app;
}

/** The cookie names a response sets. */
function setCookieNames(response: Response): string[] {
  return response.headers.getSetCookie().map((cookie) => cookie.split("=")[0]);
}

/** An RSA key pair of the family `port` runs. */
function rsaPairFor(port: PortFamilyCase) {
  return generateJWK(port.family === "jws" ? "RS256" : "RSA-OAEP-256");
}
