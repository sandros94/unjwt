import supertest from "supertest";
import { describe, it, expect, vi } from "vitest";
import { H3 } from "h3v2";
import { createApp, createRouter, toNodeListener, eventHandler, type App } from "h3v1";
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
import { createJWSSession, jwsSession } from "../src/adapters/elysia/session/jws";
import { createJWESession } from "../src/adapters/elysia/session/jwe";
import type { SessionContext } from "../src/adapters/elysia/session/types";
import type { CookieAttributes } from "../src/adapters/elysia/_cookie";

const [jwsKey, jweKey] = await Promise.all([generateJWK("HS256"), generateJWK("A128KW")]);

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
        const session = await useJWESessionV2(event, {
          name: "contract-jwe-str",
          key: "a password" as never,
        });
        const error = await caught(() => session.update({ user: "alice" }));
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

    it("keeps a JWS and a JWE session that share a name apart", async () => {
      const app = new H3({ debug: true });
      app.get("/", async (event) => {
        const jws = await useJWSSessionV2(event, { name: "shared", key: jwsKey });
        await jws.update({ family: "jws" });
        const jwe = await useJWESessionV2(event, { name: "shared", key: jweKey });
        await jwe.update({ family: "jwe" });
        return {
          jws: (jws.data as Record<string, unknown>).family,
          jwe: (jwe.data as Record<string, unknown>).family,
          distinct: jws.id !== jwe.id,
        };
      });

      expect(await (await app.request("/")).json()).toEqual({
        jws: "jws",
        jwe: "jwe",
        distinct: true,
      });
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
        const session = await useJWESessionV1(event, {
          name: "contract-jwe-str",
          key: "a password" as never,
        });
        const error = await caught(() => session.update({ user: "alice" }));
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

    it("keeps a JWS and a JWE session that share a name apart", async () => {
      const app = h3v1App(async (event) => {
        const jws = await useJWSSessionV1(event, { name: "shared", key: jwsKey });
        await jws.update({ family: "jws" });
        const jwe = await useJWESessionV1(event, { name: "shared", key: jweKey });
        await jwe.update({ family: "jwe" });
        return {
          jws: (jws.data as Record<string, unknown>).family,
          jwe: (jwe.data as Record<string, unknown>).family,
        };
      });

      const response = await supertest(toNodeListener(app)).get("/");
      expect(response.body).toEqual({ jws: "jws", jwe: "jwe" });
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
      const session = await createJWESession(context, { key: "a password" as never });
      const error = await caught(() => session.update({ user: "alice" }));

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
        key: jweKey,
        jwe: {
          encryptOptions: { alg: "PBES2-HS256+A128KW", enc: "A128GCM", p2c: 2048 },
        },
      } as const;

      const costly = await encrypt({ jti: "costly", iat: nowSeconds() }, jweKey, {
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
        key: jweKey,
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
});
