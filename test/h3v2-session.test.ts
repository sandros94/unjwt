import { describe, it, expect, beforeEach, vi } from "vitest";
import { H3 } from "h3v2";
import {
  type SessionConfigJWE,
  type SessionConfigJWS,
  useJWESession,
  useJWSSession,
  updateJWESession,
  updateJWSSession,
  generateJWK,
} from "../src/adapters/h3v2";
import { encrypt } from "../src/core/jwe";
import { sign } from "../src/core/jws";

// Pre-generate every JWK once per file. Keygen (especially RSA) and PBES2
// password-based key derivation (600k PBKDF2 iterations) dominate the test
// time otherwise — doing them in beforeEach/it blocks multiplies the cost.
// Symmetric JWKs (A128KW, HS256, A256GCMKW) are also used to replace password
// keys in session configs that don't specifically exercise PBES2; PBES2 is
// covered by the dedicated jwe tests.
const [
  jweOctKey, // generic symmetric JWE key (replaces password strings throughout)
  jwsOctKey, // generic symmetric JWS key for hook-args tests
  jwsRsaPair, // RS256 pair for the main "jws session" describe
  jweLookupA, // A256GCMKW kid=test-key-1 for onUnsealKeyLookup
  jweLookupB, // A256GCMKW kid=test-key-2
  jwsLookupA, // RS256 kid=test-key-1 for onVerifyKeyLookup
  jwsLookupB, // RS256 kid=test-key-2
  jweOaepPair, // RSA-OAEP-256 pair for "asymmetric key pair" variant test
  jwsArrayRsa, // RS256 kid=array-key for "array of public JWKs" variant
  jwsJwksetRsa, // RS256 kid=jwkset-key for "JWKSet as publicKey" variant
] = await Promise.all([
  generateJWK("A128KW"),
  generateJWK("HS256"),
  generateJWK("RS256"),
  generateJWK("A256GCMKW", { kid: "test-key-1" }),
  generateJWK("A256GCMKW", { kid: "test-key-2" }),
  generateJWK("RS256", { kid: "test-key-1" }),
  generateJWK("RS256", { kid: "test-key-2" }),
  generateJWK("RSA-OAEP-256"),
  generateJWK("RS256", { kid: "array-key" }),
  generateJWK("RS256", { kid: "jwkset-key" }),
]);

describe("adapter h3 v2", () => {
  let app: H3;

  describe("jwe session", () => {
    let cookie = "";
    let sessionIdCtr = 0;
    const sessionConfig = {
      name: "h3-jwe-test",
      key: jweOctKey,
      generateId: () => String(++sessionIdCtr),
      sessionHeader: "Authorization",
    } as const satisfies SessionConfigJWE;

    beforeEach(() => {
      app = new H3({ debug: true });

      app.all("/init", async (event) => {
        const session = await useJWESession(event, sessionConfig).then((s) => s.update({}));

        return { session };
      });

      app.all("/", async (event) => {
        const session = await useJWESession(event, sessionConfig);
        if (event.req.method === "POST") {
          await session.update(await event.req.json());
        }
        return { session };
      });

      app.get("/token", async (event) => {
        const session = await useJWESession(event, sessionConfig);
        return session.token;
      });

      app.get("/update", async (event) => {
        const date = new Date();
        const session = await useJWESession(event, {
          ...sessionConfig,
          jwe: {
            encryptOptions: {
              currentDate: date,
            },
          },
        });
        const createdAtBefore = session.createdAt;

        await updateJWESession(
          event,
          {
            ...sessionConfig,
            jwe: {
              encryptOptions: {
                currentDate: new Date(date.getTime() + 1000), // date manipulation to ensure time difference
              },
            },
          },
          { updated: true },
        );

        return {
          createdAtBefore,
          createdAtAfter: session.createdAt,
        };
      });
    });

    it("initiates session", async () => {
      const result = await app.request("/init");
      expect(result.headers.getSetCookie()).toHaveLength(1);
      cookie = result.headers.getSetCookie()[0]!;
      expect(cookie).toContain(`${sessionConfig.name}=`);
      expect(await result.json()).toMatchObject({
        session: { id: "1", data: {}, token: expect.any(String) },
      });
    });

    it("gets same session back", async () => {
      const result = await app.request("/", {
        headers: {
          Cookie: cookie,
        },
      });
      expect(await result.json()).toMatchObject({
        session: { id: "1", data: {} },
      });
    });

    it("set session data", async () => {
      const result = await app.request("/", {
        method: "POST",
        headers: {
          Cookie: cookie,
          "Content-Type": "application/json",
        },
        body: JSON.stringify({ foo: "bar" }),
      });
      cookie = result.headers.getSetCookie()[0]!;
      expect(await result.json()).toMatchObject({
        session: { id: "2", data: { foo: "bar" } },
      });

      const result2 = await app.request("/", {
        headers: {
          Cookie: cookie,
        },
      });
      expect(await result2.json()).toMatchObject({
        session: { id: "2", data: { foo: "bar" } },
      });
    });

    it("gets same session back (concurrent)", async () => {
      app.get("/concurrent", async (event) => {
        const sessions = await Promise.all(
          [1, 2, 3].map(() =>
            useJWESession(event, sessionConfig).then((s) => ({
              id: s.id,
              data: s.data,
            })),
          ),
        );
        return {
          sessions,
        };
      });
      const result = await app.request("/concurrent", {
        headers: {
          Cookie: cookie,
        },
      });
      expect(await result.json()).toMatchObject({
        sessions: [1, 2, 3].map(() => ({ id: "2", data: { foo: "bar" } })),
      });
    });

    it("stores large data in chunks", async () => {
      const token = Array.from({ length: 5000 /* ~4k + one more */ }).fill("x").join("");
      const res = await app.request("/", {
        method: "POST",
        headers: { Cookie: cookie },
        body: JSON.stringify({ token }),
      });

      const cookies = res.headers.getSetCookie();
      const cookieNames = cookies.map((c) => c.split("=")[0]);
      expect(cookieNames.length).toBe(3 /* head + 2 */);
      expect(cookieNames).toMatchObject(["h3-jwe-test", "h3-jwe-test.1", "h3-jwe-test.2"]);

      const body = await res.json();
      expect(body.session.data.token).toBe(token);
    });

    it("accepts token from authorization header", async () => {
      const sealed = await encrypt(
        {
          jti: "999",
          iat: Math.floor(Date.now() / 1000),
          hello: "world",
        },
        sessionConfig.key,
      );

      const result = await app.request("/", {
        headers: {
          Authorization: `Bearer ${sealed}`,
        },
      });

      expect(await result.json()).toMatchObject({
        session: { id: "999", data: { hello: "world" } },
      });
    });

    it("retrieves the raw session token", async () => {
      const result = await app.request("/token", {
        headers: {
          Cookie: cookie,
        },
      });
      const token = await result.text();

      expect(token).toBeDefined();
      expect(token.length).toBeGreaterThan(0);
      expect(token).toBeTypeOf("string");
    });

    it("updates createdAt on session update", async () => {
      const result = await app.request("/update", {
        headers: {
          Cookie: cookie,
        },
      });

      const body = await result.json();

      expect(body.createdAtBefore).toBeDefined();
      expect(body.createdAtAfter).toBeDefined();
      expect(body.createdAtAfter).not.toBe(body.createdAtBefore);
    });

    it("token is the updated token even with cookie: false", async () => {
      const noCookieConfig: SessionConfigJWE = {
        ...sessionConfig,
        name: "h3-jwe-test-no-cookie",
        cookie: false,
      };

      app.get("/no-cookie-jwe", async (event) => {
        const session = await useJWESession(event, noCookieConfig);
        await session.update({ foo: "bar" });
        return { token: session.token, id: session.id, data: session.data };
      });

      const result = await app.request("/no-cookie-jwe");
      expect(result.headers.getSetCookie()).toHaveLength(0);
      const body = await result.json();
      expect(body.id).toBeDefined();
      expect(body.data).toMatchObject({ foo: "bar" });
      expect(body.token).toBeDefined();
      expect(typeof body.token).toBe("string");
      expect((body.token as string).length).toBeGreaterThan(0);
    });

    it("update throws on a non-writable event when cookies are enabled", async () => {
      // Read-only event (e.g. WebSocket upgrade) has no `.res`, so
      // `hasWritableResponse()` returns false and cookie-enabled updates must throw.
      const roConfig: SessionConfigJWE = {
        ...sessionConfig,
        name: "h3-jwe-test-no-res",
      };

      const mockEvent = {
        req: { headers: new Headers() },
        context: {},
      };

      const session = await useJWESession(mockEvent as any, roConfig);
      await expect(session.update({ foo: "bar" })).rejects.toThrow("[unjwt/h3]");
    });
  });

  describe("jws session", () => {
    let cookie = "";
    let sessionIdCtr = 0;
    const sessionConfig = {
      name: "h3-jws-test",
      key: jwsRsaPair,
      generateId: () => String(++sessionIdCtr),
      sessionHeader: "Authorization",
    } as const satisfies SessionConfigJWS;

    beforeEach(() => {
      app = new H3({ debug: true });

      app.all("/init", async (event) => {
        const session = await useJWSSession(event, sessionConfig).then((s) => s.update({}));

        return { session };
      });

      app.all("/", async (event) => {
        const session = await useJWSSession(event, sessionConfig);
        if (event.req.method === "POST") {
          await session.update(await event.req.json());
        }
        return { session };
      });

      app.get("/token", async (event) => {
        const session = await useJWSSession(event, sessionConfig);
        return session.token;
      });

      app.get("/update", async (event) => {
        const date = new Date();
        const session = await useJWSSession(event, {
          ...sessionConfig,
          jws: {
            signOptions: {
              currentDate: date,
            },
          },
        });
        const createdAtBefore = session.createdAt;

        await updateJWSSession(
          event,
          {
            ...sessionConfig,
            jws: {
              signOptions: {
                currentDate: new Date(date.getTime() + 1000), // date manipulation to ensure time difference
              },
            },
          },
          { updated: true },
        );

        return {
          createdAtBefore,
          createdAtAfter: session.createdAt,
        };
      });
    });

    it("initiates session", async () => {
      const result = await app.request("/init");
      expect(result.headers.getSetCookie()).toHaveLength(1);
      cookie = result.headers.getSetCookie()[0]!;
      expect(cookie).toContain(`${sessionConfig.name}=`);
      expect(await result.json()).toMatchObject({
        session: { id: "1", data: {}, token: expect.any(String) },
      });
    });

    it("gets same session back", async () => {
      const result = await app.request("/", {
        headers: {
          Cookie: cookie,
        },
      });
      expect(await result.json()).toMatchObject({
        session: { id: "1", data: {} },
      });
    });

    it("set session data", async () => {
      const result = await app.request("/", {
        method: "POST",
        headers: {
          Cookie: cookie,
          "Content-Type": "application/json",
        },
        body: JSON.stringify({ foo: "bar" }),
      });
      cookie = result.headers.getSetCookie()[0]!;
      expect(await result.json()).toMatchObject({
        session: { id: "2", data: { foo: "bar" } },
      });

      const result2 = await app.request("/", {
        headers: {
          Cookie: cookie,
        },
      });
      expect(await result2.json()).toMatchObject({
        session: { id: "2", data: { foo: "bar" } },
      });
    });

    it("gets same session back (concurrent)", async () => {
      app.get("/concurrent", async (event) => {
        const sessions = await Promise.all(
          [1, 2, 3].map(() =>
            useJWSSession(event, sessionConfig).then((s) => ({
              id: s.id,
              data: s.data,
            })),
          ),
        );
        return {
          sessions,
        };
      });
      const result = await app.request("/concurrent", {
        headers: {
          Cookie: cookie,
        },
      });
      expect(await result.json()).toMatchObject({
        sessions: [1, 2, 3].map(() => ({ id: "2", data: { foo: "bar" } })),
      });
    });

    it("stores large data in chunks", async () => {
      const token = Array.from({ length: 5000 /* ~4k + one more */ }).fill("x").join("");
      const res = await app.request("/", {
        method: "POST",
        headers: { Cookie: cookie },
        body: JSON.stringify({ token }),
      });

      const cookies = res.headers.getSetCookie();
      const cookieNames = cookies.map((c) => c.split("=")[0]);
      expect(cookieNames.length).toBe(3 /* head + 2 */);
      expect(cookieNames).toMatchObject(["h3-jws-test", "h3-jws-test.1", "h3-jws-test.2"]);

      const body = await res.json();
      expect(body.session.data.token).toBe(token);
    });

    it("accepts token from authorization header", async () => {
      const signed = await sign(
        {
          jti: "999",
          iat: Math.floor(Date.now() / 1000),
          hello: "world",
        },
        sessionConfig.key.privateKey,
      );

      const result = await app.request("/", {
        headers: {
          Authorization: `Bearer ${signed}`,
        },
      });

      expect(await result.json()).toMatchObject({
        session: { id: "999", data: { hello: "world" } },
      });
    });

    it("retrieves the raw session token", async () => {
      const result = await app.request("/token", {
        headers: {
          Cookie: cookie,
        },
      });
      const token = await result.text();

      expect(token).toBeDefined();
      expect(token.length).toBeGreaterThan(0);
      expect(token).toBeTypeOf("string");
    });

    it("updates createdAt on session update", async () => {
      const result = await app.request("/update", {
        headers: {
          Cookie: cookie,
        },
      });

      const body = await result.json();

      expect(body.createdAtBefore).toBeDefined();
      expect(body.createdAtAfter).toBeDefined();
      expect(body.createdAtAfter).not.toBe(body.createdAtBefore);
    });

    it("token is the updated token even with cookie: false", async () => {
      const noCookieConfig: SessionConfigJWS = {
        ...sessionConfig,
        name: "h3-jws-test-no-cookie",
        cookie: false,
      };

      app.get("/no-cookie-jws", async (event) => {
        const session = await useJWSSession(event, noCookieConfig);
        await session.update({ foo: "bar" });
        return { token: session.token, id: session.id, data: session.data };
      });

      const result = await app.request("/no-cookie-jws");
      expect(result.headers.getSetCookie()).toHaveLength(0);
      const body = await result.json();
      expect(body.id).toBeDefined();
      expect(body.data).toMatchObject({ foo: "bar" });
      expect(body.token).toBeDefined();
      expect(typeof body.token).toBe("string");
      expect((body.token as string).length).toBeGreaterThan(0);
    });

    it("update throws on a non-writable event when cookies are enabled", async () => {
      // Read-only event (e.g. WebSocket upgrade) has no `.res`, so
      // `hasWritableResponse()` returns false and cookie-enabled updates must throw.
      const roConfig: SessionConfigJWS = {
        ...sessionConfig,
        name: "h3-jws-test-no-res",
      };

      const mockEvent = {
        req: { headers: new Headers() },
        context: {},
      };

      const session = await useJWSSession(mockEvent as any, roConfig);
      await expect(session.update({ foo: "bar" })).rejects.toThrow("[unjwt/h3]");
    });
  });

  describe("hooks", () => {
    describe("jwe session hooks", () => {
      it("uses onUnsealKeyLookup to find the correct key", async () => {
        const key = jweLookupA;
        const otherKey = jweLookupB;

        const lookupSpy = vi.fn((args) => {
          if (args.header.kid === "test-key-1") {
            return key;
          }
          throw new Error("Key not found");
        });

        const config: SessionConfigJWE = {
          name: "h3-jwe-lookup",
          key: otherKey, // Default key is different
          hooks: {
            onUnsealKeyLookup: lookupSpy,
          },
        };

        const token = await encrypt(
          { jti: "123", iat: Math.floor(Date.now() / 1000), foo: "bar" },
          key,
        );

        const app = new H3({ debug: true });
        app.all("/", async (event) => {
          const session = await useJWESession(event, config);
          return { session };
        });

        const result = await app.request("/", {
          headers: {
            Cookie: `${config.name}=${token}`,
          },
        });

        expect(lookupSpy).toHaveBeenCalled();
        expect(await result.json()).toMatchObject({
          session: { data: { foo: "bar" } },
        });
      });
    });

    describe("jws session hooks", () => {
      it("uses onVerifyKeyLookup to find the correct key", async () => {
        const key = jwsLookupA;
        const otherKey = jwsLookupB;

        const lookupSpy = vi.fn((args) => {
          if (args.header.kid === "test-key-1") {
            return key.publicKey;
          }
          throw new Error("Key not found");
        });

        const config: SessionConfigJWS = {
          name: "h3-jws-lookup",
          key: otherKey, // Default key is different
          hooks: {
            onVerifyKeyLookup: lookupSpy,
          },
        };

        const token = await sign(
          { jti: "123", iat: Math.floor(Date.now() / 1000), foo: "bar" },
          key.privateKey,
        );

        const app = new H3({ debug: true });
        app.all("/", async (event) => {
          const session = await useJWSSession(event, config);
          return { session };
        });

        const result = await app.request("/", {
          headers: {
            Cookie: `${config.name}=${token}`,
          },
        });

        expect(lookupSpy).toHaveBeenCalled();
        expect(await result.json()).toMatchObject({
          session: { data: { foo: "bar" } },
        });
      });
    });
  });

  describe("hook args", () => {
    it("JWE onUpdate: session.token is the new JWT, oldSession.token is the previous one", async () => {
      const updates: Array<{
        token: string | undefined;
        oldToken: string | undefined;
        id: string | undefined;
      }> = [];
      let idCtr = 0;

      const config: SessionConfigJWE = {
        name: "h3-jwe-hook-args",
        key: jweOctKey,
        generateId: () => String(++idCtr),
        hooks: {
          onUpdate: vi.fn(({ session, oldSession }) => {
            updates.push({ token: session.token, oldToken: oldSession.token, id: session.id });
          }),
        },
      };

      const localApp = new H3({ debug: true });
      localApp.all("/", async (event) => {
        const session = await useJWESession(event, config);
        await session.update({ step: 1 });
        await session.update({ step: 2 });
        return { token: session.token };
      });

      const body = await (await localApp.request("/")).json();

      expect(updates).toHaveLength(2);
      expect(updates[0]!.oldToken).toBeUndefined();
      expect(updates[0]!.token).toBeTypeOf("string");
      expect(updates[0]!.id).toBe("1");
      expect(updates[1]!.oldToken).toBe(updates[0]!.token);
      expect(updates[1]!.token).not.toBe(updates[0]!.token);
      expect(updates[1]!.id).toBe("2");
      expect(body.token).toBe(updates[1]!.token);
    });

    it("JWE onUpdate fires even when update() is called with no data (token refresh)", async () => {
      const onUpdate = vi.fn();
      const config: SessionConfigJWE = {
        name: "h3-jwe-hook-no-data",
        key: jweOctKey,
        hooks: { onUpdate },
      };

      const localApp = new H3({ debug: true });
      localApp.all("/", async (event) => {
        const session = await useJWESession(event, config);
        await session.update(); // no data — pure token refresh
        return {};
      });

      await localApp.request("/");
      expect(onUpdate).toHaveBeenCalledOnce();
    });

    it("JWE onClear fires even with cookie:false and receives oldSession", async () => {
      let clearedToken: string | undefined;
      const onClear = vi.fn(({ oldSession }: { oldSession?: { token?: string } }) => {
        clearedToken = oldSession?.token;
      });
      const config: SessionConfigJWE = {
        name: "h3-jwe-hook-clear-nocookie",
        key: jweOctKey,
        cookie: false,
        hooks: { onClear },
      };
      const sessionHeader = `x-${config.name!.toLowerCase()}-session`;

      const localApp = new H3({ debug: true });
      localApp.all("/init", async (event) => {
        const session = await useJWESession(event, config);
        await session.update({});
        return { token: session.token };
      });
      localApp.all("/clear", async (event) => {
        const session = await useJWESession(event, config);
        await session.clear();
        return {};
      });

      const initRes = await localApp.request("/init");
      const { token } = (await initRes.json()) as { token: string };
      await localApp.request("/clear", { headers: { [sessionHeader]: token } });

      expect(onClear).toHaveBeenCalledOnce();
      expect(clearedToken).toBeTypeOf("string");
      expect(clearedToken!.length).toBeGreaterThan(0);
    });

    it("JWE onRead and onExpire: session.token reflects the current JWT", async () => {
      vi.useFakeTimers();
      vi.setSystemTime(new Date("2025-01-01T00:00:00.000Z"));

      const readTokens: (string | undefined)[] = [];
      const expireTokens: (string | undefined)[] = [];
      let idCtr = 0;

      const config: SessionConfigJWE = {
        name: "h3-jwe-hook-token-args",
        key: jweOctKey,
        maxAge: 1, // 1 second
        generateId: () => String(++idCtr),
        hooks: {
          onRead: vi.fn(({ session }) => {
            readTokens.push(session.token);
          }),
          onExpire: vi.fn(({ session }) => {
            expireTokens.push(session.token);
          }),
        },
      };

      const localApp = new H3({ debug: true });
      localApp.all("/", async (event) => {
        const session = await useJWESession(event, config);
        if (event.req.method === "POST") await session.update({});
        return { token: session.token };
      });

      await localApp.request("/", { method: "POST" });
      expect(readTokens[0]).toBeUndefined();

      const initRes = await localApp.request("/", { method: "POST" });
      const cookie = initRes.headers.getSetCookie()[0];
      expect(cookie).toBeDefined();

      await localApp.request("/", { headers: { Cookie: cookie! } });
      const lastReadToken = readTokens[readTokens.length - 1];
      expect(lastReadToken).toBeTypeOf("string");
      expect(lastReadToken!.length).toBeGreaterThan(0);

      vi.setSystemTime(new Date("2025-01-01T00:00:05.000Z"));
      await localApp.request("/", { headers: { Cookie: cookie! } });
      expect(expireTokens.length).toBeGreaterThan(0);
      expect(expireTokens[0]).toBeTypeOf("string");

      vi.useRealTimers();
    });

    it("JWS onUpdate: session.token is the new JWT, oldSession.token is the previous one", async () => {
      const updates: Array<{
        token: string | undefined;
        oldToken: string | undefined;
        id: string | undefined;
      }> = [];
      let idCtr = 0;

      const config: SessionConfigJWS = {
        name: "h3-jws-hook-args",
        key: jwsOctKey,
        generateId: () => String(++idCtr),
        hooks: {
          onUpdate: vi.fn(({ session, oldSession }) => {
            updates.push({ token: session.token, oldToken: oldSession.token, id: session.id });
          }),
        },
      };

      const localApp = new H3({ debug: true });
      localApp.all("/", async (event) => {
        const session = await useJWSSession(event, config);
        await session.update({ step: 1 });
        await session.update({ step: 2 });
        return { token: session.token };
      });

      const body = await (await localApp.request("/")).json();

      expect(updates).toHaveLength(2);
      expect(updates[0]!.oldToken).toBeUndefined();
      expect(updates[0]!.token).toBeTypeOf("string");
      expect(updates[0]!.id).toBe("1");
      expect(updates[1]!.oldToken).toBe(updates[0]!.token);
      expect(updates[1]!.token).not.toBe(updates[0]!.token);
      expect(updates[1]!.id).toBe("2");
      expect(body.token).toBe(updates[1]!.token);
    });

    it("JWS onClear receives the token and fires even with cookie:false", async () => {
      let clearedToken: string | undefined;

      const config: SessionConfigJWS = {
        name: "h3-jws-hook-clear-nocookie",
        key: jwsOctKey,
        cookie: false,
        hooks: {
          onClear: vi.fn(({ oldSession }) => {
            clearedToken = oldSession?.token;
          }),
        },
      };
      const sessionHeader = `x-${config.name!.toLowerCase()}-session`;

      const localApp = new H3({ debug: true });
      localApp.all("/init", async (event) => {
        const session = await useJWSSession(event, config);
        await session.update({});
        return { token: session.token };
      });
      localApp.all("/clear", async (event) => {
        const session = await useJWSSession(event, config);
        await session.clear();
        return {};
      });

      const initRes = await localApp.request("/init");
      const { token } = (await initRes.json()) as { token: string };
      await localApp.request("/clear", { headers: { [sessionHeader]: token } });

      expect(clearedToken).toBeTypeOf("string");
      expect(clearedToken!.length).toBeGreaterThan(0);
    });

    it("onError fires on write-path (sign failure) with token:undefined, and session is rolled back", async () => {
      const onError = vi.fn();
      const onUpdate = vi.fn();

      const badKey = { kty: "EC" } as any;
      const config: SessionConfigJWS = {
        name: "h3-jws-hook-sign-error",
        key: badKey,
        hooks: { onError, onUpdate },
      };

      const localApp = new H3({ debug: true });
      let threwInHandler = false;
      localApp.all("/", async (event) => {
        const session = await useJWSSession(event, config);
        try {
          await session.update({ foo: "bar" });
        } catch {
          threwInHandler = true;
        }
        return { id: session.id ?? null, token: session.token ?? null };
      });

      const body = await (await localApp.request("/")).json();

      expect(onError).toHaveBeenCalledOnce();
      expect(onUpdate).not.toHaveBeenCalled();
      expect(onError.mock.calls[0]![0].token).toBeUndefined();
      expect(threwInHandler).toBe(true);
      expect(body.id).toBeNull();
      expect(body.token).toBeNull();
    });

    it("onError fires on write-path (seal failure) with token:undefined, and session is rolled back", async () => {
      const onError = vi.fn();
      const onUpdate = vi.fn();

      const badKey = { kty: "EC" } as any;
      const config: SessionConfigJWE = {
        name: "h3-jwe-hook-seal-error",
        key: badKey,
        hooks: { onError, onUpdate },
      };

      const localApp = new H3({ debug: true });
      let threwInHandler = false;
      localApp.all("/", async (event) => {
        const session = await useJWESession(event, config);
        try {
          await session.update({ foo: "bar" });
        } catch {
          threwInHandler = true;
        }
        return { id: session.id ?? null, token: session.token ?? null };
      });

      const body = await (await localApp.request("/")).json();

      expect(onError).toHaveBeenCalledOnce();
      expect(onUpdate).not.toHaveBeenCalled();
      expect(onError.mock.calls[0]![0].token).toBeUndefined();
      expect(threwInHandler).toBe(true);
      expect(body.id).toBeNull();
      expect(body.token).toBeNull();
    });
  });

  describe("key variants", () => {
    it("JWE session works with symmetric JWK key (oct)", async () => {
      const config: SessionConfigJWE = {
        name: "h3-jwe-symjwk",
        key: jweOctKey,
      };

      const app = new H3({ debug: true });
      let cookie = "";

      app.all("/init", async (event) => {
        const session = await useJWESession(event, config);
        await session.update({ hello: "world" });
        return { session };
      });

      app.get("/", async (event) => {
        const session = await useJWESession(event, config);
        return { session };
      });

      const initResult = await app.request("/init");
      cookie = initResult.headers.getSetCookie()[0]!;
      expect(cookie).toContain("h3-jwe-symjwk=");

      const readResult = await app.request("/", {
        headers: { Cookie: cookie },
      });
      expect(await readResult.json()).toMatchObject({
        session: { data: { hello: "world" } },
      });
    });

    it("JWE session works with asymmetric key pair (privateKey/publicKey)", async () => {
      const config: SessionConfigJWE = {
        name: "h3-jwe-keypair",
        key: { privateKey: jweOaepPair.privateKey, publicKey: jweOaepPair.publicKey },
      };

      const app = new H3({ debug: true });
      let cookie = "";

      app.all("/init", async (event) => {
        const session = await useJWESession(event, config);
        await session.update({ secret: "data" });
        return { session };
      });

      app.get("/", async (event) => {
        const session = await useJWESession(event, config);
        return { session };
      });

      const initResult = await app.request("/init");
      cookie = initResult.headers.getSetCookie()[0]!;
      expect(cookie).toContain("h3-jwe-keypair=");

      const readResult = await app.request("/", {
        headers: { Cookie: cookie },
      });
      expect(await readResult.json()).toMatchObject({
        session: { data: { secret: "data" } },
      });
    });

    it("JWS session works with symmetric JWK key", async () => {
      const config: SessionConfigJWS = {
        name: "h3-jws-symjwk",
        key: jwsOctKey, // isSymmetricJWK branch in getVerifyKey
      };

      const app = new H3({ debug: true });
      let cookie = "";

      app.all("/init", async (event) => {
        const session = await useJWSSession(event, config);
        await session.update({ foo: "bar" });
        return { session };
      });

      app.get("/", async (event) => {
        const session = await useJWSSession(event, config);
        return { session };
      });

      const initResult = await app.request("/init");
      cookie = initResult.headers.getSetCookie()[0]!;

      const readResult = await app.request("/", {
        headers: { Cookie: cookie },
      });
      expect(await readResult.json()).toMatchObject({
        session: { data: { foo: "bar" } },
      });
    });

    it("JWS session works with array of public JWKs", async () => {
      const config: SessionConfigJWS = {
        name: "h3-jws-array",
        key: {
          privateKey: jwsArrayRsa.privateKey,
          publicKey: [jwsArrayRsa.publicKey], // array branch in getVerifyKey
        },
      };

      const app = new H3({ debug: true });
      let cookie = "";

      app.all("/init", async (event) => {
        const session = await useJWSSession(event, config);
        await session.update({ foo: "bar" });
        return { session };
      });

      app.get("/", async (event) => {
        const session = await useJWSSession(event, config);
        return { session };
      });

      const initResult = await app.request("/init");
      cookie = initResult.headers.getSetCookie()[0]!;

      const readResult = await app.request("/", {
        headers: { Cookie: cookie },
      });
      expect(await readResult.json()).toMatchObject({
        session: { data: { foo: "bar" } },
      });
    });

    it("JWS session works with JWKSet as publicKey", async () => {
      const config: SessionConfigJWS = {
        name: "h3-jws-jwkset",
        key: {
          privateKey: jwsJwksetRsa.privateKey,
          publicKey: { keys: [jwsJwksetRsa.publicKey] }, // JWKSet branch in getVerifyKey
        },
      };

      const app = new H3({ debug: true });
      let cookie = "";

      app.all("/init", async (event) => {
        const session = await useJWSSession(event, config);
        await session.update({ baz: "qux" });
        return { session };
      });

      app.get("/", async (event) => {
        const session = await useJWSSession(event, config);
        return { session };
      });

      const initResult = await app.request("/init");
      cookie = initResult.headers.getSetCookie()[0]!;

      const readResult = await app.request("/", {
        headers: { Cookie: cookie },
      });
      expect(await readResult.json()).toMatchObject({
        session: { data: { baz: "qux" } },
      });
    });
  });
});
