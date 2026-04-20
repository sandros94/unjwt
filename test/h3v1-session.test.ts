import supertest from "supertest";
import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import { type App, createApp, createRouter, toNodeListener, eventHandler, readBody } from "h3v1";
import { base64UrlDecode } from "unsecure/utils";

import {
  type SessionConfigJWE,
  type SessionConfigJWS,
  type SessionHooksJWE,
  type SessionHooksJWS,
  useJWESession,
  useJWSSession,
  updateJWESession,
  updateJWSSession,
  generateJWK,
} from "../src/adapters/h3v1";
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
  jwsRsaPair, // RS256 pair for the main "jws session" describe and the jws hooks refresh flow
  jweLookupA, // A256GCMKW kid=test-key-1 for onUnsealKeyLookup
  jweLookupB, // A256GCMKW kid=test-key-2
  jwsLookupA, // RS256 kid=test-key-1 for onVerifyKeyLookup
  jwsLookupB, // RS256 (no kid) for onVerifyKeyLookup — the "default" wrong key
  jweOaepPair, // RSA-OAEP-256 pair for "asymmetric key pair" variant test
  jwsArrayRsa, // RS256 kid=array-key for "array of public JWKs" variant
] = await Promise.all([
  generateJWK("A128KW"),
  generateJWK("HS256"),
  generateJWK("RS256"),
  generateJWK("A256GCMKW", { kid: "test-key-1" }),
  generateJWK("A256GCMKW", { kid: "test-key-2" }),
  generateJWK("RS256", { kid: "test-key-1" }),
  generateJWK("RS256"),
  generateJWK("RSA-OAEP-256"),
  generateJWK("RS256", { kid: "array-key" }),
]);

describe("adapter h3 v1", () => {
  let app: App;
  let router: ReturnType<typeof createRouter>;
  let request: ReturnType<typeof supertest>;

  // #region JWE
  describe("jwe session", () => {
    let cookie = "";
    let sessionIdCtr = 0;
    const sessionConfig: SessionConfigJWE = {
      name: "h3-jwe-test",
      key: jweOctKey,
      generateId: () => String(++sessionIdCtr),
    };

    beforeEach(() => {
      router = createRouter({ preemptive: true });
      app = createApp({ debug: true }).use(router);
      request = supertest(toNodeListener(app));

      router.use(
        "/init",
        eventHandler(async (event) => {
          const session = await useJWESession(event, sessionConfig).then((s) => s.update({}));

          return { session };
        }),
      );

      router.use(
        "/",
        eventHandler(async (event) => {
          const session = await useJWESession(event, sessionConfig);
          if (event.method === "POST") {
            await session.update(await readBody(event));
          }
          return { session };
        }),
      );

      router.use(
        "/token",
        eventHandler(async (event) => {
          const session = await useJWESession(event, sessionConfig);

          return session.token;
        }),
      );

      router.use(
        "/update",
        eventHandler(async (event) => {
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
        }),
      );
    });

    it("initiates session", async () => {
      const result = await request.get("/init");
      expect(result.headers["set-cookie"]).toHaveLength(1);
      cookie = result.headers["set-cookie"]![0]!;
      expect(result.body).toMatchObject({
        session: { id: "1", data: {}, token: expect.any(String) },
      });
    });

    it("gets same session back", async () => {
      const result = await request.get("/").set("Cookie", cookie);
      expect(result.body).toMatchObject({
        session: { id: "1", data: {} },
      });
    });

    it("set session data", async () => {
      const result = await request.post("/").set("Cookie", cookie).send({ foo: "bar" });
      cookie = result.headers["set-cookie"]![0]!;
      expect(result.body).toMatchObject({
        session: { id: "2", data: { foo: "bar" } },
      });

      const result2 = await request.get("/").set("Cookie", cookie);
      expect(result2.body).toMatchObject({
        session: { id: "2", data: { foo: "bar" } },
      });
    });

    it("gets same session back (concurrent)", async () => {
      router.use(
        "/concurrent",
        eventHandler(async (event) => {
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
        }),
      );
      const result = await request.get("/concurrent").set("Cookie", cookie);
      expect(result.body).toMatchObject({
        sessions: [1, 2, 3].map(() => ({ id: "2", data: { foo: "bar" } })),
      });
    });

    it("retrieves the raw session token", async () => {
      const result = await request.get("/token").set("Cookie", cookie);
      const token = result.text;

      expect(token).toBeDefined();
      expect(token.length).toBeGreaterThan(0);
      expect(token).toBeTypeOf("string");
    });

    it("updates createdAt on session update", async () => {
      const result = await request.post("/update").set("Cookie", cookie);
      expect(result.body.createdAtBefore).toBeDefined();
      expect(result.body.createdAtAfter).toBeDefined();
      expect(result.body.createdAtAfter).not.toBe(result.body.createdAtBefore);
    });

    it("token is the updated token even with cookie: false", async () => {
      const noCookieConfig: SessionConfigJWE = {
        ...sessionConfig,
        name: "h3-jwe-test-no-cookie",
        cookie: false,
      };

      router.use(
        "/no-cookie-jwe",
        eventHandler(async (event) => {
          const session = await useJWESession(event, noCookieConfig);
          await session.update({ foo: "bar" });
          return { token: session.token, id: session.id, data: session.data };
        }),
      );

      const result = await request.get("/no-cookie-jwe");
      expect(result.headers["set-cookie"]).toBeUndefined();
      expect(result.body.id).toBeDefined();
      expect(result.body.data).toMatchObject({ foo: "bar" });
      expect(result.body.token).toBeDefined();
      expect(typeof result.body.token).toBe("string");
      expect((result.body.token as string).length).toBeGreaterThan(0);
    });
  });

  // #region JWS
  describe("jws session", () => {
    let cookie = "";
    let sessionIdCtr = 0;
    const sessionConfig: SessionConfigJWS = {
      name: "h3-jws-test",
      key: jwsRsaPair,
      generateId: () => String(++sessionIdCtr),
    };

    beforeEach(() => {
      router = createRouter({ preemptive: true });
      app = createApp({ debug: true }).use(router);
      request = supertest(toNodeListener(app));

      router.use(
        "/init",
        eventHandler(async (event) => {
          const session = await useJWSSession(event, sessionConfig).then((s) => s.update({}));

          return { session };
        }),
      );

      router.use(
        "/",
        eventHandler(async (event) => {
          const session = await useJWSSession(event, sessionConfig);
          if (event.method === "POST") {
            await session.update(await readBody(event));
          }
          return { session };
        }),
      );

      router.use(
        "/token",
        eventHandler(async (event) => {
          const session = await useJWSSession(event, sessionConfig);

          return session.token;
        }),
      );

      router.use(
        "/update",
        eventHandler(async (event) => {
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
        }),
      );
    });

    it("initiates session", async () => {
      const result = await request.get("/init");
      expect(result.headers["set-cookie"]).toHaveLength(1);
      cookie = result.headers["set-cookie"]![0]!;
      expect(result.body).toMatchObject({
        session: { id: "1", data: {}, token: expect.any(String) },
      });
    });

    it("gets same session back", async () => {
      const result = await request.get("/").set("Cookie", cookie);
      expect(result.body).toMatchObject({
        session: { id: "1", data: {} },
      });
    });

    it("set session data", async () => {
      const result = await request.post("/").set("Cookie", cookie).send({ foo: "bar" });
      cookie = result.headers["set-cookie"]![0]!;
      expect(result.body).toMatchObject({
        session: { id: "2", data: { foo: "bar" } },
      });

      const result2 = await request.get("/").set("Cookie", cookie);
      expect(result2.body).toMatchObject({
        session: { id: "2", data: { foo: "bar" } },
      });
    });

    it("gets same session back (concurrent)", async () => {
      router.use(
        "/concurrent",
        eventHandler(async (event) => {
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
        }),
      );
      const result = await request.get("/concurrent").set("Cookie", cookie);
      expect(result.body).toMatchObject({
        sessions: [1, 2, 3].map(() => ({ id: "2", data: { foo: "bar" } })),
      });
    });

    it("retrieves the raw session token", async () => {
      const result = await request.get("/token").set("Cookie", cookie);
      const token = result.text;

      expect(token).toBeDefined();
      expect(token.length).toBeGreaterThan(0);
      expect(token).toBeTypeOf("string");
    });

    it("updates createdAt on session update", async () => {
      const result = await request.post("/update").set("Cookie", cookie);
      expect(result.body.createdAtBefore).toBeDefined();
      expect(result.body.createdAtAfter).toBeDefined();
      expect(result.body.createdAtAfter).not.toBe(result.body.createdAtBefore);
    });

    it("token is the updated token even with cookie: false", async () => {
      const noCookieConfig: SessionConfigJWS = {
        ...sessionConfig,
        name: "h3-jws-test-no-cookie",
        cookie: false,
      };

      router.use(
        "/no-cookie-jws",
        eventHandler(async (event) => {
          const session = await useJWSSession(event, noCookieConfig);
          await session.update({ foo: "bar" });
          return { token: session.token, id: session.id, data: session.data };
        }),
      );

      const result = await request.get("/no-cookie-jws");
      expect(result.headers["set-cookie"]).toBeUndefined();
      expect(result.body.id).toBeDefined();
      expect(result.body.data).toMatchObject({ foo: "bar" });
      expect(result.body.token).toBeDefined();
      expect(typeof result.body.token).toBe("string");
      expect((result.body.token as string).length).toBeGreaterThan(0);
    });
  });

  // #region Hooks
  describe("hooks", () => {
    const getCookieValue = (cookies: string | string[] | undefined, name: string) => {
      const list = Array.isArray(cookies) ? cookies : cookies ? [cookies] : [];
      return list.find((cookie) => cookie.startsWith(`${name}=`))?.split(";")[0];
    };

    describe("jwe session hooks", () => {
      let cookie = "";
      let sessionIdCtr = 0;
      let sessionConfig: SessionConfigJWE;
      let hooks: SessionHooksJWE;
      const errors: unknown[] = [];

      beforeEach(() => {
        vi.useRealTimers();
        cookie = "";
        sessionIdCtr = 0;
        errors.length = 0;

        hooks = {
          onRead: vi.fn(async ({ session, event, config }) => {
            if (session.expiresAt !== undefined) {
              const timeLeft = session.expiresAt - session.createdAt;
              if (timeLeft < config.maxAge! / 2) {
                await updateJWESession(event, config);
              }
            }
          }),
          onUpdate: vi.fn(),
          onClear: vi.fn(),
          onExpire: vi.fn(),
          onError: vi.fn(({ error }) => {
            errors.push(error);
          }),
        };

        sessionConfig = {
          name: "h3-jwe-hooks",
          key: jweOctKey,
          maxAge: 2,
          generateId: () => String(++sessionIdCtr),
          hooks,
        };

        router = createRouter({ preemptive: true });
        app = createApp({ debug: true }).use(router);
        request = supertest(toNodeListener(app));

        router.use(
          "/",
          eventHandler(async (event) => {
            const session = await useJWESession(event, sessionConfig);
            await (event.method === "POST"
              ? session.update(await readBody(event))
              : session.update({}));
            return { session };
          }),
        );

        router.use(
          "/clear",
          eventHandler(async (event) => {
            const session = await useJWESession(event, sessionConfig);
            await session.clear();
            return { cleared: true };
          }),
        );
      });

      afterEach(() => {
        vi.useRealTimers();
      });

      it("refreshes near-expiring session via onRead hook", async () => {
        vi.useFakeTimers();
        vi.setSystemTime(new Date("2024-01-01T00:00:00.000Z"));

        const first = await request.get("/");
        cookie = getCookieValue(first.headers["set-cookie"], sessionConfig.name!)!;
        const firstToken = cookie;

        expect(hooks.onRead).toHaveBeenCalledTimes(0);
        expect(first.body.session.id).toBe("1");
        const firstExpiresAt = first.body.session.expiresAt;
        expect(firstExpiresAt).toBeDefined();

        const nearExpiry = new Date("2024-01-01T00:00:01.600Z");
        vi.setSystemTime(nearExpiry);
        expect(Date.now()).toBe(nearExpiry.getTime());
        const second = await request.get("/").set("Cookie", cookie);
        const nextCookie = getCookieValue(second.headers["set-cookie"], sessionConfig.name!)!;

        expect(nextCookie).toBeTruthy();
        expect(nextCookie).not.toEqual(firstToken);
        expect(hooks.onRead).toHaveBeenCalledTimes(0);
        expect(hooks.onExpire).toHaveBeenCalledTimes(1);
        expect(second.body.session.id).toBe("2");
        const secondExpiresAt = second.body.session.expiresAt;
        expect(secondExpiresAt).toBeDefined();
        expect(secondExpiresAt).toBeGreaterThan(firstExpiresAt);

        vi.useRealTimers();
      });

      it("triggers onUpdate and onClear hooks", async () => {
        const first = await request.get("/");
        cookie = getCookieValue(first.headers["set-cookie"], sessionConfig.name!)!;

        const updateResponse = await request.post("/").set("Cookie", cookie).send({ foo: "bar" });
        cookie =
          getCookieValue(updateResponse.headers["set-cookie"], sessionConfig.name!) ?? cookie;

        expect(hooks.onUpdate).toHaveBeenCalledTimes(2); // one for initial update, one for this
        expect(updateResponse.body.session.data).toMatchObject({ foo: "bar" });

        const clearResponse = await request.post("/clear").set("Cookie", cookie);
        expect(clearResponse.body).toMatchObject({ cleared: true });
        expect(hooks.onClear).toHaveBeenCalledTimes(1);
      });

      it("invokes onError for invalid tokens", async () => {
        const response = await request
          .get("/")
          .set("Cookie", `${sessionConfig.name}=malformed-token`);

        expect(hooks.onError).toHaveBeenCalledTimes(1);
        expect(errors).toHaveLength(1);
        expect(String(errors[0])).toContain("Invalid session token");
        expect(response.headers["set-cookie"]).toHaveLength(1);
      });

      it("uses onUnsealKeyLookup to find the correct key", async () => {
        const key = jweLookupA;
        const otherKey = jweLookupB;

        const lookupSpy = vi.fn((args) => {
          if (args.header.kid === "test-key-1" && args.header.kid === key.kid) {
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

        const app = createApp({ debug: true });
        app.use(
          "/",
          eventHandler(async (event) => {
            const session = await useJWESession(event, config);
            return { session };
          }),
        );
        const request = supertest(toNodeListener(app));

        const result = await request.get("/").set("Cookie", `${config.name}=${token}`);

        expect(lookupSpy).toHaveBeenCalled();
        expect(result.body.session.data).toMatchObject({ foo: "bar" });
      });
    });

    describe("jws session hooks", async () => {
      let accessCookie = "";
      let refreshCookie = "";
      let accessConfig: SessionConfigJWS;
      let refreshConfig: SessionConfigJWE;
      let accessHooks: SessionHooksJWS;
      let refreshHooks: SessionHooksJWE;
      const refreshChecks: string[] = [];
      const accessErrors: unknown[] = [];
      let accessIdCtr = 0;
      let refreshIdCtr = 0;

      beforeEach(async () => {
        vi.useRealTimers();
        accessCookie = "";
        refreshCookie = "";
        refreshChecks.length = 0;
        accessErrors.length = 0;
        accessIdCtr = 0;
        refreshIdCtr = 0;

        refreshHooks = {
          onRead: vi.fn(),
          onUpdate: vi.fn(),
          onClear: vi.fn(),
          onExpire: vi.fn(),
          onError: vi.fn(),
        };

        refreshConfig = {
          name: "refresh_token",
          key: jweOctKey,
          maxAge: 60,
          generateId: () => `refresh-${++refreshIdCtr}`,
          hooks: refreshHooks,
          jwe: {
            encryptOptions: {
              protectedHeader: {
                typ: "rt+jwt", // allow custom `typ`
              },
            },
          },
        };

        accessHooks = {
          onRead: vi.fn(),
          onUpdate: vi.fn(),
          onClear: vi.fn(),
          onExpire: vi.fn(async ({ event, error }) => {
            const refreshSession = await useJWESession(event, refreshConfig);
            const refreshId = refreshSession.id;
            if (!refreshId) {
              throw new Error("refresh session missing id");
            }
            refreshChecks.push(refreshId);
            if (error) {
              accessErrors.push(error);
            }
            await updateJWSSession(event, accessConfig);
          }),
          onError: vi.fn(({ error }) => {
            accessErrors.push(error);
          }),
        };

        accessConfig = {
          name: "access_token",
          key: jwsRsaPair,
          maxAge: 10,
          generateId: () => `access-${++accessIdCtr}`,
          hooks: accessHooks,
          jws: {
            signOptions: {
              protectedHeader: {
                typ: "at+jwt", // allow custom `typ`
              },
            },
          },
        };

        router = createRouter({ preemptive: true });
        app = createApp({ debug: true }).use(router);
        request = supertest(toNodeListener(app));

        router.post(
          "/login",
          eventHandler(async (event) => {
            const [refreshSession, accessSession] = await Promise.all([
              useJWESession(event, refreshConfig),
              useJWSSession(event, accessConfig),
            ]);
            await Promise.all([refreshSession.update({}), accessSession.update({})]);

            return {
              access: {
                id: accessSession.id,
                data: accessSession.data,
              },
              refresh: {
                id: refreshSession.id,
                data: refreshSession.data,
              },
            };
          }),
        );

        router.use(
          "/tokens",
          eventHandler(async (event) => {
            const [refreshSession, accessSession] = await Promise.all([
              useJWESession(event, refreshConfig),
              useJWSSession(event, accessConfig),
            ]);

            if (event.method === "POST") {
              const body = await readBody(event);
              await accessSession.update(body);
            }

            return {
              access: {
                id: accessSession.id,
                data: accessSession.data,
              },
              refresh: {
                id: refreshSession.id,
                data: refreshSession.data,
              },
            };
          }),
        );

        router.use(
          "/tokens/clear",
          eventHandler(async (event) => {
            const accessSession = await useJWSSession(event, accessConfig);
            await accessSession.clear();
            return { cleared: true };
          }),
        );
      });

      afterEach(() => {
        vi.useRealTimers();
      });

      it("uses refresh session in onExpire hook before reissuing access token", async () => {
        vi.useFakeTimers();
        vi.setSystemTime(new Date("2024-02-01T00:00:00.000Z"));

        const first = await request.post("/login");
        accessCookie = getCookieValue(first.headers["set-cookie"], accessConfig.name!)!;
        refreshCookie = getCookieValue(first.headers["set-cookie"], refreshConfig.name!)!;

        expect(accessCookie).toBeTruthy();
        expect(refreshCookie).toBeTruthy();
        expect(accessHooks.onRead).toHaveBeenCalledTimes(0);
        expect(refreshHooks.onRead).toHaveBeenCalledTimes(0);

        vi.setSystemTime(new Date("2024-02-01T00:00:20.000Z"));
        const second = await request.get("/tokens").set("Cookie", [accessCookie, refreshCookie]);

        const newCookies = second.headers["set-cookie"] ?? [];
        const refreshedAccessCookie = getCookieValue(newCookies, accessConfig.name!);

        expect(accessHooks.onExpire).toHaveBeenCalledTimes(1);
        expect(refreshChecks).toEqual([second.body.refresh.id]);
        expect(accessErrors.some((error) => String(error).includes("Token has expired"))).toBe(
          true,
        );
        expect(refreshedAccessCookie).toBeTruthy();
        expect(refreshedAccessCookie).not.toEqual(accessCookie);
        expect(second.body.access.id).not.toEqual(first.body.access.id);
        expect(refreshHooks.onRead).toHaveBeenCalledTimes(2);

        vi.useRealTimers();
      });

      it("triggers onUpdate, onError and onClear hooks", async () => {
        const updateResponse = await request.post("/tokens").send({ scope: "read" });

        const updateCookies = updateResponse.headers["set-cookie"] ?? [];
        accessCookie = getCookieValue(updateCookies, accessConfig.name!) ?? accessCookie;
        refreshCookie = getCookieValue(updateCookies, refreshConfig.name!) ?? refreshCookie;

        expect(accessHooks.onUpdate).toHaveBeenCalledTimes(1);
        expect(updateResponse.body.access.data).toMatchObject({
          scope: "read",
        });

        const errorResponse = await request
          .get("/tokens")
          .set("Cookie", [`${accessConfig.name}=invalid`, refreshCookie]);

        const errorCookies = errorResponse.headers["set-cookie"] ?? [];
        accessCookie = getCookieValue(errorCookies, accessConfig.name!) ?? accessCookie;

        expect(accessHooks.onError).toHaveBeenCalledTimes(1);
        expect(accessErrors.some((error) => String(error).includes("Invalid session token"))).toBe(
          true,
        );

        const clearResponse = await request
          .post("/tokens/clear")
          .set("Cookie", [accessCookie, refreshCookie]);
        expect(clearResponse.body).toMatchObject({ cleared: true });
        expect(accessHooks.onClear).toHaveBeenCalledTimes(1);
      });

      it("has correct custom `typ` headers", async () => {
        const first = await request.post("/login");
        const accessHeader = getCookieValue(first.headers["set-cookie"], accessConfig.name!)!
          .split("=")[1]!
          .split(".")[0]!;
        const refreshHeader = getCookieValue(first.headers["set-cookie"], refreshConfig.name!)!
          .split("=")[1]!
          .split(".")[0]!;

        const accessDecoded = JSON.parse(base64UrlDecode(accessHeader));
        const refreshDecoded = JSON.parse(base64UrlDecode(refreshHeader));

        expect(accessDecoded.typ).toBe("at+jwt");
        expect(refreshDecoded.typ).toBe("rt+jwt");
      });

      it("uses onVerifyKeyLookup to find the correct key", async () => {
        const key = jwsLookupA;
        const otherKey = jwsLookupB;

        const lookupSpy = vi.fn((args) => {
          if (args.header.kid === "test-key-1" && args.header.kid === key.publicKey.kid) {
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

        const app = createApp({ debug: true });
        app.use(
          "/",
          eventHandler(async (event) => {
            const session = await useJWSSession(event, config);
            return { session };
          }),
        );
        const request = supertest(toNodeListener(app));

        const result = await request.get("/").set("Cookie", `${config.name}=${token}`);

        expect(lookupSpy).toHaveBeenCalled();
        expect(result.body.session.data).toMatchObject({ foo: "bar" });
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

      const localRouter = createRouter({ preemptive: true });
      const localApp = createApp({ debug: true }).use(localRouter);
      const localRequest = supertest(toNodeListener(localApp));

      localRouter.use(
        "/",
        eventHandler(async (event) => {
          const session = await useJWESession(event, config);
          await session.update({ step: 1 });
          await session.update({ step: 2 });
          return { token: session.token };
        }),
      );

      const res = await localRequest.get("/");

      expect(updates).toHaveLength(2);

      expect(updates[0]!.oldToken).toBeUndefined();
      expect(updates[0]!.token).toBeTypeOf("string");
      expect(updates[0]!.token!.length).toBeGreaterThan(0);
      expect(updates[0]!.id).toBe("1");

      expect(updates[1]!.oldToken).toBe(updates[0]!.token);
      expect(updates[1]!.token).toBeTypeOf("string");
      expect(updates[1]!.token).not.toBe(updates[0]!.token);
      expect(updates[1]!.id).toBe("2");

      expect(res.body.token).toBe(updates[1]!.token);
    });

    it("JWE onUpdate fires even when update() is called with no data (token refresh)", async () => {
      const onUpdate = vi.fn();
      const config: SessionConfigJWE = {
        name: "h3-jwe-hook-no-data",
        key: jweOctKey,
        hooks: { onUpdate },
      };

      const localRouter = createRouter({ preemptive: true });
      const localApp = createApp({ debug: true }).use(localRouter);
      const localRequest = supertest(toNodeListener(localApp));

      localRouter.use(
        "/",
        eventHandler(async (event) => {
          const session = await useJWESession(event, config);
          await session.update(); // no data — pure token refresh
          return {};
        }),
      );

      await localRequest.get("/");
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

      const localRouter = createRouter({ preemptive: true });
      const localApp = createApp({ debug: true }).use(localRouter);
      const localRequest = supertest(toNodeListener(localApp));
      const sessionHeader = `x-${config.name!.toLowerCase()}-session`;

      localRouter.use(
        "/init",
        eventHandler(async (event) => {
          const session = await useJWESession(event, config);
          await session.update({});
          return { token: session.token };
        }),
      );
      localRouter.use(
        "/clear",
        eventHandler(async (event) => {
          const session = await useJWESession(event, config);
          await session.clear();
          return {};
        }),
      );

      const initResult = await localRequest.get("/init");
      const token = initResult.body.token as string;
      await localRequest.get("/clear").set(sessionHeader, token);

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

      const localRouter = createRouter({ preemptive: true });
      const localApp = createApp({ debug: true }).use(localRouter);
      const localRequest = supertest(toNodeListener(localApp));

      localRouter.use(
        "/",
        eventHandler(async (event) => {
          const session = await useJWESession(event, config);
          if (event.method === "POST") await session.update({});
          return { token: session.token };
        }),
      );

      await localRequest.post("/");
      expect(readTokens[0]).toBeUndefined();

      const initRes = await localRequest.post("/");
      const cookie = initRes.headers["set-cookie"]?.[0];
      expect(cookie).toBeDefined();

      const readRes = await localRequest.get("/").set("Cookie", cookie!);
      const lastReadToken = readTokens[readTokens.length - 1];
      expect(lastReadToken).toBeTypeOf("string");
      expect(lastReadToken!.length).toBeGreaterThan(0);
      expect(readRes.body.token).toBe(lastReadToken);

      vi.setSystemTime(new Date("2025-01-01T00:00:05.000Z"));
      await localRequest.get("/").set("Cookie", cookie!);
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

      const localRouter = createRouter({ preemptive: true });
      const localApp = createApp({ debug: true }).use(localRouter);
      const localRequest = supertest(toNodeListener(localApp));

      localRouter.use(
        "/",
        eventHandler(async (event) => {
          const session = await useJWSSession(event, config);
          await session.update({ step: 1 });
          await session.update({ step: 2 });
          return { token: session.token };
        }),
      );

      const res = await localRequest.get("/");

      expect(updates).toHaveLength(2);
      expect(updates[0]!.oldToken).toBeUndefined();
      expect(updates[0]!.token).toBeTypeOf("string");
      expect(updates[0]!.id).toBe("1");
      expect(updates[1]!.oldToken).toBe(updates[0]!.token);
      expect(updates[1]!.token).not.toBe(updates[0]!.token);
      expect(updates[1]!.id).toBe("2");
      expect(res.body.token).toBe(updates[1]!.token);
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

      const localRouter = createRouter({ preemptive: true });
      const localApp = createApp({ debug: true }).use(localRouter);
      const localRequest = supertest(toNodeListener(localApp));
      const sessionHeader = `x-${config.name!.toLowerCase()}-session`;

      localRouter.use(
        "/init",
        eventHandler(async (event) => {
          const session = await useJWSSession(event, config);
          await session.update({});
          return { token: session.token };
        }),
      );
      localRouter.use(
        "/clear",
        eventHandler(async (event) => {
          const session = await useJWSSession(event, config);
          await session.clear();
          return {};
        }),
      );

      const initResult = await localRequest.get("/init");
      const token = initResult.body.token as string;
      await localRequest.get("/clear").set(sessionHeader, token);

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

      const localRouter = createRouter({ preemptive: true });
      const localApp = createApp({ debug: true }).use(localRouter);
      const localRequest = supertest(toNodeListener(localApp));

      let threwInHandler = false;
      localRouter.use(
        "/",
        eventHandler(async (event) => {
          const session = await useJWSSession(event, config);
          try {
            await session.update({ foo: "bar" });
          } catch {
            threwInHandler = true;
          }
          return { id: session.id ?? null, token: session.token ?? null };
        }),
      );

      const res = await localRequest.get("/");

      expect(onError).toHaveBeenCalledOnce();
      expect(onUpdate).not.toHaveBeenCalled();

      expect(onError.mock.calls[0]![0].token).toBeUndefined();

      expect(threwInHandler).toBe(true);
      expect(res.body.id).toBeNull();
      expect(res.body.token).toBeNull();
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

      const localRouter = createRouter({ preemptive: true });
      const localApp = createApp({ debug: true }).use(localRouter);
      const localRequest = supertest(toNodeListener(localApp));

      let threwInHandler = false;
      localRouter.use(
        "/",
        eventHandler(async (event) => {
          const session = await useJWESession(event, config);
          try {
            await session.update({ foo: "bar" });
          } catch {
            threwInHandler = true;
          }
          return { id: session.id ?? null, token: session.token ?? null };
        }),
      );

      const res = await localRequest.get("/");

      expect(onError).toHaveBeenCalledOnce();
      expect(onUpdate).not.toHaveBeenCalled();
      expect(onError.mock.calls[0]![0].token).toBeUndefined();
      expect(threwInHandler).toBe(true);
      expect(res.body.id).toBeNull();
      expect(res.body.token).toBeNull();
    });
  });

  describe("key variants", () => {
    it("JWE session works with symmetric JWK key (oct)", async () => {
      const config: SessionConfigJWE = {
        name: "h3-jwe-symjwk",
        key: jweOctKey,
      };

      const localRouter = createRouter({ preemptive: true });
      const localApp = createApp({ debug: true }).use(localRouter);
      const localRequest = supertest(toNodeListener(localApp));

      localRouter.use(
        "/init",
        eventHandler(async (event) => {
          const session = await useJWESession(event, config);
          await session.update({ hello: "world" });
          return { session };
        }),
      );

      localRouter.use(
        "/",
        eventHandler(async (event) => {
          const session = await useJWESession(event, config);
          return { session };
        }),
      );

      const initResult = await localRequest.get("/init");
      const cookie = initResult.headers["set-cookie"]![0]!;
      expect(cookie).toContain("h3-jwe-symjwk=");

      const readResult = await localRequest.get("/").set("Cookie", cookie);
      expect(readResult.body).toMatchObject({
        session: { data: { hello: "world" } },
      });
    });

    it("JWE session works with asymmetric key pair (privateKey/publicKey)", async () => {
      const config: SessionConfigJWE = {
        name: "h3-jwe-keypair",
        key: { privateKey: jweOaepPair.privateKey, publicKey: jweOaepPair.publicKey },
      };

      const localRouter = createRouter({ preemptive: true });
      const localApp = createApp({ debug: true }).use(localRouter);
      const localRequest = supertest(toNodeListener(localApp));

      localRouter.use(
        "/init",
        eventHandler(async (event) => {
          const session = await useJWESession(event, config);
          await session.update({ secret: "data" });
          return { session };
        }),
      );

      localRouter.use(
        "/",
        eventHandler(async (event) => {
          const session = await useJWESession(event, config);
          return { session };
        }),
      );

      const initResult = await localRequest.get("/init");
      const cookie = initResult.headers["set-cookie"]![0]!;
      expect(cookie).toContain("h3-jwe-keypair=");

      const readResult = await localRequest.get("/").set("Cookie", cookie);
      expect(readResult.body).toMatchObject({
        session: { data: { secret: "data" } },
      });
    });

    it("JWS session works with symmetric JWK key", async () => {
      const config: SessionConfigJWS = {
        name: "h3-jws-symjwk",
        key: jwsOctKey, // isSymmetricJWK branch in getVerifyKey
      };

      const localRouter = createRouter({ preemptive: true });
      const localApp = createApp({ debug: true }).use(localRouter);
      const localRequest = supertest(toNodeListener(localApp));

      localRouter.use(
        "/init",
        eventHandler(async (event) => {
          const session = await useJWSSession(event, config);
          await session.update({ foo: "bar" });
          return { session };
        }),
      );

      localRouter.use(
        "/",
        eventHandler(async (event) => {
          const session = await useJWSSession(event, config);
          return { session };
        }),
      );

      const initResult = await localRequest.get("/init");
      const cookie = initResult.headers["set-cookie"]![0]!;

      const readResult = await localRequest.get("/").set("Cookie", cookie);
      expect(readResult.body).toMatchObject({
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

      const localRouter = createRouter({ preemptive: true });
      const localApp = createApp({ debug: true }).use(localRouter);
      const localRequest = supertest(toNodeListener(localApp));

      localRouter.use(
        "/init",
        eventHandler(async (event) => {
          const session = await useJWSSession(event, config);
          await session.update({ foo: "bar" });
          return { session };
        }),
      );

      localRouter.use(
        "/",
        eventHandler(async (event) => {
          const session = await useJWSSession(event, config);
          return { session };
        }),
      );

      const initResult = await localRequest.get("/init");
      const cookie = initResult.headers["set-cookie"]![0]!;

      const readResult = await localRequest.get("/").set("Cookie", cookie);
      expect(readResult.body).toMatchObject({
        session: { data: { foo: "bar" } },
      });
    });
  });
});
