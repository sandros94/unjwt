import supertest from "supertest";
import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import {
  type App,
  createApp,
  createRouter,
  toNodeListener,
  eventHandler,
  readBody,
} from "h3";
import {
  type SessionConfigJWE,
  type SessionConfigJWS,
  useJWESession,
  useJWSSession,
  updateJWESession,
  generateJWK,
} from "../src/adapters/h3";

describe("adapter h3", () => {
  let app: App;
  let router: ReturnType<typeof createRouter>;
  let request: ReturnType<typeof supertest>;

  describe("jwe session", () => {
    let cookie = "";
    let sessionIdCtr = 0;
    const sessionConfig: SessionConfigJWE = {
      name: "h3-jwe-test",
      secret: "jwe-secret",
      generateId: () => String(++sessionIdCtr),
    };

    beforeEach(() => {
      router = createRouter({ preemptive: true });
      app = createApp({ debug: true }).use(router);
      request = supertest(toNodeListener(app));

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
    });

    it("initiates session", async () => {
      const result = await request.get("/");
      expect(result.headers["set-cookie"]).toHaveLength(1);
      cookie = result.headers["set-cookie"]![0]!;
      expect(result.body).toMatchObject({
        session: { id: "1", data: {} },
      });
    });

    it("gets same session back", async () => {
      const result = await request.get("/").set("Cookie", cookie);
      expect(result.body).toMatchObject({
        session: { id: "1", data: {} },
      });
    });

    it("set session data", async () => {
      const result = await request
        .post("/")
        .set("Cookie", cookie)
        .send({ foo: "bar" });
      cookie = result.headers["set-cookie"]![0]!;
      expect(result.body).toMatchObject({
        session: { id: "1", data: { foo: "bar" } },
      });

      const result2 = await request.get("/").set("Cookie", cookie);
      expect(result2.body).toMatchObject({
        session: { id: "1", data: { foo: "bar" } },
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
        sessions: [1, 2, 3].map(() => ({ id: "1", data: { foo: "bar" } })),
      });
    });
  });

  describe("jws session", async () => {
    let cookie = "";
    let sessionIdCtr = 0;
    const keys = await generateJWK("RS256");
    const sessionConfig: SessionConfigJWS = {
      name: "h3-jws-test",
      key: keys,
      generateId: () => String(++sessionIdCtr),
    };

    beforeEach(() => {
      router = createRouter({ preemptive: true });
      app = createApp({ debug: true }).use(router);
      request = supertest(toNodeListener(app));

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
    });

    it("initiates session", async () => {
      const result = await request.get("/");
      expect(result.headers["set-cookie"]).toHaveLength(1);
      cookie = result.headers["set-cookie"]![0]!;
      expect(result.body).toMatchObject({
        session: { id: "1", data: {} },
      });
    });

    it("gets same session back", async () => {
      const result = await request.get("/").set("Cookie", cookie);
      expect(result.body).toMatchObject({
        session: { id: "1", data: {} },
      });
    });

    it("set session data", async () => {
      const result = await request
        .post("/")
        .set("Cookie", cookie)
        .send({ foo: "bar" });
      cookie = result.headers["set-cookie"]![0]!;
      expect(result.body).toMatchObject({
        session: { id: "1", data: { foo: "bar" } },
      });

      const result2 = await request.get("/").set("Cookie", cookie);
      expect(result2.body).toMatchObject({
        session: { id: "1", data: { foo: "bar" } },
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
        sessions: [1, 2, 3].map(() => ({ id: "1", data: { foo: "bar" } })),
      });
    });
  });

  describe("hooks", () => {
    const getCookieValue = (
      cookies: string | string[] | undefined,
      name: string,
    ) => {
      const list = Array.isArray(cookies) ? cookies : cookies ? [cookies] : [];
      return list
        .find((cookie) => cookie.startsWith(`${name}=`))
        ?.split(";")[0];
    };

    describe("jwe session hooks", () => {
      let cookie = "";
      let sessionIdCtr = 0;
      let sessionConfig: SessionConfigJWE;
      let hooks: {
        onRead: ReturnType<typeof vi.fn>;
        onUpdate: ReturnType<typeof vi.fn>;
        onClear: ReturnType<typeof vi.fn>;
        onExpire: ReturnType<typeof vi.fn>;
        onError: ReturnType<typeof vi.fn>;
      };
      const errors: unknown[] = [];

      beforeEach(() => {
        vi.useRealTimers();
        cookie = "";
        sessionIdCtr = 0;
        errors.length = 0;

        let configRef: SessionConfigJWE | null = null;

        hooks = {
          onRead: vi.fn(async (session, event) => {
            if (session.expiresAt !== undefined) {
              const timeLeft = session.expiresAt - session.createdAt;
              // if time left is less than half of maxAge, refresh
              if (timeLeft < configRef!.maxAge! / 2) {
                await updateJWESession(event, configRef!);
              }
            }
          }),
          onUpdate: vi.fn(),
          onClear: vi.fn(),
          onExpire: vi.fn(),
          onError: vi.fn((_event, error) => {
            errors.push(error);
          }),
        };

        sessionConfig = {
          name: "h3-jwe-hooks",
          secret: "jwe-hook-secret",
          maxAge: 2,
          generateId: () => String(++sessionIdCtr),
          hooks,
        };
        configRef = sessionConfig;

        router = createRouter({ preemptive: true });
        app = createApp({ debug: true }).use(router);
        request = supertest(toNodeListener(app));

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
        cookie = getCookieValue(
          first.headers["set-cookie"],
          sessionConfig.name!,
        )!;
        const firstToken = cookie;

        expect(hooks.onRead).toHaveBeenCalledTimes(1);
        expect(first.body.session.id).toBe("1");
        const firstExpiresAt = first.body.session.expiresAt;
        expect(firstExpiresAt).toBeDefined();

        const nearExpiry = new Date("2024-01-01T00:00:01.600Z");
        vi.setSystemTime(nearExpiry);
        expect(Date.now()).toBe(nearExpiry.getTime());
        const second = await request.get("/").set("Cookie", cookie);
        const nextCookie = getCookieValue(
          second.headers["set-cookie"],
          sessionConfig.name!,
        )!;

        expect(nextCookie).toBeTruthy();
        expect(nextCookie).not.toEqual(firstToken);
        expect(hooks.onRead).toHaveBeenCalledTimes(2);
        expect(second.body.session.id).toBe("2");
        const secondExpiresAt = second.body.session.expiresAt;
        expect(secondExpiresAt).toBeDefined();
        expect(secondExpiresAt).toBeGreaterThan(firstExpiresAt);

        vi.useRealTimers();
      });

      it("triggers onUpdate and onClear hooks", async () => {
        const first = await request.get("/");
        cookie = getCookieValue(
          first.headers["set-cookie"],
          sessionConfig.name!,
        )!;

        const updateResponse = await request
          .post("/")
          .set("Cookie", cookie)
          .send({ foo: "bar" });
        cookie =
          getCookieValue(
            updateResponse.headers["set-cookie"],
            sessionConfig.name!,
          ) ?? cookie;

        expect(hooks.onUpdate).toHaveBeenCalledTimes(1);
        expect(updateResponse.body.session.data).toMatchObject({ foo: "bar" });

        const clearResponse = await request
          .post("/clear")
          .set("Cookie", cookie);
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
    });

    describe("jws session hooks", async () => {
      let accessCookie = "";
      let refreshCookie = "";
      let accessConfig: SessionConfigJWS;
      let refreshConfig: SessionConfigJWE;
      let accessHooks: {
        onRead: ReturnType<typeof vi.fn>;
        onUpdate: ReturnType<typeof vi.fn>;
        onClear: ReturnType<typeof vi.fn>;
        onExpire: ReturnType<typeof vi.fn>;
        onError: ReturnType<typeof vi.fn>;
      };
      let refreshHooks: {
        onRead: ReturnType<typeof vi.fn>;
        onUpdate: ReturnType<typeof vi.fn>;
        onClear: ReturnType<typeof vi.fn>;
        onExpire: ReturnType<typeof vi.fn>;
        onError: ReturnType<typeof vi.fn>;
      };
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

        const keys = await generateJWK("RS256");

        refreshHooks = {
          onRead: vi.fn(),
          onUpdate: vi.fn(),
          onClear: vi.fn(),
          onExpire: vi.fn(),
          onError: vi.fn(),
        };

        refreshConfig = {
          name: "h3-jwe-refresh",
          secret: "jwe-refresh-secret",
          maxAge: 30,
          generateId: () => `refresh-${++refreshIdCtr}`,
          hooks: refreshHooks,
        };

        accessHooks = {
          onRead: vi.fn(),
          onUpdate: vi.fn(),
          onClear: vi.fn(),
          onExpire: vi.fn(async (event, error) => {
            const refreshSession = await useJWESession(event, refreshConfig);
            const refreshId = refreshSession.id;
            if (!refreshId) {
              throw new Error("refresh session missing id");
            }
            refreshChecks.push(refreshId);
            if (error) {
              accessErrors.push(error);
            }
          }),
          onError: vi.fn((_event, error) => {
            accessErrors.push(error);
          }),
        };

        accessConfig = {
          name: "h3-jws-hooks",
          key: keys,
          maxAge: 1,
          generateId: () => `access-${++accessIdCtr}`,
          hooks: accessHooks,
        };

        router = createRouter({ preemptive: true });
        app = createApp({ debug: true }).use(router);
        request = supertest(toNodeListener(app));

        router.use(
          "/tokens",
          eventHandler(async (event) => {
            const refreshSession = await useJWESession(event, refreshConfig);
            const accessSession = await useJWSSession(event, accessConfig);
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

        const first = await request.get("/tokens");
        accessCookie = getCookieValue(
          first.headers["set-cookie"],
          accessConfig.name!,
        )!;
        refreshCookie = getCookieValue(
          first.headers["set-cookie"],
          refreshConfig.name!,
        )!;

        expect(accessCookie).toBeTruthy();
        expect(refreshCookie).toBeTruthy();
        expect(accessHooks.onRead).toHaveBeenCalledTimes(1);
        expect(refreshHooks.onRead).toHaveBeenCalledTimes(1);

        vi.setSystemTime(new Date("2024-02-01T00:00:02.000Z"));
        const second = await request
          .get("/tokens")
          .set("Cookie", [accessCookie, refreshCookie]);

        const newCookies = second.headers["set-cookie"] ?? [];
        const refreshedAccessCookie = getCookieValue(
          newCookies,
          accessConfig.name!,
        );

        expect(accessHooks.onExpire).toHaveBeenCalledTimes(1);
        expect(refreshChecks).toEqual([second.body.refresh.id]);
        expect(
          accessErrors.some((error) =>
            String(error).includes("Token has expired"),
          ),
        ).toBe(true);
        expect(refreshedAccessCookie).toBeTruthy();
        expect(refreshedAccessCookie).not.toEqual(accessCookie);
        expect(second.body.access.id).not.toEqual(first.body.access.id);
        expect(refreshHooks.onRead).toHaveBeenCalledTimes(3);

        vi.useRealTimers();
      });

      it("triggers onUpdate, onError and onClear hooks", async () => {
        const first = await request.get("/tokens");
        accessCookie = getCookieValue(
          first.headers["set-cookie"],
          accessConfig.name!,
        )!;
        refreshCookie = getCookieValue(
          first.headers["set-cookie"],
          refreshConfig.name!,
        )!;

        const updateResponse = await request
          .post("/tokens")
          .set("Cookie", [accessCookie, refreshCookie])
          .send({ scope: "read" });

        const updateCookies = updateResponse.headers["set-cookie"] ?? [];
        accessCookie =
          getCookieValue(updateCookies, accessConfig.name!) ?? accessCookie;

        // calls for `onUpdate` inside `updateJWESession` are not counted
        expect(accessHooks.onUpdate).toHaveBeenCalledTimes(1);
        expect(updateResponse.body.access.data).toMatchObject({
          scope: "read",
        });

        const errorResponse = await request
          .get("/tokens")
          .set("Cookie", [`${accessConfig.name}=invalid`, refreshCookie]);

        const errorCookies = errorResponse.headers["set-cookie"] ?? [];
        accessCookie =
          getCookieValue(errorCookies, accessConfig.name!) ?? accessCookie;

        expect(accessHooks.onError).toHaveBeenCalledTimes(1);
        expect(
          accessErrors.some((error) =>
            String(error).includes("Invalid session token"),
          ),
        ).toBe(true);

        const clearResponse = await request
          .post("/tokens/clear")
          .set("Cookie", accessCookie);
        expect(clearResponse.body).toMatchObject({ cleared: true });
        expect(accessHooks.onClear).toHaveBeenCalledTimes(1);
      });
    });
  });
});
