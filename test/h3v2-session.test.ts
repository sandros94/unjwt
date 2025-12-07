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

describe("adapter h3 v2", () => {
  let app: H3;

  describe("jwe session", () => {
    let cookie = "";
    let sessionIdCtr = 0;
    const sessionConfig = {
      name: "h3-jwe-test",
      key: "jwe-secret",
      generateId: () => String(++sessionIdCtr),
      sessionHeader: "Authorization",
    } as const satisfies SessionConfigJWE;

    beforeEach(() => {
      app = new H3({ debug: true });

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
      const result = await app.request("/");
      expect(result.headers.getSetCookie()).toHaveLength(1);
      cookie = result.headers.getSetCookie()[0]!;
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
      const token = Array.from({ length: 5000 /* ~4k + one more */ })
        .fill("x")
        .join("");
      const res = await app.request("/", {
        method: "POST",
        headers: { Cookie: cookie },
        body: JSON.stringify({ token }),
      });

      const cookies = res.headers.getSetCookie();
      const cookieNames = cookies.map((c) => c.split("=")[0]);
      expect(cookieNames.length).toBe(3 /* head + 2 */);
      expect(cookieNames).toMatchObject([
        "h3-jwe-test",
        "h3-jwe-test.1",
        "h3-jwe-test.2",
      ]);

      const body = await res.json();
      expect(body.session.data.token).toBe(token);
    });

    it("accepts token from authorization header", async () => {
      // Lets create a new sealed session token first
      const sealed = await encrypt(
        {
          jti: "999",
          iat: Math.floor(Date.now() / 1000),
          hello: "world",
        },
        sessionConfig.key,
      );

      // Now request with authorization header
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
  });

  describe("jws session", async () => {
    let cookie = "";
    let sessionIdCtr = 0;
    const keys = await generateJWK("RS256");
    const sessionConfig = {
      name: "h3-jws-test",
      key: keys,
      generateId: () => String(++sessionIdCtr),
      sessionHeader: "Authorization",
    } as const satisfies SessionConfigJWS;

    beforeEach(() => {
      app = new H3({ debug: true });

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
      const result = await app.request("/");
      expect(result.headers.getSetCookie()).toHaveLength(1);
      cookie = result.headers.getSetCookie()[0]!;
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
      const token = Array.from({ length: 5000 /* ~4k + one more */ })
        .fill("x")
        .join("");
      const res = await app.request("/", {
        method: "POST",
        headers: { Cookie: cookie },
        body: JSON.stringify({ token }),
      });

      const cookies = res.headers.getSetCookie();
      const cookieNames = cookies.map((c) => c.split("=")[0]);
      expect(cookieNames.length).toBe(3 /* head + 2 */);
      expect(cookieNames).toMatchObject([
        "h3-jws-test",
        "h3-jws-test.1",
        "h3-jws-test.2",
      ]);

      const body = await res.json();
      expect(body.session.data.token).toBe(token);
    });

    it("accepts token from authorization header", async () => {
      // Lets create a new signed session token first
      const signed = await sign(
        {
          jti: "999",
          iat: Math.floor(Date.now() / 1000),
          hello: "world",
        },
        sessionConfig.key.privateKey,
      );

      // Now request with authorization header
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
  });

  describe("hooks", () => {
    describe("jwe session hooks", () => {
      it("uses onUnsealKeyLookup to find the correct key", async () => {
        const [key, otherKey] = await Promise.all([
          generateJWK("A256GCMKW", {
            kid: "test-key-1",
          }),
          generateJWK("A256GCMKW", {
            kid: "test-key-2",
          }),
        ]);

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

        // Manually create a token with the correct key
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
        const [key, otherKey] = await Promise.all([
          generateJWK("RS256", {
            kid: "test-key-1",
          }),
          generateJWK("RS256", {
            kid: "test-key-2",
          }),
        ]);

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

        // Manually create a token with the correct key
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
});
