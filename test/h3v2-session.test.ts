import { describe, it, expect, beforeEach } from "vitest";
import { H3 } from "h3v2";
import {
  type SessionConfigJWE,
  type SessionConfigJWS,
  useJWESession,
  useJWSSession,
  generateJWK,
} from "../src/adapters/h3v2";

describe("adapter h3 v2", () => {
  let app: H3;

  describe("jwe session", () => {
    let cookie = "";
    let sessionIdCtr = 0;
    const sessionConfig: SessionConfigJWE = {
      name: "h3-jwe-test",
      key: "jwe-secret",
      generateId: () => String(++sessionIdCtr),
    };

    beforeEach(() => {
      app = new H3({ debug: true });

      app.all("/", async (event) => {
        const session = await useJWESession(event, sessionConfig);
        if (event.req.method === "POST") {
          await session.update(await event.req.json());
        }
        return { session };
      });
    });

    it("initiates session", async () => {
      const result = await app.request("/");
      expect(result.headers.getSetCookie()).toHaveLength(1);
      cookie = result.headers.getSetCookie()[0]!;
      expect(await result.json()).toMatchObject({
        session: { id: "1", data: {} },
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
        session: { id: "1", data: { foo: "bar" } },
      });

      const result2 = await app.request("/", {
        headers: {
          Cookie: cookie,
        },
      });
      expect(await result2.json()).toMatchObject({
        session: { id: "1", data: { foo: "bar" } },
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
        sessions: [1, 2, 3].map(() => ({ id: "1", data: { foo: "bar" } })),
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
      app = new H3({ debug: true });

      app.all("/", async (event) => {
        const session = await useJWSSession(event, sessionConfig);
        if (event.req.method === "POST") {
          await session.update(await event.req.json());
        }
        return { session };
      });
    });

    it("initiates session", async () => {
      const result = await app.request("/");
      expect(result.headers.getSetCookie()).toHaveLength(1);
      cookie = result.headers.getSetCookie()[0]!;
      expect(await result.json()).toMatchObject({
        session: { id: "1", data: {} },
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
        session: { id: "1", data: { foo: "bar" } },
      });

      const result2 = await app.request("/", {
        headers: {
          Cookie: cookie,
        },
      });
      expect(await result2.json()).toMatchObject({
        session: { id: "1", data: { foo: "bar" } },
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
        sessions: [1, 2, 3].map(() => ({ id: "1", data: { foo: "bar" } })),
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
  });
});
