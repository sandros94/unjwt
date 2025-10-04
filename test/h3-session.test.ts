import supertest from "supertest";
import { describe, it, expect, beforeEach } from "vitest";
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
});
