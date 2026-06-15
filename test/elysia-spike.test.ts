// THROWAWAY Phase 0 spike — validates the .agents/vision/elysia-adapter.md claims
// against a real Elysia instance under vitest+Node (no Bun). Delete before implementation.
import { describe, it, expect } from "vitest";
import { Elysia } from "elysia";

describe("elysia spike — vision claims", () => {
  it("claim 1: imports under Node and app.handle(Request) returns a Response", async () => {
    const app = new Elysia().get("/", () => "ok");
    const res = await app.handle(new Request("http://localhost/"));
    expect(res).toBeInstanceOf(Response);
    expect(await res.text()).toBe("ok");
  });

  it("claim 2: the cookie jar is populated from the incoming request at resolve stage", async () => {
    let seenAtResolve: string | undefined;
    const app = new Elysia()
      .resolve(({ cookie }) => {
        // dynamic-key cookie reads are typed `unknown` (only schema-declared names get `string`)
        seenAtResolve = cookie["in"]?.value as string | undefined;
        return {};
      })
      .get("/", ({ cookie }) => cookie["in"]?.value ?? "MISSING");

    const res = await app.handle(
      new Request("http://localhost/", { headers: { cookie: "in=hello" } }),
    );
    expect(await res.text()).toBe("hello");
    expect(seenAtResolve).toBe("hello"); // available already at resolve, not just in handler
  });

  it("claim 3: a scoped .resolve() in a plugin propagates value AND type to the consumer's routes", async () => {
    const plugin = new Elysia({ name: "spike.session" }).resolve({ as: "scoped" }, () => ({
      session: { id: "abc", data: { n: 1 } },
    }));

    const app = new Elysia()
      .use(plugin)
      // If `session` were not propagated (or typed `any`), this would fail typecheck/runtime:
      .get("/me", ({ session }) => `${session.id}:${session.data.n}`);

    const res = await app.handle(new Request("http://localhost/me"));
    expect(await res.text()).toBe("abc:1");
  });

  it("claim 4: chunked cookies round-trip (write name.0/.1, reassemble on read, remove clears)", async () => {
    const app = new Elysia()
      .get("/set", ({ cookie }) => {
        cookie["sess.0"].value = "AAA";
        cookie["sess.1"].value = "BBB";
        return "set";
      })
      .get("/read", ({ cookie }) => {
        const parts: string[] = [];
        for (let i = 0; cookie[`sess.${i}`]?.value !== undefined; i++) {
          parts.push(cookie[`sess.${i}`].value as string);
        }
        return parts.join("");
      })
      .get("/clear", ({ cookie }) => {
        for (let i = 0; cookie[`sess.${i}`]?.value !== undefined; i++) {
          cookie[`sess.${i}`].remove();
        }
        return "cleared";
      });

    // write path emits Set-Cookie for each chunk
    const setRes = await app.handle(new Request("http://localhost/set"));
    const setCookies = setRes.headers.getSetCookie();
    expect(setCookies.some((c) => c.startsWith("sess.0=AAA"))).toBe(true);
    expect(setCookies.some((c) => c.startsWith("sess.1=BBB"))).toBe(true);

    // read path reassembles from incoming chunked cookies
    const readRes = await app.handle(
      new Request("http://localhost/read", { headers: { cookie: "sess.0=AAA; sess.1=BBB" } }),
    );
    expect(await readRes.text()).toBe("AAABBB");

    // clear path expires each chunk
    const clearRes = await app.handle(
      new Request("http://localhost/clear", { headers: { cookie: "sess.0=AAA; sess.1=BBB" } }),
    );
    const cleared = clearRes.headers.getSetCookie();
    expect(cleared.length).toBeGreaterThan(0);
    expect(cleared.every((c) => /Expires=Thu, 01 Jan 1970|Max-Age=0/i.test(c))).toBe(true);
  });

  it("claim 5: a guard macro can short-circuit with status(401)", async () => {
    const plugin = new Elysia({ name: "spike.guard" }).macro({
      requireSession: {
        resolve({ cookie, status }) {
          if (!cookie["session"]?.value) return status(401, "Unauthorized");
          return { ok: true as const };
        },
      },
    });

    const app = new Elysia()
      .use(plugin)
      .get("/open", () => "open")
      .guard({ requireSession: true }, (a) => a.get("/gated", () => "secret"));

    const denied = await app.handle(new Request("http://localhost/gated"));
    expect(denied.status).toBe(401);

    const allowed = await app.handle(
      new Request("http://localhost/gated", { headers: { cookie: "session=x" } }),
    );
    expect(allowed.status).toBe(200);
    expect(await allowed.text()).toBe("secret");
  });

  it("claim 6: Set-Cookie is auto-emitted only when a value changes", async () => {
    const app = new Elysia()
      .get("/touch-no-write", ({ cookie }) => {
        void cookie["x"]?.value; // read only
        return "r";
      })
      .get("/write", ({ cookie }) => {
        cookie["x"].value = "1";
        return "w";
      });

    const noWrite = await app.handle(new Request("http://localhost/touch-no-write"));
    expect(noWrite.headers.getSetCookie().length).toBe(0);

    const write = await app.handle(new Request("http://localhost/write"));
    expect(write.headers.getSetCookie().some((c) => c.startsWith("x=1"))).toBe(true);
  });
});
