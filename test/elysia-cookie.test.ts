import { describe, it, expect } from "vitest";
import { Elysia } from "elysia";
import {
  readChunkedCookie,
  writeChunkedCookie,
  removeChunkedCookie,
  type ChunkableCookieJar,
  type CookieAttributes,
} from "../src/adapters/elysia/_cookie";

// ChunkableCookieJar is used by the mock-jar unit tests below; the real-Elysia
// integration block passes ctx.cookie directly to prove structural assignability.

interface MockEntry {
  value: unknown;
  lastWrite?: CookieAttributes & { value: string };
}

function makeJar(initial: Record<string, string> = {}) {
  const store = new Map<string, MockEntry>();
  for (const [k, v] of Object.entries(initial)) store.set(k, { value: v });

  const jar = new Proxy({} as ChunkableCookieJar, {
    get(_t, prop: string) {
      return {
        get value() {
          return store.get(prop)?.value;
        },
        set(config: CookieAttributes & { value: string }) {
          store.set(prop, { value: config.value, lastWrite: config });
        },
      };
    },
  });

  return { jar, store };
}

describe("elysia chunked cookies — unit", () => {
  it("writes a short value as a single plain cookie (no marker, no chunks)", () => {
    const { jar, store } = makeJar();
    writeChunkedCookie(jar, "sess", "hello", { chunkMaxLength: 10, path: "/" });

    expect(store.get("sess")?.value).toBe("hello");
    expect(store.has("sess.1")).toBe(false);
    expect(store.get("sess")?.lastWrite?.path).toBe("/");
  });

  it("treats a value of exactly chunkMaxLength as one chunk (plain)", () => {
    const { jar, store } = makeJar();
    writeChunkedCookie(jar, "sess", "0123456789", { chunkMaxLength: 10 });

    expect(store.get("sess")?.value).toBe("0123456789");
    expect(store.has("sess.1")).toBe(false);
  });

  it("splits an over-length value into marker + 1-indexed chunks", () => {
    const { jar, store } = makeJar();
    writeChunkedCookie(jar, "sess", "0123456789AB", { chunkMaxLength: 10 });

    expect(store.get("sess")?.value).toBe("__chunked__2");
    expect(store.get("sess.1")?.value).toBe("0123456789");
    expect(store.get("sess.2")?.value).toBe("AB");
  });

  it("round-trips: read reassembles the chunks back into the original value", () => {
    const value = "x".repeat(25);
    const { jar } = makeJar();
    writeChunkedCookie(jar, "sess", value, { chunkMaxLength: 10 });

    expect(readChunkedCookie(jar, "sess")).toBe(value);
  });

  it("reads a plain (unchunked) cookie directly", () => {
    const { jar } = makeJar({ sess: "plain-token" });
    expect(readChunkedCookie(jar, "sess")).toBe("plain-token");
  });

  it("returns undefined when the cookie is absent", () => {
    const { jar } = makeJar();
    expect(readChunkedCookie(jar, "sess")).toBeUndefined();
  });

  it("returns undefined when a declared chunk is missing", () => {
    const { jar } = makeJar({ sess: "__chunked__3", "sess.1": "a", "sess.2": "b" });
    expect(readChunkedCookie(jar, "sess")).toBeUndefined();
  });

  it("returns undefined for an out-of-range chunk count", () => {
    const { jar } = makeJar({ sess: "__chunked__0" });
    expect(readChunkedCookie(jar, "sess")).toBeUndefined();
  });

  it("treats a marker with a non-digit suffix as malformed (not chunked)", () => {
    const { jar } = makeJar({ sess: "__chunked__3x", "sess.1": "a" });
    expect(readChunkedCookie(jar, "sess")).toBeUndefined();
  });

  it("expires surplus chunks when re-writing with fewer (chunked → plain)", () => {
    const { jar, store } = makeJar();
    writeChunkedCookie(jar, "sess", "x".repeat(25), { chunkMaxLength: 10 }); // 3 chunks
    writeChunkedCookie(jar, "sess", "short", { chunkMaxLength: 10 }); // plain

    expect(store.get("sess")?.value).toBe("short");
    expect(store.get("sess.1")?.lastWrite?.maxAge).toBe(0);
    expect(store.get("sess.2")?.lastWrite?.maxAge).toBe(0);
    expect(store.get("sess.3")?.lastWrite?.maxAge).toBe(0);
  });

  it("expires surplus chunks when re-writing with fewer (more → fewer chunks)", () => {
    const { jar, store } = makeJar();
    writeChunkedCookie(jar, "sess", "x".repeat(50), { chunkMaxLength: 10 }); // 5 chunks
    writeChunkedCookie(jar, "sess", "y".repeat(20), { chunkMaxLength: 10 }); // 2 chunks

    expect(store.get("sess")?.value).toBe("__chunked__2");
    expect(store.get("sess.1")?.value).toBe("y".repeat(10));
    expect(store.get("sess.2")?.value).toBe("y".repeat(10));
    expect(store.get("sess.3")?.lastWrite?.maxAge).toBe(0);
    expect(store.get("sess.4")?.lastWrite?.maxAge).toBe(0);
    expect(store.get("sess.5")?.lastWrite?.maxAge).toBe(0);
  });

  it("removes a chunked cookie and all its parts", () => {
    const { jar, store } = makeJar({
      sess: "__chunked__2",
      "sess.1": "a",
      "sess.2": "b",
    });
    removeChunkedCookie(jar, "sess", { path: "/" });

    expect(store.get("sess")?.lastWrite?.maxAge).toBe(0);
    expect(store.get("sess.1")?.lastWrite?.maxAge).toBe(0);
    expect(store.get("sess.2")?.lastWrite?.maxAge).toBe(0);
    expect(store.get("sess")?.lastWrite?.path).toBe("/");
  });

  it("removing a plain cookie only expires the base name", () => {
    const { jar, store } = makeJar({ sess: "plain" });
    removeChunkedCookie(jar, "sess");

    expect(store.get("sess")?.lastWrite?.maxAge).toBe(0);
    expect(store.has("sess.1")).toBe(false);
  });

  it("throws when a value would exceed the 100-chunk limit", () => {
    const { jar } = makeJar();
    expect(() => writeChunkedCookie(jar, "sess", "x".repeat(101), { chunkMaxLength: 1 })).toThrow(
      /exceeding the limit of 100/,
    );
  });
});

describe("elysia chunked cookies — real Elysia jar integration", () => {
  const app = new Elysia()
    .get("/set", ({ cookie }) => {
      writeChunkedCookie(cookie, "sess", "x".repeat(25), {
        chunkMaxLength: 10,
        path: "/",
        httpOnly: true,
      });
      return "set";
    })
    .get("/read", ({ cookie }) => readChunkedCookie(cookie, "sess") ?? "MISSING")
    .get("/clear", ({ cookie }) => {
      removeChunkedCookie(cookie, "sess", { path: "/" });
      return "cleared";
    });

  it("emits marker + per-chunk Set-Cookie through the real jar", async () => {
    const res = await app.handle(new Request("http://localhost/set"));
    const setCookies = res.headers.getSetCookie();

    expect(setCookies.some((c) => c.startsWith("sess=__chunked__3"))).toBe(true);
    expect(setCookies.some((c) => c.startsWith("sess.1="))).toBe(true);
    expect(setCookies.some((c) => c.startsWith("sess.3="))).toBe(true);
    expect(setCookies.every((c) => /HttpOnly/i.test(c))).toBe(true);
  });

  it("reassembles incoming chunked cookies", async () => {
    const value = "x".repeat(25);
    const res = await app.handle(
      new Request("http://localhost/read", {
        headers: {
          cookie: `sess=__chunked__3; sess.1=${value.slice(0, 10)}; sess.2=${value.slice(10, 20)}; sess.3=${value.slice(20)}`,
        },
      }),
    );
    expect(await res.text()).toBe(value);
  });

  it("expires all chunks on clear", async () => {
    const res = await app.handle(
      new Request("http://localhost/clear", {
        headers: { cookie: "sess=__chunked__2; sess.1=aaa; sess.2=bbb" },
      }),
    );
    const cleared = res.headers.getSetCookie();
    expect(cleared.length).toBeGreaterThanOrEqual(3);
    expect(cleared.every((c) => /Max-Age=0|Expires=Thu, 01 Jan 1970/i.test(c))).toBe(true);
  });
});
