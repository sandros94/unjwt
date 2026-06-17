import { describe, it, expect, beforeAll } from "vitest";
import { Elysia, t } from "elysia";
import { generateJWK } from "../src/core/jwk";
import type { JWK_oct, JWK_HMAC, JWEEncryptJWK } from "../src/core/types";
import { createJWSSession, jwsSession } from "../src/adapters/elysia/session/jws";
import { createJWESession, jweSession } from "../src/adapters/elysia/session/jwe";

function cookieHeader(setCookies: string[]): string {
  return setCookies
    .filter((c) => !/Max-Age=0|Expires=Thu, 01 Jan 1970/i.test(c))
    .map((c) => c.split(";")[0])
    .join("; ");
}

function post(path: string, body: unknown, headers: Record<string, string> = {}): Request {
  return new Request(`http://localhost${path}`, {
    method: "POST",
    headers: { "content-type": "application/json", ...headers },
    body: JSON.stringify(body),
  });
}

describe("elysia session — running server via app.handle", () => {
  let jwsKey: JWK_oct<JWK_HMAC>;
  let jweKey: JWEEncryptJWK;

  beforeAll(async () => {
    jwsKey = await generateJWK("HS256");
    jweKey = await generateJWK("A256GCMKW");
  });

  it("JWS: round-trips a session across requests through real cookies", async () => {
    const app = new Elysia()
      .resolve(async ({ cookie, request }) => ({
        session: await createJWSSession({ cookie, request }, { key: jwsKey, maxAge: "1h" }),
      }))
      .post(
        "/login",
        async ({ session, body }) => {
          await session.update({ user: body.user });
          return { id: session.id };
        },
        { body: t.Object({ user: t.String() }) },
      )
      .get("/me", ({ session }) => ({
        id: session.id ?? null,
        user: (session.data as { user?: string }).user ?? null,
      }))
      .post("/logout", async ({ session }) => {
        await session.clear();
        return { ok: true };
      });

    const login = await app.handle(post("/login", { user: "alice" }));
    const setCookies = login.headers.getSetCookie();
    expect(setCookies.some((c) => c.startsWith("elysia-jws="))).toBe(true);
    expect(setCookies.every((c) => !/HttpOnly/i.test(c))).toBe(true); // JWS payload is client-readable

    const cookie = cookieHeader(setCookies);
    const me = await app.handle(new Request("http://localhost/me", { headers: { cookie } }));
    const body = (await me.json()) as { id: string | null; user: string | null };
    expect(body.user).toBe("alice");
    expect(body.id).toBeTypeOf("string");

    const logout = await app.handle(post("/logout", {}, { cookie }));
    const cleared = logout.headers.getSetCookie();
    expect(cleared.length).toBeGreaterThan(0);
    expect(cleared.every((c) => /Max-Age=0|Expires=Thu, 01 Jan 1970/i.test(c))).toBe(true);
  });

  it("JWS: reads the session from the x-<name>-session header", async () => {
    const app = new Elysia()
      .resolve(async ({ cookie, request }) => ({
        session: await createJWSSession({ cookie, request }, { key: jwsKey, maxAge: "1h" }),
      }))
      .post(
        "/login",
        async ({ session, body }) => {
          await session.update({ user: body.user });
          return { id: session.id };
        },
        { body: t.Object({ user: t.String() }) },
      )
      .get("/me", ({ session }) => ({ user: (session.data as { user?: string }).user ?? null }));

    const login = await app.handle(post("/login", { user: "bob" }));
    const token = cookieHeader(login.headers.getSetCookie()).replace("elysia-jws=", "");

    const me = await app.handle(
      new Request("http://localhost/me", {
        headers: { "x-elysia-jws-session": `Bearer ${token}` },
      }),
    );
    expect(((await me.json()) as { user: string | null }).user).toBe("bob");
  });

  it("JWE: round-trips an encrypted session and defaults to HttpOnly", async () => {
    const app = new Elysia()
      .resolve(async ({ cookie, request }) => ({
        session: await createJWESession({ cookie, request }, { key: jweKey, maxAge: "1h" }),
      }))
      .post(
        "/login",
        async ({ session, body }) => {
          await session.update({ user: body.user, role: body.role });
          return { id: session.id };
        },
        { body: t.Object({ user: t.String(), role: t.String() }) },
      )
      .get("/me", ({ session }) => ({
        user: (session.data as { user?: string }).user ?? null,
        role: (session.data as { role?: string }).role ?? null,
      }));

    const login = await app.handle(post("/login", { user: "carol", role: "admin" }));
    const setCookies = login.headers.getSetCookie();
    expect(setCookies.some((c) => c.startsWith("elysia-jwe="))).toBe(true);
    expect(setCookies.every((c) => /HttpOnly/i.test(c))).toBe(true); // JWE defaults httpOnly

    const cookie = cookieHeader(setCookies);
    const me = await app.handle(new Request("http://localhost/me", { headers: { cookie } }));
    const body = (await me.json()) as { user: string | null; role: string | null };
    expect(body.user).toBe("carol");
    expect(body.role).toBe("admin");

    // The raw cookie must not expose the payload (it is encrypted).
    expect(cookie).not.toContain("carol");
  });

  it("starts with an empty session when no cookie/header is present", async () => {
    const app = new Elysia()
      .resolve(async ({ cookie, request }) => ({
        session: await createJWSSession({ cookie, request }, { key: jwsKey }),
      }))
      .get("/me", ({ session }) => ({ id: session.id ?? null }));

    const me = await app.handle(new Request("http://localhost/me"));
    expect(((await me.json()) as { id: string | null }).id).toBeNull();
    expect(me.headers.getSetCookie()).toHaveLength(0);
  });
});

describe("elysia session — plugin API (jwsSession / jweSession)", () => {
  let jwsKey: JWK_oct<JWK_HMAC>;
  let jweKey: JWEEncryptJWK;

  beforeAll(async () => {
    jwsKey = await generateJWK("HS256");
    jweKey = await generateJWK("A256GCMKW");
  });

  it("jwsSession exposes an ambient ctx.session and round-trips", async () => {
    const app = new Elysia()
      .use(jwsSession({ key: jwsKey, maxAge: "1h" }))
      .post(
        "/login",
        async ({ session, body }) => {
          await session.update({ user: body.user });
          return { id: session.id };
        },
        { body: t.Object({ user: t.String() }) },
      )
      .get("/me", ({ session }) => ({ user: (session.data as { user?: string }).user ?? null }));

    const login = await app.handle(post("/login", { user: "alice" }));
    const cookie = cookieHeader(login.headers.getSetCookie());
    const me = await app.handle(new Request("http://localhost/me", { headers: { cookie } }));
    expect(((await me.json()) as { user: string | null }).user).toBe("alice");
  });

  it("requireSession guard macro 401s without a session and passes with one", async () => {
    const app = new Elysia()
      .use(jwsSession({ key: jwsKey, maxAge: "1h" }))
      .post(
        "/login",
        async ({ session, body }) => {
          await session.update({ user: body.user });
          return { ok: true };
        },
        { body: t.Object({ user: t.String() }) },
      )
      .guard({ requireSession: true }, (a) =>
        a.get("/admin", ({ session }) => ({ user: (session.data as { user?: string }).user })),
      );

    const denied = await app.handle(new Request("http://localhost/admin"));
    expect(denied.status).toBe(401);

    const login = await app.handle(post("/login", { user: "bob" }));
    const cookie = cookieHeader(login.headers.getSetCookie());
    const allowed = await app.handle(
      new Request("http://localhost/admin", { headers: { cookie } }),
    );
    expect(allowed.status).toBe(200);
    expect(((await allowed.json()) as { user: string }).user).toBe("bob");
  });

  it("supports a custom contextKey", async () => {
    const app = new Elysia()
      .use(jwsSession({ key: jwsKey, contextKey: "auth" }))
      .post(
        "/login",
        async ({ auth, body }) => {
          await auth.update({ user: body.user });
          return { id: auth.id };
        },
        { body: t.Object({ user: t.String() }) },
      )
      .get("/me", ({ auth }) => ({ user: (auth.data as { user?: string }).user ?? null }));

    const login = await app.handle(post("/login", { user: "carol" }));
    const cookie = cookieHeader(login.headers.getSetCookie());
    const me = await app.handle(new Request("http://localhost/me", { headers: { cookie } }));
    expect(((await me.json()) as { user: string | null }).user).toBe("carol");
  });

  it("jweSession exposes an ambient ctx.session and round-trips (encrypted)", async () => {
    const app = new Elysia()
      .use(jweSession({ key: jweKey, maxAge: "1h" }))
      .post(
        "/login",
        async ({ session, body }) => {
          await session.update({ user: body.user });
          return { id: session.id };
        },
        { body: t.Object({ user: t.String() }) },
      )
      .get("/me", ({ session }) => ({ user: (session.data as { user?: string }).user ?? null }));

    const login = await app.handle(post("/login", { user: "dave" }));
    const setCookies = login.headers.getSetCookie();
    expect(setCookies.every((c) => /HttpOnly/i.test(c))).toBe(true);
    const cookie = cookieHeader(setCookies);
    expect(cookie).not.toContain("dave");

    const me = await app.handle(new Request("http://localhost/me", { headers: { cookie } }));
    expect(((await me.json()) as { user: string | null }).user).toBe("dave");
  });
});

describe("elysia session — multiple sessions on one app", () => {
  let hsKey: JWK_oct<JWK_HMAC>;
  let jweKey1: JWEEncryptJWK;
  let jweKey2: JWEEncryptJWK;

  beforeAll(async () => {
    hsKey = await generateJWK("HS256");
    jweKey1 = await generateJWK("A256GCMKW");
    jweKey2 = await generateJWK("A256GCMKW");
  });

  it("two independent JWE sessions (distinct contextKey + name) round-trip separately", async () => {
    const app = new Elysia()
      .use(jweSession({ key: jweKey1, contextKey: "session", name: "sid", maxAge: "1h" }))
      .use(jweSession({ key: jweKey2, contextKey: "shared", name: "shared", maxAge: "5m" }))
      .post(
        "/login",
        async ({ session, shared, body }) => {
          await session.update({ user: body.user });
          await shared.update({ scope: "billing" });
          return { ok: true };
        },
        { body: t.Object({ user: t.String() }) },
      )
      .get("/me", ({ session, shared }) => ({
        user: (session.data as { user?: string }).user ?? null,
        scope: (shared.data as { scope?: string }).scope ?? null,
      }));

    const login = await app.handle(post("/login", { user: "alice" }));
    const names = login.headers.getSetCookie().map((c) => c.split("=")[0]);
    expect(names).toContain("sid");
    expect(names).toContain("shared");

    const cookie = cookieHeader(login.headers.getSetCookie());
    const me = await app.handle(new Request("http://localhost/me", { headers: { cookie } }));
    const body = (await me.json()) as { user: string | null; scope: string | null };
    expect(body.user).toBe("alice");
    expect(body.scope).toBe("billing");
  });

  it("JWS access + JWE refresh together, each with its own cookie defaults", async () => {
    const app = new Elysia()
      .use(jwsSession({ key: hsKey, contextKey: "access", name: "at", maxAge: "10m" }))
      .use(jweSession({ key: jweKey1, contextKey: "refresh", name: "rt", maxAge: "7D" }))
      .post(
        "/login",
        async ({ access, refresh, body }) => {
          await access.update({ user: body.user });
          await refresh.update({ sub: body.user });
          return { ok: true };
        },
        { body: t.Object({ user: t.String() }) },
      )
      .get("/me", ({ access, refresh }) => ({
        user: (access.data as { user?: string }).user ?? null,
        sub: (refresh.data as { sub?: string }).sub ?? null,
      }));

    const login = await app.handle(post("/login", { user: "bob" }));
    const setCookies = login.headers.getSetCookie();
    const at = setCookies.find((c) => c.startsWith("at="))!;
    const rt = setCookies.find((c) => c.startsWith("rt="))!;
    expect(/HttpOnly/i.test(at)).toBe(false); // JWS access — client-readable
    expect(/HttpOnly/i.test(rt)).toBe(true); // JWE refresh — httpOnly

    const cookie = cookieHeader(setCookies);
    const me = await app.handle(new Request("http://localhost/me", { headers: { cookie } }));
    const body = (await me.json()) as { user: string | null; sub: string | null };
    expect(body.user).toBe("bob");
    expect(body.sub).toBe("bob");
  });

  it("derives a distinct guard macro per contextKey (require<Key>)", async () => {
    const app = new Elysia()
      .use(jweSession({ key: jweKey1, contextKey: "session", name: "sid", maxAge: "1h" }))
      .use(jweSession({ key: jweKey2, contextKey: "shared", name: "shared", maxAge: "1h" }))
      .post("/login-session", async ({ session }) => {
        await session.update({ a: 1 });
        return { ok: true };
      })
      .guard({ requireSession: true }, (a) => a.get("/needs-session", () => "session-ok"))
      .guard({ requireShared: true }, (a) => a.get("/needs-shared", () => "shared-ok"));

    const login = await app.handle(post("/login-session", {}));
    const cookie = cookieHeader(login.headers.getSetCookie());

    // A "session" cookie satisfies requireSession but NOT requireShared.
    const needsSession = await app.handle(
      new Request("http://localhost/needs-session", { headers: { cookie } }),
    );
    const needsShared = await app.handle(
      new Request("http://localhost/needs-shared", { headers: { cookie } }),
    );
    expect(needsSession.status).toBe(200);
    expect(needsShared.status).toBe(401);
  });
});
