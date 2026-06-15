import { describe, it, expect, vi, beforeAll } from "vitest";
import { generateJWK } from "../src/core/jwk";
import type {
  JWK_oct,
  JWK_HMAC,
  JWSAsymmetricPrivateJWK,
  JWSAsymmetricPublicJWK,
} from "../src/core/types";
import {
  createJWSSession,
  type SessionConfigJWS,
  type SessionContext,
} from "../src/adapters/elysia/session/jws";
import type { CookieAttributes } from "../src/adapters/elysia/_cookie";

interface MockEntry {
  value: unknown;
  lastWrite?: CookieAttributes & { value: string };
}

function makeContext(
  opts: { cookies?: Record<string, string>; headers?: Record<string, string> } = {},
) {
  const store = new Map<string, MockEntry>();
  for (const [k, v] of Object.entries(opts.cookies ?? {})) store.set(k, { value: v });

  const cookie = new Proxy({} as SessionContext["cookie"], {
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

  const context: SessionContext = {
    cookie,
    request: { headers: new Headers(opts.headers ?? {}) },
  };
  return { context, store };
}

function liveCookies(store: Map<string, MockEntry>): Record<string, string> {
  const out: Record<string, string> = {};
  for (const [k, e] of store) {
    if (e.lastWrite?.maxAge === 0) continue;
    if (typeof e.value === "string" && e.value !== "") out[k] = e.value;
  }
  return out;
}

describe("elysia JWS session core", () => {
  let hsKey: JWK_oct<JWK_HMAC>;
  let rsa: { privateKey: JWSAsymmetricPrivateJWK; publicKey: JWSAsymmetricPublicJWK };

  beforeAll(async () => {
    hsKey = await generateJWK("HS256");
    rsa = await generateJWK("RS256");
  });

  it("starts empty when no token is present (no hooks fire)", async () => {
    const onRead = vi.fn();
    const { context } = makeContext();
    const session = await createJWSSession(context, { key: hsKey, hooks: { onRead } });

    expect(session.id).toBeUndefined();
    expect(session.token).toBeUndefined();
    expect(Object.keys(session.data)).toHaveLength(0);
    expect(onRead).not.toHaveBeenCalled();
  });

  it("update() mints a session, writes a cookie, and fires onUpdate with the empty oldSession", async () => {
    const onUpdate = vi.fn();
    const { context, store } = makeContext();
    const session = await createJWSSession(context, { key: hsKey, hooks: { onUpdate } });

    await session.update({ user: "alice" });

    expect(session.id).toBeTypeOf("string");
    expect(session.token).toBeTypeOf("string");
    expect((session.data as any).user).toBe("alice");
    expect(liveCookies(store)["elysia-jws"]).toBe(session.token);
    expect(onUpdate).toHaveBeenCalledOnce();
    expect(onUpdate.mock.calls[0]![0].oldSession.id).toBeUndefined();
    expect(onUpdate.mock.calls[0]![0].session.id).toBe(session.id);
  });

  it("round-trips a session token from the cookie on the next request (fires onRead)", async () => {
    const cfg: SessionConfigJWS = { key: hsKey };
    const first = makeContext();
    const s1 = await createJWSSession(first.context, cfg);
    await s1.update({ user: "bob", role: "admin" });

    const onRead = vi.fn();
    const second = makeContext({ cookies: liveCookies(first.store) });
    const s2 = await createJWSSession(second.context, { ...cfg, hooks: { onRead } });

    expect(s2.id).toBe(s1.id);
    expect((s2.data as any).user).toBe("bob");
    expect((s2.data as any).role).toBe("admin");
    expect(onRead).toHaveBeenCalledOnce();
  });

  it("reads the token from the session header (Bearer stripped) and fires onRead", async () => {
    const cfg: SessionConfigJWS = { key: hsKey };
    const minted = await createJWSSession(makeContext().context, cfg);
    await minted.update({ user: "carol" });

    const onRead = vi.fn();
    const { context } = makeContext({
      headers: { "x-elysia-jws-session": `Bearer ${minted.token}` },
    });
    const session = await createJWSSession(context, { ...cfg, hooks: { onRead } });

    expect(session.id).toBe(minted.id);
    expect((session.data as any).user).toBe("carol");
    expect(onRead).toHaveBeenCalledOnce();
  });

  it("fires onExpire (not onRead) for an expired token, with decoded claims in cause", async () => {
    const issueCfg: SessionConfigJWS = {
      key: hsKey,
      maxAge: "1s",
      jws: { signOptions: { currentDate: new Date(1000) } },
    };
    const minted = await createJWSSession(makeContext().context, issueCfg);
    await minted.update({ user: "dave" });

    const onRead = vi.fn();
    const onExpire = vi.fn();
    const { context } = makeContext({ cookies: { "elysia-jws": minted.token! } });
    const session = await createJWSSession(context, {
      key: hsKey,
      maxAge: "1s",
      hooks: { onRead, onExpire },
    });

    expect(onExpire).toHaveBeenCalledOnce();
    expect(onRead).not.toHaveBeenCalled();
    expect(onExpire.mock.calls[0]![0].session.id).toBe(minted.id);
    expect(session.id).toBeUndefined();
  });

  it("fires onError (not onRead) for a malformed/invalid token", async () => {
    const onRead = vi.fn();
    const onError = vi.fn();
    const { context } = makeContext({ cookies: { "elysia-jws": "not.a.jwt" } });
    const session = await createJWSSession(context, { key: hsKey, hooks: { onRead, onError } });

    expect(onError).toHaveBeenCalledOnce();
    expect(onRead).not.toHaveBeenCalled();
    expect(session.id).toBeUndefined();
  });

  it("rolls back session.data and fires onError when signing fails mid-update", async () => {
    const onError = vi.fn();
    const { context } = makeContext();
    const session = await createJWSSession(context, { key: hsKey, hooks: { onError } });
    await session.update({ user: "erin" });
    const idBefore = session.id;

    await expect(session.update({ bad: 1n as unknown as string })).rejects.toThrow();

    expect(onError).toHaveBeenCalledOnce();
    expect(session.id).toBe(idBefore);
    expect((session.data as any).user).toBe("erin");
    expect("bad" in session.data).toBe(false);
  });

  it("onUpdate.oldSession.data is a deep pre-update snapshot", async () => {
    const snapshots: Array<{ oldRole: unknown; newRole: unknown }> = [];
    const { context } = makeContext();
    const session = await createJWSSession(context, {
      key: hsKey,
      hooks: {
        onUpdate: ({ session: s, oldSession }) => {
          snapshots.push({
            oldRole: (oldSession.data as any).user?.role,
            newRole: (s.data as any).user?.role,
          });
        },
      },
    });

    await session.update({ user: { role: "user" } });
    await session.update((data) => {
      (data as any).user.role = "admin";
      return {};
    });

    expect(snapshots[1]!.oldRole).toBe("user");
    expect(snapshots[1]!.newRole).toBe("admin");
  });

  it("clear() resets state, expires the cookie, and fires onClear with the old session", async () => {
    const onClear = vi.fn();
    const { context, store } = makeContext();
    const session = await createJWSSession(context, { key: hsKey, hooks: { onClear } });
    await session.update({ user: "frank" });
    const idBefore = session.id;

    await session.clear();

    expect(session.id).toBeUndefined();
    expect(session.token).toBeUndefined();
    expect(Object.keys(session.data)).toHaveLength(0);
    expect(store.get("elysia-jws")?.lastWrite?.maxAge).toBe(0);
    expect(onClear).toHaveBeenCalledOnce();
    expect(onClear.mock.calls[0]![0].oldSession.id).toBe(idBefore);
  });

  it("works with an asymmetric key pair (private signs, public verifies)", async () => {
    const cfg: SessionConfigJWS = { key: { privateKey: rsa.privateKey, publicKey: rsa.publicKey } };
    const first = makeContext();
    const s1 = await createJWSSession(first.context, cfg);
    await s1.update({ user: "grace" });

    const second = makeContext({ cookies: liveCookies(first.store) });
    const s2 = await createJWSSession(second.context, cfg);

    expect(s2.id).toBe(s1.id);
    expect((s2.data as any).user).toBe("grace");
  });

  it("omits exp when maxAge is unset and enforces it when set", async () => {
    const noExp = makeContext();
    const s1 = await createJWSSession(noExp.context, { key: hsKey });
    await s1.update({ user: "heidi" });
    expect(s1.expiresAt).toBeUndefined();

    const withExp = makeContext();
    const s2 = await createJWSSession(withExp.context, { key: hsKey, maxAge: "1h" });
    await s2.update({ user: "ivan" });
    expect(typeof s2.expiresAt).toBe("number");
  });
});
