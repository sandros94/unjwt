import { describe, it, expect, expectTypeOf, vi } from "vitest";

import { isJWTError } from "../src/error.ts";
import { generateJWK, generateKey } from "../src/core/jwk/index.ts";
import { sign, verify } from "../src/core/jws/index.ts";
import { encrypt, decrypt } from "../src/core/jwe/index.ts";
import type { ExpiresIn } from "../src/core/types/index.ts";
import { base64UrlParse } from "../src/utils/index.ts";
import {
  MAX_CHUNK_COUNT,
  parseChunkCount,
  readChunked,
} from "../src/session/_internal/chunked-cookie.ts";
import {
  defineJWSSession,
  defineJWESession,
  type OpenedSessionState,
  type SessionData,
  type SessionDecryptOptions,
  type SessionDefinition,
  type SessionVerifyOptions,
  type WebSessionEvent,
} from "../src/session/index.ts";
import { createJWSCodec } from "../src/session/_internal/codec-jws.ts";
import { createJWECodec } from "../src/session/_internal/codec-jwe.ts";
import type {
  SessionBinding,
  SessionCodec,
  SessionCoreConfig,
} from "../src/session/_internal/types.ts";
import { bindSession } from "../src/session/_internal/bind.ts";
import type { CookieJar, SessionDriver } from "../src/session/_internal/driver.ts";
import { loadSession } from "../src/session/_internal/read.ts";
import { dropSession, issueSession, sessionActions } from "../src/session/_internal/write.ts";
import type { SessionManager } from "../src/session/types.ts";

const [jwsKey, jweKey, rsaSignPair, rsaEncPair] = await Promise.all([
  generateJWK("HS256"),
  generateJWK("A128KW"),
  generateJWK("RS256"),
  generateJWK("RSA-OAEP-256"),
]);
// PBES2 derives its key from the JWK's bytes, so the JWK declares the PBES2 alg itself.
const pbes2Key = { ...jweKey, alg: "PBES2-HS256+A128KW" } as const;

const SECOND = 1000;
const nowSeconds = () => Math.floor(Date.now() / 1000);

/**
 * A token signed with the session key and carrying the session `typ`, but
 * minted by something other than the session.
 */
function foreignJWS(claims: Record<string, unknown>, header: Record<string, unknown> = {}) {
  return sign(claims, jwsKey, {
    protectedHeader: { typ: "session+jwt", ...header },
  });
}

async function caught(run: () => Promise<unknown>): Promise<unknown> {
  try {
    await run();
  } catch (error) {
    return error;
  }
  return undefined;
}

/**
 * Fail rather than hang. A hook that reads the same session it was dispatched
 * from would otherwise await a promise that is waiting on the hook itself, and
 * the request would never settle.
 */
function within<T>(promise: Promise<T> | T, label: string, ms = 2000): Promise<T> {
  return Promise.race([
    Promise.resolve(promise),
    new Promise<never>((_resolve, reject) =>
      setTimeout(() => reject(new Error(`${label} did not settle within ${ms}ms`)), ms),
    ),
  ]);
}

/** Session data long enough to need `count` cookie chunks at `chunkMaxLength`. */
function bulkyData(count: number, chunkMaxLength: number): Record<string, string> {
  return { pad: "x".repeat(count * chunkMaxLength) };
}

const EXPIRED_CLAIMS = {
  jti: "expired-session",
  iat: nowSeconds() - 120,
  exp: nowSeconds() - 60,
};

describe("session contract", () => {
  // #region reads and updates
  describe("reads and updates", () => {
    it.each(familyCases())(
      "$label: a blank session header is a token failure, the cookie unread",
      async (variant) => {
        const token = await mintToken(variant, baseConfig(variant), { who: "cookie" });

        const body = await variant.run(
          { ...baseConfig(variant), sessionHeader: true },
          async (open) => {
            const session = await open();
            return { id: session.id ?? null, who: session.data.who ?? null };
          },
          { cookies: { [variant.name]: token }, headers: { [`x-${variant.name}-session`]: " " } },
        );

        expect(body).toEqual({ id: null, who: null });
      },
    );

    it.each(familyCases())(
      "$label: strips the session-owned claims from an update payload",
      async (variant) => {
        const body = await variant.run(baseConfig(variant), async (open) => {
          const session = await open();
          await session.update({ user: "alice", jti: "forged", exp: 2, nbf: 3 });
          return { id: session.id ?? null, data: { ...session.data } };
        });

        expect(body.data).toEqual({ user: "alice" });
        expect(body.id).not.toBe("forged");
      },
    );

    it.each(familyCases())(
      "$label: rejects prototype-poisoning keys in an update",
      async (variant) => {
        const body = await variant.run(baseConfig(variant), async (open) => {
          const session = await open();
          const error = await caught(() => session.update({ ["constructor"]: 1 }));
          return {
            code: isJWTError(error, "ERR_INVALID_OPTION"),
            message: (error as Error | undefined)?.message ?? null,
          };
        });

        expect(body.code).toBe(true);
        expect(body.message).toMatch(/constructor/);
      },
    );

    it.each(familyCases())("$label: gives one issue a lifetime of its own", async (variant) => {
      const body = await variant.run({ ...baseConfig(variant), maxAge: 60 }, async (open) => {
        const session = await open();
        await session.update({ user: "alice" }, { maxAge: 3600 });
        return { lifetime: session.expiresAt! - session.createdAt };
      });

      expect(body).toEqual({ lifetime: 3600 * SECOND });
    });

    it.each(familyCases())(
      "$label: gives an issue after a clear a lifetime of its own",
      async (variant) => {
        const body = await variant.run({ ...baseConfig(variant), maxAge: 60 }, async (open) => {
          const session = await open();
          await session.update({ user: "alice" });
          await session.clear();
          await session.update({ user: "bob" }, { maxAge: 3600 });
          return {
            id: session.id ?? null,
            data: { ...session.data },
            lifetime: session.expiresAt! - session.createdAt,
          };
        });

        expect(body.id).toBeTypeOf("string");
        expect(body.data).toEqual({ user: "bob" });
        expect(body.lifetime).toBe(3600 * SECOND);
      },
    );
  });
  // #endregion

  // #region chunk bounds
  describe("cookie chunk bounds", () => {
    const chunkMaxLength = 64;
    const chunked = {
      name: "chunk-jws",
      key: jwsKey,
      cookie: { chunkMaxLength, secure: false },
    } as const;

    it("refuses a token needing more chunks than the limit", async () => {
      const session = await defineJWSSession(chunked).use({
        req: new Request("http://localhost/"),
        res: { headers: new Headers() },
      });
      const error = await caught(() =>
        session.update(bulkyData(MAX_CHUNK_COUNT + 14, chunkMaxLength)),
      );

      expect(isJWTError(error, "ERR_SESSION_CONFIG_INVALID")).toBe(true);
      expect((error as Error).message).toContain(String(MAX_CHUNK_COUNT));
    });

    it.each(["__chunked__99", "__chunked__0", "__chunked__abc"])(
      "reads a forged %s marker as no session",
      async (marker) => {
        const session = await defineJWSSession(chunked).use({
          req: new Request("http://localhost/", { headers: { cookie: `chunk-jws=${marker}` } }),
        });

        expect(session.id).toBeUndefined();
        expect(session.token).toBeUndefined();
      },
    );

    it("reads a chunk set missing one of its chunks as no session", async () => {
      const session = await defineJWSSession(chunked).use({
        req: new Request("http://localhost/", {
          headers: { cookie: "chunk-jws=__chunked__2; chunk-jws.1=abc" },
        }),
      });

      expect(session.id).toBeUndefined();
      expect(session.token).toBeUndefined();
    });

    it("bounds cleanup of a forged chunk marker", async () => {
      const headers = new Headers();
      const session = await defineJWSSession(chunked).use({
        req: new Request("http://localhost/", { headers: { cookie: "chunk-jws=__chunked__100" } }),
        res: { headers },
      });
      await session.update({ user: "alice" });

      expect(headers.getSetCookie().length).toBeLessThanOrEqual(MAX_CHUNK_COUNT + 1);
    });
  });
  // #endregion

  // #region key and payload failures
  describe("misconfigured keys and payloads", () => {
    it("a public-only JWS key is refused when the session is defined", async () => {
      const error = await caught(() =>
        defineJWSSession({ name: "publiconly", key: { publicKey: {} } as never }).use({
          req: new Request("http://localhost/"),
        }),
      );

      expect(isJWTError(error, "ERR_SESSION_KEY_INVALID")).toBe(true);
    });

    it("an empty key object is refused when the session is defined", async () => {
      const error = await caught(() =>
        defineJWSSession({ name: "emptykey", key: {} as never }).use({
          req: new Request("http://localhost/"),
        }),
      );

      expect(isJWTError(error, "ERR_SESSION_KEY_INVALID")).toBe(true);
    });
  });
  // #endregion

  // #region one contract across both families
  describe("one contract across both families", () => {
    it.each(familyCases())("$label: a token that does not open is invalid", async (variant) => {
      const body = await variant.run(
        { name: variant.name, key: variant.key, cookie: { secure: false }, hooks: {} },
        async (open) => {
          const session = await open();
          return { id: session.id ?? null, token: session.token ?? null };
        },
        { cookies: { [variant.name]: "not.a.token" } },
      );

      expect(body).toEqual({ id: null, token: null });
    });

    it.each(familyCases())("$label: reports an unopenable token to onError", async (variant) => {
      let seen: unknown;
      const body = await variant.run(
        {
          name: variant.name,
          key: variant.key,
          cookie: { secure: false },
          hooks: {
            onError: ({ error }: { error: unknown }) => {
              seen = error;
            },
          },
        },
        async (open) => {
          await open();
          return { code: isJWTError(seen, "ERR_SESSION_TOKEN_INVALID") };
        },
        { cookies: { [variant.name]: "not.a.token" } },
      );

      expect(body).toEqual({ code: true });
    });

    it.each(familyCases())(
      "$label: drops the cookie of a token that does not open, as an expired one's",
      async (variant) => {
        const onError = vi.fn();
        const response = await variant.serve(
          { name: variant.name, key: variant.key, cookie: { secure: false }, hooks: { onError } },
          async (open) => ({ id: (await open()).id ?? null }),
          { cookies: { [variant.name]: "not.a.token" } },
        );

        expect(response.body).toEqual({ id: null });
        expect(onError).toHaveBeenCalledOnce();
        expect(response.cookies).toEqual([
          expect.stringMatching(new RegExp(`^${variant.name}=; .*Max-Age=0`)),
        ]);
      },
    );

    it.each(familyCases())(
      "$label: keeps the cookie when the key lookup threw, which says nothing about the token",
      async (variant) => {
        const token = await mintToken(variant, baseConfig(variant), { user: "alice" });
        const onError = vi.fn();
        const lookup = () => {
          throw new Error("key store unavailable");
        };
        const response = await variant.serve(
          {
            name: variant.name,
            key: variant.key,
            cookie: { secure: false },
            hooks: {
              onError,
              ...(variant.family === "jws"
                ? { onVerifyKeyLookup: lookup }
                : { onUnsealKeyLookup: lookup }),
            },
          },
          async (open) => ({ id: (await open()).id ?? null }),
          { cookies: { [variant.name]: token } },
        );

        expect(response.body).toEqual({ id: null });
        expect(isJWTError(onError.mock.calls[0]?.[0]?.error.cause, "ERR_JWK_KEY_NOT_FOUND")).toBe(
          true,
        );
        expect(response.cookies).toEqual([]);
      },
    );

    it.each(familyCases())(
      "$label: a missing key is refused when the session is defined",
      async (variant) => {
        const body = await variant.run(
          { name: variant.name, key: undefined, cookie: { secure: false } },
          async (open) => {
            const error = await caught(open);
            return { code: isJWTError(error, "ERR_SESSION_KEY_INVALID") };
          },
        );

        expect(body).toEqual({ code: true });
      },
    );

    it.each(familyCases())("$label: an unusable name is a config failure", async (variant) => {
      const body = await variant.run(
        { name: "bad name", key: variant.key, cookie: { secure: false } },
        async (open) => {
          const error = await caught(open);
          return { code: isJWTError(error, "ERR_SESSION_CONFIG_INVALID") };
        },
      );

      expect(body).toEqual({ code: true });
    });

    it.each(familyCases())("$label: three concurrent reads share one jti", async (variant) => {
      const config = { name: variant.name, key: variant.key, cookie: { secure: false } };

      const minted = await variant.run(config, async (open) => {
        const session = await open();
        await session.update({ user: "alice" });
        return { token: session.token! };
      });

      const body = await variant.run(
        config,
        async (open) => {
          const sessions = await Promise.all([open(), open(), open()]);
          const ids = sessions.map((session) => session.id);
          return { ids, distinct: new Set(ids).size };
        },
        { cookies: { [variant.name]: minted.token as string } },
      );

      expect(body.distinct).toBe(1);
      expect((body.ids as (string | undefined)[])[0]).toBeDefined();
    });
  });
  // #endregion

  // #region one session state per request
  describe("one session state per request", () => {
    it.each(familyCases())(
      "$label: a hook that clears the session on read leaves the handler without one",
      async (variant) => {
        const token = await mintToken(variant, baseConfig(variant), { user: "alice" });
        const config = {
          ...baseConfig(variant),
          hooks: {
            onRead: async (args: Record<string, unknown>) => {
              await (await variant.reopen(args, baseConfig(variant))).clear();
            },
          },
        };

        const handled = await variant.run(
          config,
          async (open) => {
            const session = await open();
            return { id: session.id ?? null, data: { ...session.data } };
          },
          { cookies: { [variant.name]: token } },
        );
        const guarded = await variant.guarded(config, { cookies: { [variant.name]: token } });

        expect(handled).toEqual({ id: null, data: {} });
        expect(guarded.status).toBe(401);
      },
    );

    it.each(familyCases())(
      "$label: a hook that reissues an expired session hands the handler the new one",
      async (variant) => {
        const expired = await foreignToken(variant.family, EXPIRED_CLAIMS);
        const issued: string[] = [];
        const config = {
          ...baseConfig(variant),
          hooks: {
            onExpire: async (args: Record<string, unknown>) => {
              const session = await variant.reopen(args, baseConfig(variant));
              await session.update({ refreshed: true });
              issued.push(session.id!);
            },
          },
        };

        const handled = await variant.run(
          config,
          async (open) => {
            const session = await open();
            return { id: session.id ?? null, data: { ...session.data } };
          },
          { cookies: { [variant.name]: expired } },
        );
        const guarded = await variant.guarded(config, { cookies: { [variant.name]: expired } });

        expect(handled).toEqual({ id: issued[0], data: { refreshed: true } });
        expect(guarded.status).toBe(200);
        expect(guarded.body).toEqual({ id: issued[1] });
      },
    );

    it.each(familyCases())(
      "$label: a cleared session stays cleared while the request still carries a header token",
      async (variant) => {
        const cookieToken = await mintToken(variant, baseConfig(variant), { who: "cookie" });
        const headerToken = await mintToken(variant, baseConfig(variant), { who: "header" });

        const body = await variant.run(
          baseConfig(variant),
          async (open) => {
            const session = await open();
            const before = session.id;
            await session.clear();
            const again = await open();
            return { before, id: again.id ?? null, token: again.token ?? null };
          },
          {
            cookies: { [variant.name]: cookieToken },
            headers: { [`x-${variant.name}-session`]: headerToken },
          },
        );

        expect(body.before).toBeTypeOf("string");
        expect(body).toMatchObject({ id: null, token: null });
      },
    );

    it.each(familyCases())(
      "$label: reports one unopenable token to onError once however often it is opened",
      async (variant) => {
        const onError = vi.fn();
        const body = await variant.run(
          { ...baseConfig(variant), hooks: { onError } },
          async (open) => {
            await open();
            await open();
            return { calls: onError.mock.calls.length };
          },
          { cookies: { [variant.name]: "not.a.token" } },
        );

        expect(body).toEqual({ calls: 1 });
      },
    );
  });
  // #endregion

  // #region key halves
  describe("asymmetric JWE key halves", () => {
    const jweCases = () => familyCases().filter((variant) => variant.family === "jwe");

    it.each(jweCases())(
      "$label: refuses a password string as the private half before any token is opened",
      async (variant) => {
        const { publicKey } = rsaEncPair;
        const onError = vi.fn();
        const forged = await encrypt(
          { jti: "forged", iat: nowSeconds(), exp: nowSeconds() + 3600, sub: "attacker" },
          "hunter2",
          {
            alg: "PBES2-HS256+A128KW",
            enc: "A128GCM",
            p2c: 2048,
            protectedHeader: { typ: "session+jwt" },
          },
        );

        const body = await variant.run(
          {
            name: variant.name,
            key: { publicKey, privateKey: "hunter2" },
            cookie: { secure: false },
            hooks: { onError },
          },
          async (open) => {
            const error = await caught(open);
            return {
              code: isJWTError(error, "ERR_SESSION_KEY_INVALID"),
              message: (error as Error | undefined)?.message ?? null,
            };
          },
          { cookies: { [variant.name]: forged } },
        );

        expect(body.code).toBe(true);
        expect(body.message).toMatch(
          variant.family === "jws" ? /privateKey/ : /an asymmetric key seals with its public half/,
        );
        expect(onError).not.toHaveBeenCalled();
      },
    );
  });
  // #endregion

  // #region writes that fail
  describe("a cookie write that fails", () => {
    it.each(familyCases())(
      "$label: rolls the session back and reports to onError",
      async (variant) => {
        const onError = vi.fn();
        const chunkMaxLength = 64;
        const body = await variant.run(
          {
            name: variant.name,
            key: variant.key,
            cookie: { secure: false, chunkMaxLength },
            hooks: { onError },
          },
          async (open) => {
            const session = await open();
            await session.update({ user: "alice" });
            const before = { id: session.id, token: session.token };
            const error = await caught(() =>
              session.update(bulkyData(MAX_CHUNK_COUNT + 14, chunkMaxLength)),
            );
            return {
              config: isJWTError(error, "ERR_SESSION_CONFIG_INVALID"),
              unchanged: session.id === before.id && session.token === before.token,
              user: session.data.user,
              pad: "pad" in session.data,
              reported: isJWTError(onError.mock.calls[0]?.[0].error, "ERR_SESSION_CONFIG_INVALID"),
            };
          },
        );

        expect(body).toEqual({
          config: true,
          unchanged: true,
          user: "alice",
          pad: false,
          reported: true,
        });
        expect(onError).toHaveBeenCalledOnce();
      },
    );
  });
  // #endregion

  // #region token lifetime
  describe("token lifetime on read", () => {
    /** The `onExpire` call a Web session makes once its in-memory session outlives `maxAge`. */
    async function inMemoryExpiry() {
      const onExpire = vi.fn();
      const event = { req: new Request("http://localhost/"), res: { headers: new Headers() } };
      const config = { name: "contract-jws", key: jwsKey, maxAge: 1, hooks: { onExpire } };
      vi.useFakeTimers({ shouldAdvanceTime: true });
      try {
        const session = await defineJWSSession(config).use(event);
        await session.update({ user: "alice" });
        vi.setSystemTime(Date.now() + 5000);
        await defineJWSSession(config).use(event);
      } finally {
        vi.useRealTimers();
      }
      return onExpire.mock.calls[0][0] as {
        error: Error;
        session: { expiresAt: number };
      };
    }

    it("reports the expiry instant of an in-memory session in milliseconds", async () => {
      const { error, session } = await inMemoryExpiry();

      expect(error.message).toContain(new Date(session.expiresAt).toISOString());
      expect(new Date(session.expiresAt).getUTCFullYear()).toBe(new Date().getUTCFullYear());
    });

    it("reports an in-memory expiry with the message claim validation gives for the same instant", async () => {
      const { error, session } = await inMemoryExpiry();

      const token = await sign({ exp: session.expiresAt / 1000 }, jwsKey);
      const coreError = await verify(token, jwsKey, {
        currentDate: new Date(session.expiresAt + 5000),
      }).catch((error_: unknown) => error_);
      expect(isJWTError(coreError, "ERR_JWT_EXPIRED")).toBe(true);
      expect(error.message).toBe((coreError as Error).message);
    });

    it.each(familyCases())(
      "$label: a per-issue lifetime longer than the config's ends at the config maxAge",
      async (variant) => {
        const onExpire = vi.fn();
        const onError = vi.fn();
        const issuedAt = new Date(Date.now() - 5 * SECOND);
        const token = await mintToken(
          variant,
          {
            ...baseConfig(variant),
            maxAge: 1,
            ...issueOptions(variant.family, { currentDate: issuedAt }),
          },
          { user: "alice" },
          { maxAge: 3600 },
        );

        const body = await variant.run(
          { ...baseConfig(variant), maxAge: 1, hooks: { onExpire, onError } },
          async (open) => {
            const session = await open();
            return { user: session.data.user ?? null };
          },
          { cookies: { [variant.name]: token } },
        );

        expect(body).toEqual({ user: null });
        expect(onExpire).toHaveBeenCalledOnce();
        expect(onExpire.mock.calls[0]?.[0].session.expiresAt).toBe(
          Math.floor(issuedAt.getTime() / 1000) * 1000 + SECOND,
        );
        expect(onError).not.toHaveBeenCalled();
      },
    );

    it.each(familyCases())(
      "$label: a token without exp is refused when the session has a maxAge",
      async (variant) => {
        const onExpire = vi.fn();
        const onError = vi.fn();
        const token = await foreignToken(variant.family, { jti: "no-exp", iat: nowSeconds() });

        const body = await variant.run(
          { ...baseConfig(variant), maxAge: 3600, hooks: { onExpire, onError } },
          async (open) => ({ id: (await open()).id ?? null }),
          { cookies: { [variant.name]: token } },
        );

        expect(body).toEqual({ id: null });
        expect(onExpire).not.toHaveBeenCalled();
        expect(isJWTError(onError.mock.calls[0]?.[0].error, "ERR_SESSION_TOKEN_INVALID")).toBe(
          true,
        );
      },
    );

    it.each(familyCases())(
      "$label: a token whose exp has passed goes to onExpire",
      async (variant) => {
        const onExpire = vi.fn();
        const onError = vi.fn();
        const token = await foreignToken(variant.family, EXPIRED_CLAIMS);

        const body = await variant.run(
          { ...baseConfig(variant), maxAge: 3600, hooks: { onExpire, onError } },
          async (open) => ({ id: (await open()).id ?? null }),
          { cookies: { [variant.name]: token } },
        );

        expect(body).toEqual({ id: null });
        expect(onError).not.toHaveBeenCalled();
        expect(onExpire).toHaveBeenCalledOnce();
        expect(isJWTError(onExpire.mock.calls[0][0].error, "ERR_JWT_EXPIRED")).toBe(true);
      },
    );
  });
  // #endregion

  // #region issued in the future
  describe("issued in the future", () => {
    it.each(familyCases())(
      "$label: a token issued in the future is refused even without a maxAge",
      async (variant) => {
        const future = new Date(Date.now() + 3600_000);
        const minted = await mintToken(
          variant,
          {
            ...baseConfig(variant),
            ...(variant.family === "jws"
              ? { jws: { signOptions: { currentDate: future } } }
              : { jwe: { encryptOptions: { currentDate: future } } }),
          },
          { user: "alice" },
        );
        const onError = vi.fn();
        const body = await variant.run(
          { ...baseConfig(variant), hooks: { onError } },
          async (open) => ({ id: (await open()).id ?? null }),
          { cookies: { [variant.name]: minted } },
        );
        expect(body.id).toBeNull();
        expect(onError).toHaveBeenCalledTimes(1);
        expect(isJWTError(onError.mock.calls[0]?.[0]?.error, "ERR_SESSION_TOKEN_INVALID")).toBe(
          true,
        );

        const tolerated = await variant.run(
          {
            ...baseConfig(variant),
            ...(variant.family === "jws"
              ? { jws: { verifyOptions: { clockTolerance: "2h" } } }
              : { jwe: { decryptOptions: { clockTolerance: "2h" } } }),
          },
          async (open) => ({ id: (await open()).id ?? null }),
          { cookies: { [variant.name]: minted } },
        );
        expect(tolerated.id).toBeTypeOf("string");
      },
    );
  });
  // #endregion

  // #region session-owned claims
  describe("claims the session owns", () => {
    it.each(familyCases())("$label: issue options cannot set exp or nbf", async (variant) => {
      const later = new Date(Date.now() + 365 * 24 * 3600 * SECOND);
      for (const options of [{ expiresAt: later }, { notBeforeIn: 30 }, { notBeforeAt: later }]) {
        const token = await mintToken(
          variant,
          {
            name: variant.name,
            key: variant.key,
            maxAge: 60,
            cookie: { secure: false },
            ...issueOptions(variant.family, options),
          },
          { user: "alice" },
        );
        const claims = await claimsOf(variant.family, token);

        expect((claims.exp as number) - (claims.iat as number)).toBe(60);
        expect(claims).not.toHaveProperty("nbf");
      }
    });
  });
  // #endregion

  // #region reserved claims in session data
  describe("reserved claims in session data", () => {
    const mutate = async (variant: FamilyCase) =>
      variant.run(baseConfig(variant), async (open) => {
        const session = await open();
        await session.update({ user: "alice" });
        Object.assign(session.data, { nbf: 1, exp: 4102444800, iat: 1, jti: "mine" });
        await session.update();
        return { id: session.id ?? null, token: session.token ?? null, data: { ...session.data } };
      });

    it.each(familyCases())(
      "$label: reserved claims written into session.data do not become the session's own",
      async (variant) => {
        const body = await mutate(variant);
        expect(body.id).not.toBe("mine");
        expect(body.data).toEqual({ user: "alice" });
      },
    );

    it.each(familyCases().filter((variant) => variant.family === "jws"))(
      "$label: reserved claims written into session.data never reach the token",
      async (variant) => {
        const body = await mutate(variant);
        const claims = decodeSegment(String(body.token).split(".")[1] ?? "");
        expect(claims.nbf).toBeUndefined();
        expect(claims.exp).toBeUndefined();
        expect(claims.jti).toBe(body.id);
        expect(claims.iat).not.toBe(1);
      },
    );
  });
  // #endregion

  // #region PBES2 iteration cap
  describe("PBES2 iteration cap", () => {
    const jweCases = () => familyCases().filter((variant) => variant.family === "jwe");

    it.each(jweCases())(
      "$label: caps unwrap at the session's own count when the key carries the alg",
      async (variant) => {
        const onError = vi.fn();
        const config = {
          name: variant.name,
          key: pbes2Key,
          cookie: { secure: false },
          jwe: { encryptOptions: { p2c: 2048 } },
          hooks: { onError },
        };
        const own = await mintToken(variant, config, { user: "alice" });
        const costly = await encrypt(
          { jti: "costly", iat: nowSeconds(), user: "mallory" },
          pbes2Key,
          { p2c: 4096, protectedHeader: { typ: "session+jwt" } },
        );

        const read = (token: string) =>
          variant.run(config, async (open) => ({ user: (await open()).data.user ?? null }), {
            cookies: { [variant.name]: token },
          });

        expect(await read(own)).toEqual({ user: "alice" });
        expect(onError).not.toHaveBeenCalled();
        expect(await read(costly)).toEqual({ user: null });
        expect(onError.mock.calls[0][0].error.cause.message).toMatch(/p2c/);
      },
    );
  });
  // #endregion

  // #region token-only configs
  describe("token-only configs", () => {
    it.each(
      familyCases().flatMap((variant) =>
        [{ sessionHeader: false }, {}].map((header) => ({
          variant,
          header,
          label: `${variant.label}, sessionHeader ${"sessionHeader" in header ? "false" : "unset"}`,
        })),
      ),
    )("$label: a session manager still needs a token source", async ({ variant, header }) => {
      const body = await variant.run(
        { name: variant.name, key: variant.key, cookie: false, ...header },
        async (open) => {
          const error = await caught(open);
          return {
            code: isJWTError(error, "ERR_SESSION_CONFIG_INVALID"),
            message: (error as Error | undefined)?.message ?? null,
          };
        },
      );

      expect(body.code).toBe(true);
      expect(body.message).toContain('"sessionHeader"');
    });
  });
  // #endregion

  // #region re-entrant hook matrix
  describe("re-entrant hook matrix", () => {
    const matrixCases = () =>
      familyCases()
        .filter((variant) => variant.family === "jws")
        .flatMap((variant) =>
          hookMatrix().map((entry) => ({ ...entry, variant, label: variant.label })),
        );

    it.each(matrixCases())(
      "$label: $hook may $operation the same session",
      async ({ variant, ...entry }) => {
        const seen: unknown[] = [];
        const config: Record<string, unknown> = {
          name: "matrix-jws",
          key: jwsKey,
          maxAge: "1h",
          cookie: { secure: false },
        };
        config.hooks = reentrantHooks(entry, (args) => variant.reopen(args, config), seen);

        const cookie = await matrixCookie(entry.hook);
        const body = await within(
          variant.run(
            config,
            async (open) => {
              const session = await open();
              await triggerHook(entry, session);
              return {
                id: session.id ?? null,
                token: session.token ?? null,
                hook: session.data.hook ?? null,
              };
            },
            { cookies: cookie ? { "matrix-jws": cookie } : {} },
          ),
          `${entry.hook} / ${entry.operation}`,
        );

        expect(seen).toHaveLength(1);
        expect(body).toMatchObject(handlerView(entry, seen[0]));
      },
    );
  });
  // #endregion

  // #region cookie expiry precedence
  describe("cookie expiry", () => {
    it("lets the token lifetime decide the cookie expiry", async () => {
      const far = new Date(Date.now() + 10 * 365 * 24 * 3600 * 1000);
      const config = {
        name: "expiry-jws",
        key: jwsKey,
        maxAge: "1m",
        cookie: { secure: false, expires: far },
      } as const;

      const headers = new Headers();
      const session = await defineJWSSession(config).use({
        req: new Request("http://localhost/"),
        res: { headers },
      });
      await session.update({ user: "alice" });

      expect(headers.getSetCookie()[0]).not.toContain(String(far.getUTCFullYear()));
    });
  });
  // #endregion

  // #region PBES2 cap with a key lookup
  describe("PBES2 iteration cap with a key lookup hook", () => {
    const jweCases = () => familyCases().filter((variant) => variant.family === "jwe");

    it.each(jweCases())(
      "$label: caps unwrap at the session's own count when a hook supplies the key",
      async (variant) => {
        const onError = vi.fn();
        const config = {
          name: variant.name,
          key: pbes2Key,
          cookie: { secure: false },
          jwe: { encryptOptions: { p2c: 2048 } },
          hooks: { onError, onUnsealKeyLookup: () => pbes2Key },
        };
        const own = await mintToken(variant, config, { user: "alice" });
        const costly = await encrypt(
          { jti: "costly", iat: nowSeconds(), user: "mallory" },
          pbes2Key,
          { p2c: 4096, protectedHeader: { typ: "session+jwt" } },
        );

        const read = (token: string) =>
          variant.run(config, async (open) => ({ user: (await open()).data.user ?? null }), {
            cookies: { [variant.name]: token },
          });

        expect(await read(own)).toEqual({ user: "alice" });
        expect(onError).not.toHaveBeenCalled();
        expect(await read(costly)).toEqual({ user: null });
        expect(onError.mock.calls[0][0].error.cause.message).toMatch(/p2c/);
      },
    );
  });
  // #endregion

  // #region one clock
  describe("one clock per session", () => {
    it.each(familyCases())(
      "$label: a session issued under a past currentDate stays live for the rest of the request",
      async (variant) => {
        const onExpire = vi.fn();
        const config = {
          name: variant.name,
          key: variant.key,
          maxAge: 60,
          cookie: { secure: false },
          ...issueOptions(variant.family, { currentDate: new Date(Date.now() - 3600 * SECOND) }),
          hooks: { onExpire },
        };

        const body = await variant.run(config, async (open) => {
          const session = await open();
          await session.update({ user: "alice" });
          const again = await open();
          return { same: again.id === session.id, user: again.data.user ?? null };
        });

        expect(body).toEqual({ same: true, user: "alice" });
        expect(onExpire).not.toHaveBeenCalled();
      },
    );
  });
  // #endregion

  // #region session typ
  describe("session typ", () => {
    const live = () => ({ jti: "live", iat: nowSeconds(), exp: nowSeconds() + 3600 });

    it.each(familyCases())("$label: writes typ session+jwt and no cty", async (variant) => {
      const token = await mintToken(variant, expiringConfig(variant), { user: "alice" });
      const header = protectedHeaderOf(token);

      expect(header.typ).toBe("session+jwt");
      expect(header).not.toHaveProperty("cty");
    });

    it.each(familyCases())("$label: passes a configured cty through untouched", async (variant) => {
      const config = {
        ...expiringConfig(variant),
        ...issueOptions(variant.family, { protectedHeader: { cty: "application/json" } }),
      };
      const token = await mintToken(variant, config, { user: "alice" });
      const read = await variant.run(
        config,
        async (open) => ({ user: (await open()).data.user ?? null }),
        { cookies: { [variant.name]: token } },
      );

      expect(protectedHeaderOf(token)).toMatchObject({
        typ: "session+jwt",
        cty: "application/json",
      });
      expect(read).toEqual({ user: "alice" });
    });

    it.each(familyCases())(
      "$label: accepts the session typ written as a full media type",
      async (variant) => {
        for (const typ of ["application/session+jwt", "Application/Session+JWT"]) {
          const onError = vi.fn();
          const body = await variant.run(
            { ...expiringConfig(variant), hooks: { onError } },
            async (open) => ({ id: (await open()).id ?? null }),
            { cookies: { [variant.name]: await foreignToken(variant.family, live(), { typ }) } },
          );

          expect(body).toEqual({ id: "live" });
          expect(onError).not.toHaveBeenCalled();
        }
      },
    );

    it.each(familyCases())(
      "$label: refuses a JWT-typed token through onError, never onExpire, expired or not",
      async (variant) => {
        const tokens = [
          await foreignPlainToken(variant.family, live()),
          await foreignPlainToken(variant.family, EXPIRED_CLAIMS),
          await foreignToken(variant.family, EXPIRED_CLAIMS, { typ: "at+jwt" }),
        ];

        for (const token of tokens) {
          const onError = vi.fn();
          const onExpire = vi.fn();
          const response = await variant.serve(
            { ...expiringConfig(variant), hooks: { onError, onExpire } },
            async (open) => ({ id: (await open()).id ?? null }),
            { cookies: { [variant.name]: token } },
          );

          expect(response.body).toEqual({ id: null });
          expect(response.cookies).toEqual([
            expect.stringMatching(new RegExp(`^${variant.name}=; .*Max-Age=0`)),
          ]);
          expect(onExpire).not.toHaveBeenCalled();
          const error = onError.mock.calls[0][0].error;
          expect(isJWTError(error, "ERR_SESSION_TOKEN_INVALID")).toBe(true);
          expect(error.message).toMatch(/typ/);
        }
      },
    );

    it.each(familyCases())(
      "$label: an expired session token still goes to onExpire",
      async (variant) => {
        const onError = vi.fn();
        const onExpire = vi.fn();
        const response = await variant.serve(
          { ...expiringConfig(variant), hooks: { onError, onExpire } },
          async (open) => ({ id: (await open()).id ?? null }),
          { cookies: { [variant.name]: await foreignToken(variant.family, EXPIRED_CLAIMS) } },
        );

        expect(response.body).toEqual({ id: null });
        expect(onError).not.toHaveBeenCalled();
        expect(onExpire.mock.calls[0][0].session.id).toBe(EXPIRED_CLAIMS.jti);
      },
    );
  });
  // #endregion

  // #region configured key material
  describe("configured key material that cannot be imported", () => {
    const unusableKeys: Record<Family, Record<string, unknown>> = {
      jws: { kty: "oct", k: "!!!not-base64url!!!", alg: "HS256" },
      jwe: { kty: "oct", k: "A".repeat(27), alg: "A128KW" },
    };

    it.each(familyCases())(
      "$label: fails the read with a key error instead of reporting the token",
      async (variant) => {
        const onError = vi.fn();
        const token = await foreignToken(variant.family, {
          jti: "live",
          iat: nowSeconds(),
          exp: nowSeconds() + 3600,
        });

        const body = await variant.run(
          {
            name: variant.name,
            key: unusableKeys[variant.family],
            cookie: { secure: false },
            hooks: { onError },
          },
          async (open) => {
            const error = await caught(open);
            return {
              code: isJWTError(error, "ERR_SESSION_KEY_INVALID"),
              cause: isJWTError((error as Error | undefined)?.cause, "ERR_JWK_INVALID"),
            };
          },
          { cookies: { [variant.name]: token } },
        );

        expect(body).toEqual({ code: true, cause: true });
        expect(onError).not.toHaveBeenCalled();
      },
    );
  });
  // #endregion

  // #region update payloads and typ
  describe("update payloads and the session typ", () => {
    it.each(familyCases())(
      "$label: refuses update data that is not a plain object",
      async (variant) => {
        const body = await variant.run(baseConfig(variant), async (open) => {
          const session = await open();
          await session.update({ user: "alice" });
          const before = { id: session.id, token: session.token };
          const errors = [
            await caught(() => session.update("abc" as never)),
            await caught(() => session.update([1, 2] as never)),
            await caught(() => session.update((() => "abc") as never)),
            await caught(() => session.update(new URLSearchParams("user=mallory") as never)),
          ];
          return {
            codes: errors.map((error) => isJWTError(error, "ERR_INVALID_OPTION")),
            data: { ...session.data },
            unchanged: session.id === before.id && session.token === before.token,
          };
        });

        expect(body).toEqual({
          codes: [true, true, true, true],
          data: { user: "alice" },
          unchanged: true,
        });
      },
    );

    it.each(
      familyCases().flatMap((variant) =>
        ["secevent+jwt", "app-session"].map((typ) => ({ ...variant, typ })),
      ),
    )(
      "$label: signs with a configured typ ($typ) and requires it back",
      async ({ typ, ...variant }) => {
        const onError = vi.fn();
        const typed = {
          ...baseConfig(variant),
          ...issueOptions(variant.family, { protectedHeader: { typ } }),
        };
        const own = await mintToken(variant, typed, { user: "alice" });
        const plain = await mintToken(variant, baseConfig(variant), { user: "bob" });

        const read = (token: string) =>
          variant.run(
            { ...typed, hooks: { onError } },
            async (open) => ({ user: (await open()).data.user ?? null }),
            { cookies: { [variant.name]: token } },
          );

        expect(protectedHeaderOf(own).typ).toBe(typ);
        expect(await read(own)).toEqual({ user: "alice" });
        expect(onError).not.toHaveBeenCalled();
        expect(await read(plain)).toEqual({ user: null });
        expect(isJWTError(onError.mock.calls[0][0].error, "ERR_SESSION_TOKEN_INVALID")).toBe(true);
      },
    );
  });
  // #endregion

  // #region cookie lifetime
  describe("cookie lifetime", () => {
    const far = new Date(Date.now() + 10 * 365 * 24 * 3600 * SECOND);

    it.each(familyCases())(
      "$label: a token with a lifetime drops a configured cookie maxAge and expires with the token",
      async (variant) => {
        const response = await variant.serve(
          {
            ...baseConfig(variant),
            maxAge: "1m",
            cookie: { secure: false, maxAge: 10 * 365 * 24 * 3600 },
          },
          async (open) => {
            const session = await open();
            await session.update({ user: "alice" });
            return { expiresAt: session.expiresAt };
          },
        );

        const cookie = liveSetCookie(response.cookies, variant.name)!;
        expect(cookieAttribute(cookie, "max-age")).toBeUndefined();
        expect(Date.parse(cookieAttribute(cookie, "expires")!)).toBe(response.body.expiresAt);
      },
    );

    it.each(familyCases())(
      "$label: a token without a lifetime keeps the configured cookie expires and maxAge",
      async (variant) => {
        const response = await variant.serve(
          { ...baseConfig(variant), cookie: { secure: false, expires: far, maxAge: 3600 } },
          async (open) => {
            const session = await open();
            await session.update({ user: "alice" });
            return { expiresAt: session.expiresAt ?? null };
          },
        );

        const cookie = liveSetCookie(response.cookies, variant.name)!;
        expect(response.body.expiresAt).toBeNull();
        expect(cookieAttribute(cookie, "max-age")).toBe("3600");
        expect(new Date(cookieAttribute(cookie, "expires")!).getUTCFullYear()).toBe(
          far.getUTCFullYear(),
        );
      },
    );

    it.each(familyCases())(
      "$label: a request that carried no token never reports an expiry",
      async (variant) => {
        const onExpire = vi.fn();
        const config = { ...baseConfig(variant), maxAge: 1, hooks: { onExpire } };
        const response = await variant.serve(config, async (open) => {
          await open({
            ...config,
            ...issueOptions(variant.family, { currentDate: new Date(Date.now() - 5 * SECOND) }),
          });
          const again = await open();
          return { id: again.id ?? null, token: again.token ?? null };
        });

        expect(response.body).toEqual({ id: null, token: null });
        expect(onExpire).not.toHaveBeenCalled();
        expect(response.cookies).toEqual([]);
      },
    );

    it.each(familyCases())(
      "$label: a chunk set that shrinks within one request expires the chunks it no longer uses",
      async (variant) => {
        const chunkMaxLength = 64;
        const response = await variant.serve(
          { ...baseConfig(variant), cookie: { secure: false, chunkMaxLength } },
          async (open) => {
            const session = await open();
            await session.update(bulkyData(6, chunkMaxLength));
            const longest = session.token!.length;
            await session.update({ pad: "x" });
            return { token: session.token, shrunk: session.token!.length < longest };
          },
        );

        const live = liveCookies(response.cookies);
        const count = parseChunkCount(live[variant.name]);
        const chunks = Object.keys(live).filter((name) => name.startsWith(`${variant.name}.`));
        expect(response.body.shrunk).toBe(true);
        expect(readChunked({ read: (name) => live[name] }, variant.name)).toBe(response.body.token);
        expect(chunks.toSorted()).toEqual(
          Array.from({ length: count }, (_, index) => `${variant.name}.${index + 1}`).toSorted(),
        );
      },
    );
  });
  // #endregion

  // #region session names
  describe("session names", () => {
    it.each(familyCases())(
      "$label: a name spelling another name's chunk cookie is a config failure",
      async (variant) => {
        const body = await variant.run(
          { name: variant.name, key: variant.key, cookie: { secure: false } },
          async (open) => {
            const codes: boolean[] = [];
            for (const name of [`${variant.name}.1`, `${variant.name}.16`]) {
              const error = await caught(() =>
                open({ name, key: variant.key, cookie: { secure: false } }),
              );
              codes.push(isJWTError(error, "ERR_SESSION_CONFIG_INVALID"));
            }
            const dotted = await open({
              name: `${variant.name}.v1`,
              key: variant.key,
              cookie: { secure: false },
            });
            return { codes, dotted: dotted.id ?? null };
          },
        );

        expect(body).toEqual({ codes: [true, true], dotted: null });
      },
    );

    it.each(familyCases())(
      "$label: a __Host- prefixed name round-trips under its prefix rules",
      async (variant) => {
        const config = { name: `__Host-${variant.name}`, key: variant.key };
        const minted = await variant.serve(config, async (open) => {
          const session = await open();
          await session.update({ user: "alice" });
          return { token: session.token };
        });
        const cookie = liveSetCookie(minted.cookies, config.name)!;

        const body = await variant.run(
          config,
          async (open) => ({ user: (await open()).data.user ?? null }),
          { cookies: { [config.name]: minted.body.token as string } },
        );

        expect(setCookieAttributes(cookie)).toMatchObject({ path: "/", secure: true });
        expect(cookieAttribute(cookie, "domain")).toBeUndefined();
        expect(body).toEqual({ user: "alice" });
      },
    );
  });
  // #endregion

  // #region cookie name prefixes
  describe("cookie name prefixes", () => {
    const codeOf = async (
      variant: FamilyCase,
      config: Record<string, unknown>,
    ): Promise<string | null> =>
      (
        await variant.run(baseConfig(variant), async (open) => {
          const error = await caught(() => open(config));
          return { code: isJWTError(error) ? error.code : null };
        })
      ).code as string | null;

    it.each(familyCases())(
      "$label: a __Host- name refuses a Domain, a Path other than / and an insecure cookie",
      async (variant) => {
        const name = `__Host-${variant.name}`;
        expect(
          await codeOf(variant, { name, key: variant.key, cookie: { domain: "example.com" } }),
        ).toBe("ERR_SESSION_CONFIG_INVALID");
        expect(await codeOf(variant, { name, key: variant.key, cookie: { path: "/app" } })).toBe(
          "ERR_SESSION_CONFIG_INVALID",
        );
        expect(await codeOf(variant, { name, key: variant.key, cookie: { secure: false } })).toBe(
          "ERR_SESSION_CONFIG_INVALID",
        );
        expect(
          await codeOf(variant, {
            name: `__Secure-${variant.name}`,
            key: variant.key,
            cookie: { secure: false },
          }),
        ).toBe("ERR_SESSION_CONFIG_INVALID");
      },
    );

    it.each(familyCases())(
      "$label: a __Host- name with the default attributes, or without a cookie, is accepted",
      async (variant) => {
        const name = `__Host-${variant.name}`;
        const response = await variant.serve({ name, key: variant.key }, async (open) => {
          const session = await open();
          await session.update({ user: "alice" });
          return { id: session.id ?? null };
        });
        expect(response.body.id).toBeTypeOf("string");
        expect(
          response.cookies.some((c) => c.startsWith(`${name}=`) && /;\s*Secure/i.test(c)),
        ).toBe(true);
        expect(response.cookies.some((c) => /;\s*Domain=/i.test(c))).toBe(false);

        const headerOnly = await variant.run(
          { name, key: variant.key, cookie: false, sessionHeader: true },
          async (open) => ({
            id: (await open()).id ?? null,
          }),
        );
        expect(headerOnly.id).toBeNull();
      },
    );
  });
  // #endregion

  // #region session header
  describe("session header", () => {
    it.each(familyCases())(
      "$label: a session header that is not a header name is a config failure",
      async (variant) => {
        const body = await variant.run(baseConfig(variant), async (open) => {
          const codes: boolean[] = [];
          for (const sessionHeader of ["bad header", "", "x-session\r\n", "x-sess:ion"]) {
            const error = await caught(() => open({ ...baseConfig(variant), sessionHeader }));
            codes.push(isJWTError(error, "ERR_SESSION_CONFIG_INVALID"));
          }
          return { codes };
        });

        expect(body).toEqual({ codes: [true, true, true, true] });
      },
    );

    it.each(familyCases())(
      "$label: an Authorization header without a Bearer token is a token failure",
      async (variant) => {
        const onError = vi.fn();
        const config = {
          ...baseConfig(variant),
          sessionHeader: "authorization",
          hooks: { onError },
        };
        const bodies: Record<string, unknown>[] = [];
        for (const value of ["Bearer", "Bearer   ", "Basic dXNlcjpwYXNz", "Bearer a b"]) {
          bodies.push(
            await variant.run(config, async (open) => ({ id: (await open()).id ?? null }), {
              headers: { authorization: value },
            }),
          );
        }

        expect(bodies).toEqual([{ id: null }, { id: null }, { id: null }, { id: null }]);
        expect(onError).toHaveBeenCalledTimes(4);
        for (const [{ error }] of onError.mock.calls) {
          expect(isJWTError(error, "ERR_SESSION_TOKEN_INVALID")).toBe(true);
          expect((error as Error).message).toContain('the "authorization" header holds neither');
        }
      },
    );
  });
  // #endregion

  // #region update hooks and payload round trip
  describe("update hooks and the data round trip", () => {
    it.each(familyCases())(
      "$label: an onUpdate hook that throws rejects the update, which stays issued",
      async (variant) => {
        const onError = vi.fn();
        const config = {
          ...baseConfig(variant),
          hooks: {
            onUpdate: () => {
              throw new Error("hook failed");
            },
            onError,
          },
        };
        const response = await variant.serve(config, async (open) => {
          const session = await open();
          const error = await caught(() => session.update({ user: "alice" }));
          return {
            message: (error as Error).message,
            id: session.id ?? null,
            user: session.data.user ?? null,
            token: session.token ?? null,
          };
        });

        expect(response.body).toMatchObject({ message: "hook failed", user: "alice" });
        expect(response.body.id).toBeTypeOf("string");
        expect(liveCookies(response.cookies)[variant.name]).toBe(response.body.token);
        expect(onError).not.toHaveBeenCalled();
      },
    );

    it.each(familyCases())(
      "$label: session data reads back as its JSON round trip",
      async (variant) => {
        const token = await mintToken(variant, baseConfig(variant), {
          at: new Date(0),
          ratio: Number.NaN,
          gone: undefined,
        });

        const body = await variant.run(
          baseConfig(variant),
          async (open) => ({ data: { ...(await open()).data } }),
          { cookies: { [variant.name]: token } },
        );

        expect(body).toEqual({ data: { at: "1970-01-01T00:00:00.000Z", ratio: null } });
      },
    );
  });
  // #endregion

  // #region session kid
  describe("session kid", () => {
    it.each(familyCases())(
      "$label: a configured protectedHeader.kid wins over the key's kid",
      async (variant) => {
        const config = {
          ...kidConfig(variant),
          ...issueOptions(variant.family, { protectedHeader: { kid: "header-kid" } }),
        };
        const token = await mintToken(variant, config, { user: "alice" });
        const read = await variant.run(
          config,
          async (open) => ({ user: (await open()).data.user ?? null }),
          { cookies: { [variant.name]: token } },
        );

        expect(protectedHeaderOf(token).kid).toBe("header-kid");
        expect(read).toEqual({ user: "alice" });
      },
    );

    it.each(familyCases())(
      "$label: the key's kid is written when the config names none",
      async (variant) => {
        const token = await mintToken(variant, kidConfig(variant), { user: "alice" });

        expect(protectedHeaderOf(token).kid).toBe("key-kid");
      },
    );
  });
  // #endregion

  // #region options reaching the token check
  describe("options reaching the token check", () => {
    it.each(familyCases())(
      "$label: a symmetric key set from the lookup hook opens the token",
      async (variant) => {
        const token = await mintToken(variant, baseConfig(variant), { user: "alice" });
        const lookup = () => ({ keys: [variant.key] });
        const hooks =
          variant.family === "jws" ? { onVerifyKeyLookup: lookup } : { onUnsealKeyLookup: lookup };

        const read = await variant.run(
          { ...baseConfig(variant), hooks },
          async (open) => ({ user: (await open()).data.user ?? null }),
          { cookies: { [variant.name]: token } },
        );

        expect(read).toEqual({ user: "alice" });
      },
    );

    it.each(familyCases())(
      "$label: limits.keyCandidates bounds the key set a token is tried against",
      async (variant) => {
        const token = await mintToken(variant, baseConfig(variant), { user: "alice" });
        const other = {
          ...(await generateJWK(variant.family === "jws" ? "HS256" : "A128KW")),
          kid: (variant.key as { kid?: string }).kid,
        };
        const lookup = () => ({ keys: [other, variant.key] });
        const hooks =
          variant.family === "jws" ? { onVerifyKeyLookup: lookup } : { onUnsealKeyLookup: lookup };

        const reads: Record<string, unknown>[] = [];
        for (const keyCandidates of [1, 2]) {
          reads.push(
            await variant.run(
              {
                ...baseConfig(variant),
                ...openOptions(variant.family, { limits: { keyCandidates } }),
                hooks,
              },
              async (open) => ({ user: (await open()).data.user ?? null }),
              { cookies: { [variant.name]: token } },
            ),
          );
        }

        expect(reads).toEqual([{ user: null }, { user: "alice" }]);
      },
    );

    it("JWS verify options and JWE decrypt options take the same core options", () => {
      expectTypeOf<SessionVerifyOptions>().toHaveProperty("limits");
      expectTypeOf<SessionDecryptOptions>().toHaveProperty("limits");
      expectTypeOf<SessionVerifyOptions>().not.toHaveProperty("typ");
      expectTypeOf<SessionVerifyOptions>().not.toHaveProperty("maxTokenAge");
      expectTypeOf<SessionVerifyOptions>().not.toHaveProperty("payload");
      expectTypeOf<SessionVerifyOptions>().not.toHaveProperty("validateClaims");
      expectTypeOf<SessionVerifyOptions>().toHaveProperty("algorithms");
      expectTypeOf<SessionDecryptOptions>().not.toHaveProperty("typ");
      expectTypeOf<SessionDecryptOptions>().not.toHaveProperty("maxTokenAge");
      expectTypeOf<SessionDecryptOptions>().not.toHaveProperty("payload");
      expectTypeOf<SessionDecryptOptions>().not.toHaveProperty("validateClaims");
      expectTypeOf<SessionDecryptOptions>().toHaveProperty("algorithms");
      expectTypeOf<SessionDecryptOptions>().not.toHaveProperty("encryptionAlgorithms");
    });
  });
  // #endregion

  // #region reads and rolling
  describe("reads and rolling", () => {
    const opened = async (
      open: (override?: Record<string, unknown>) => Promise<SessionManager>,
    ) => {
      const session = await open();
      return { id: session.id ?? null, token: session.token ?? null, data: { ...session.data } };
    };

    it.each(familyCases())(
      "$label: onRead fires once per request, however often the session is opened",
      async (variant) => {
        const token = await mintToken(variant, baseConfig(variant), { user: "alice" });
        const onRead = vi.fn();
        const body = await variant.run(
          { ...baseConfig(variant), hooks: { onRead } },
          async (open) => {
            await open();
            await open();
            const session = await open();
            return { id: session.id ?? null };
          },
          { cookies: { [variant.name]: token } },
        );

        expect(body.id).toBeTypeOf("string");
        expect(onRead).toHaveBeenCalledTimes(1);
      },
    );

    it.each(familyCases())(
      "$label: a hook that opens the session again gets the same one without firing itself",
      async (variant) => {
        const token = await mintToken(variant, baseConfig(variant), { user: "alice" });
        let reads = 0;
        const seen: (string | undefined)[] = [];
        const config: Record<string, unknown> = {
          ...baseConfig(variant),
          hooks: {
            onRead: async (args: Record<string, unknown>) => {
              reads++;
              seen.push((await variant.reopen(args, config)).id);
            },
          },
        };

        const body = await variant.run(
          config,
          async (open) => ({ ...(await opened(open)), reads, seen }),
          { cookies: { [variant.name]: token } },
        );

        expect(body.reads).toBe(1);
        expect(body.seen).toEqual([body.id]);
        expect(body.data).toEqual({ user: "alice" });
      },
    );

    it.each(familyCases())(
      "$label: hooks receive the session manager, so onRead can update in place",
      async (variant) => {
        const token = await mintToken(variant, baseConfig(variant), { user: "alice" });
        const onUpdate = vi.fn();
        const body = await variant.run(
          {
            ...baseConfig(variant),
            hooks: {
              onRead: async ({ session }: { session: SessionManager }) => {
                await session.update({ seen: true });
              },
              onUpdate,
            },
          },
          opened,
          { cookies: { [variant.name]: token } },
        );

        expect(body.data).toEqual({ user: "alice", seen: true });
        expect(body.token).not.toBe(token);
        expect(onUpdate).toHaveBeenCalledTimes(1);
        expect(onUpdate.mock.calls[0]?.[0]).toMatchObject({ trigger: "update" });
      },
    );

    it.each(familyCases())(
      "$label: rolling: true reissues a valid session on read and reports it to onUpdate",
      async (variant) => {
        const config = expiringConfig(variant);
        const token = await mintToken(variant, config, { user: "alice" });
        const onRead = vi.fn();
        const onUpdate = vi.fn();
        const response = await variant.serve(
          { ...config, rolling: true, hooks: { onRead, onUpdate } },
          opened,
          { cookies: { [variant.name]: token } },
        );

        expect(response.body.data).toEqual({ user: "alice" });
        expect(response.body.token).not.toBe(token);
        expect(response.cookies.length).toBeGreaterThan(0);
        expect(onRead).toHaveBeenCalledTimes(1);
        expect(onUpdate).toHaveBeenCalledTimes(1);
        expect(onUpdate.mock.calls[0]?.[0]).toMatchObject({
          trigger: "rolling",
          oldSession: { token },
        });
      },
    );

    it.each(familyCases())(
      "$label: a rolling duration reissues only once the token is that old",
      async (variant) => {
        const config = { ...expiringConfig(variant), rolling: "15m" };
        const fresh = await mintToken(variant, config, { user: "alice" });
        const issuedAt = nowSeconds() - 20 * 60;
        const aged = await foreignToken(variant.family, {
          jti: "aged",
          iat: issuedAt,
          exp: issuedAt + 3600,
          user: "alice",
        });

        const kept = await variant.serve(config, opened, { cookies: { [variant.name]: fresh } });
        expect(kept.body.token).toBe(fresh);
        expect(kept.cookies).toEqual([]);

        const rolled = await variant.serve(config, opened, { cookies: { [variant.name]: aged } });
        expect(rolled.body.token).not.toBe(aged);
        expect(rolled.cookies.length).toBeGreaterThan(0);
      },
    );

    it.each(familyCases())(
      "$label: a hook that clears the session on read stops the roll",
      async (variant) => {
        const config = expiringConfig(variant);
        const token = await mintToken(variant, config, { user: "alice" });
        const onUpdate = vi.fn();
        const response = await variant.serve(
          {
            ...config,
            rolling: true,
            hooks: {
              onRead: async ({ session }: { session: SessionManager }) => {
                await session.clear();
              },
              onUpdate,
            },
          },
          opened,
          { cookies: { [variant.name]: token } },
        );

        expect(response.body.id).toBeNull();
        expect(onUpdate).not.toHaveBeenCalled();
      },
    );

    it.each(familyCases())(
      "$label: rolling needs a maxAge and a true or duration value",
      async (variant) => {
        const codeOf = async (config: Record<string, unknown>) =>
          (
            await variant.run(config, async (open) => {
              const error = await caught(open);
              return { code: isJWTError(error) ? error.code : null };
            })
          ).code;

        expect(await codeOf({ ...baseConfig(variant), rolling: true })).toBe(
          "ERR_SESSION_CONFIG_INVALID",
        );
        expect(await codeOf({ ...expiringConfig(variant), rolling: "soon" })).toBe(
          "ERR_INVALID_OPTION",
        );
        expect(await codeOf({ ...expiringConfig(variant), rolling: false })).toBe(
          "ERR_INVALID_OPTION",
        );
        expect(await codeOf({ ...expiringConfig(variant), rolling: 0 })).toBe("ERR_INVALID_OPTION");
        expect(await codeOf({ ...expiringConfig(variant), rolling: "1h" })).toBe(
          "ERR_SESSION_CONFIG_INVALID",
        );
      },
    );
  });
  // #endregion

  // #region key pair halves
  describe("key pair halves", () => {
    const refusal = (variant: FamilyCase, key: unknown) =>
      variant.run({ name: variant.name, key, cookie: { secure: false } }, async (open) => {
        const error = await caught(open);
        return {
          code: isJWTError(error, "ERR_SESSION_KEY_INVALID"),
          message: (error as Error | undefined)?.message ?? null,
        };
      });

    it.each(familyCases().filter((variant) => variant.family === "jws"))(
      "$label: names the private half when it is not a private key",
      async (variant) => {
        const { publicKey } = rsaPairFor(variant);
        const body = await refusal(variant, { publicKey, privateKey: publicKey });

        expect(body.code).toBe(true);
        expect(body.message).toMatch(/"privateKey"/);
      },
    );

    it.each(familyCases().filter((variant) => variant.family === "jws"))(
      "$label: names the public half when it is not a public key",
      async (variant) => {
        const { privateKey } = rsaPairFor(variant);
        const body = await refusal(variant, { publicKey: "hunter2", privateKey });

        expect(body.code).toBe(true);
        expect(body.message).toMatch(/"publicKey"/);
      },
    );

    it.each(familyCases().filter((variant) => variant.family === "jwe"))(
      "$label: refuses a key pair, or its private half alone, as the session key",
      async (variant) => {
        const { privateKey, publicKey } = rsaPairFor(variant);
        const cryptoPair = await generateKey("RSA-OAEP-256");
        const keys = [{ privateKey, publicKey }, { privateKey }, privateKey, cryptoPair];

        for (const key of keys) {
          const body = await refusal(variant, key);
          expect(body.code).toBe(true);
          expect(body.message).toMatch(/an asymmetric key seals with its public half/);
        }
      },
    );

    it.each(familyCases().filter((variant) => variant.family === "jws"))(
      "$label: a key pair signs with its private half and reads back with its public half",
      async (variant) => {
        const { privateKey, publicKey } = rsaPairFor(variant);
        const config = {
          name: variant.name,
          key: { privateKey, publicKey },
          cookie: { secure: false },
        };
        const token = await mintToken(variant, config, { user: "ada" });

        const body = await variant.run(
          config,
          async (open) => {
            const session = await open();
            return { id: session.id ?? null, data: session.data };
          },
          { cookies: { [variant.name]: token } },
        );

        expect(body.id).toEqual(expect.any(String));
        expect(body.data).toEqual({ user: "ada" });
        expect(protectedHeaderOf(token).alg).toBe("RS256");
      },
    );

    it.each(familyCases().filter((variant) => variant.family === "jws"))(
      "$label: refuses a public key list or set carrying an entry that is not a public key",
      async (variant) => {
        const { privateKey, publicKey } = rsaPairFor(variant);
        const bodies = [
          await refusal(variant, { privateKey, publicKey: [publicKey, privateKey] }),
          await refusal(variant, { privateKey, publicKey: { keys: [publicKey, jwsKey] } }),
          await refusal(variant, { privateKey, publicKey: [] }),
        ];

        for (const body of bodies) {
          expect(body.code).toBe(true);
          expect(body.message).toMatch(/"publicKey"/);
        }
      },
    );
  });
  // #endregion

  // #region cookie attributes on the wire
  describe("cookie attributes on the wire", () => {
    const COOKIE_ATTRIBUTES = [
      "expires",
      "max-age",
      "domain",
      "path",
      "secure",
      "httponly",
      "samesite",
      "partitioned",
      "priority",
    ];

    it.each(familyCases())(
      "$label: writes and expires its cookie with cookie attributes only",
      async (variant) => {
        const config = {
          name: variant.name,
          key: variant.key,
          maxAge: 60,
          cookie: { secure: false, chunkMaxLength: 4000 },
        };
        const written = await variant.serve(config, async (open) => {
          const session = await open();
          await session.update({ user: "alice" });
          return { token: session.token };
        });
        const cleared = await variant.serve(
          config,
          async (open) => {
            await (await open()).clear();
            return { ok: true };
          },
          { cookies: { [variant.name]: written.body.token as string } },
        );

        const headers = [...written.cookies, ...cleared.cookies];
        expect(written.cookies.length).toBeGreaterThan(0);
        expect(cleared.cookies.length).toBeGreaterThan(0);
        for (const header of headers) {
          for (const attribute of attributeNames(header)) {
            expect(COOKIE_ATTRIBUTES).toContain(attribute);
          }
        }
      },
    );

    it.each(familyCases())(
      "$label: an expired cookie carries Max-Age=0 and an epoch Expires",
      async (variant) => {
        const config = {
          name: variant.name,
          key: variant.key,
          maxAge: 3600,
          cookie: { secure: false, maxAge: 3600 },
        };
        const token = await mintToken(variant, config, { user: "alice" });
        const cleared = await variant.serve(
          config,
          async (open) => {
            await (await open()).clear();
            return { ok: true };
          },
          { cookies: { [variant.name]: token } },
        );
        const dropped = await variant.serve(
          config,
          async (open) => ({ id: (await open()).id ?? null }),
          {
            cookies: { [variant.name]: await foreignToken(variant.family, EXPIRED_CLAIMS) },
          },
        );

        for (const response of [cleared, dropped]) {
          const expired = expiredSetCookie(response.cookies, variant.name);
          expect(expired).toBeDefined();
          expect(cookieAttribute(expired!, "max-age")).toBe("0");
          expect(Date.parse(cookieAttribute(expired!, "expires")!)).toBe(0);
        }
      },
    );
  });
  // #endregion

  // #region token transports
  describe("token transports", () => {
    const HEADER_CASES = [
      { setting: "unset", cookie: true, header: undefined, reads: false },
      { setting: "true", cookie: true, header: undefined, reads: true },
      { setting: "false", cookie: true, header: undefined, reads: false },
      { setting: "a header name", cookie: true, header: "x-custom-token", reads: true },
      { setting: "true", cookie: false, header: undefined, reads: true },
    ] as const;

    const SETTINGS = {
      "unset": {},
      "true": { sessionHeader: true },
      "false": { sessionHeader: false },
      "a header name": { sessionHeader: "x-custom-token" },
    } as const;

    it.each(
      familyCases().flatMap((variant) =>
        HEADER_CASES.map((entry) => ({
          variant,
          entry,
          label: `${variant.label}: sessionHeader ${entry.setting}, cookies ${entry.cookie ? "on" : "off"}`,
        })),
      ),
    )("$label", async ({ variant, entry }) => {
      const config = {
        name: variant.name,
        key: variant.key,
        cookie: entry.cookie ? { secure: false } : false,
        ...SETTINGS[entry.setting],
      };
      const token = await foreignToken(variant.family, { jti: "from-header", iat: nowSeconds() });
      const header = entry.header ?? `x-${variant.name}-session`;

      const body = await variant.run(config, async (open) => ({ id: (await open()).id ?? null }), {
        headers: { [header]: token },
      });

      expect(body).toEqual({ id: entry.reads ? "from-header" : null });
    });

    const READ_ONLY_CONTEXTS = {
      "web request without a response": {
        context: (headers: Record<string, string>) => ({
          req: new Request("http://localhost/", { headers }),
        }),
      },
    } as const;

    const readOnlyCases = (Object.keys(READ_ONLY_CONTEXTS) as (keyof typeof READ_ONLY_CONTEXTS)[])
      .flatMap((kind) => (["jws", "jwe"] as const).map((family) => ({ kind, family })))
      .map((entry) => ({ ...entry, label: `${entry.kind} ${entry.family}` }));

    /** A cookie session on a read-only context, counting the key lookups its reads make. */
    function readOnlySession(
      entry: { kind: keyof typeof READ_ONLY_CONTEXTS; family: Family },
      options: { cookie: string; hooks?: Record<string, unknown> },
    ) {
      const { context } = READ_ONLY_CONTEXTS[entry.kind];
      const name = `contract-${entry.family}`;
      const key = entry.family === "jws" ? jwsKey : jweKey;
      const lookup = vi.fn(() => key);
      const config = {
        name,
        key,
        cookie: { secure: false },
        hooks: {
          ...options.hooks,
          ...(entry.family === "jws"
            ? { onVerifyKeyLookup: lookup }
            : { onUnsealKeyLookup: lookup }),
        },
      };
      const event = context({ cookie: `${name}=${options.cookie}` });
      const open = () => OPENERS[entry.family](event, config as never) as Promise<SessionManager>;
      return { open, lookup };
    }

    const readOnlyError = (error: unknown) =>
      isJWTError(error, "ERR_SESSION_READONLY_EVENT") &&
      error.message.includes("Cannot update session on read-only event.");

    it.each(readOnlyCases)(
      "$label: a cookie session refuses update, and clear empties it for the rest of the context",
      async (entry) => {
        const onClear = vi.fn();
        const token = await foreignToken(entry.family, { jti: "read-only", iat: nowSeconds() });
        const { open, lookup } = readOnlySession(entry, { cookie: token, hooks: { onClear } });

        const session = await open();
        expect(session.id).toBe("read-only");
        expect(readOnlyError(await caught(() => session.update({ user: "alice" })))).toBe(true);
        expect(session.id).toBe("read-only");

        expect(await caught(() => session.clear())).toBeUndefined();
        expect(onClear).toHaveBeenCalledOnce();
        expect(onClear.mock.calls[0]?.[0]).toMatchObject({ oldSession: { id: "read-only" } });
        expect(session.id).toBeUndefined();
        expect(session.token).toBeUndefined();

        const again = await open();
        expect(again.id).toBeUndefined();
        expect(again.token).toBeUndefined();
        expect(lookup).toHaveBeenCalledOnce();
        expect(readOnlyError(await caught(() => again.update({ user: "alice" })))).toBe(true);
      },
    );

    it.each(readOnlyCases)(
      "$label: an onRead hook that clears a revoked session leaves it empty",
      async (entry) => {
        const revoked = new Set(["revoked"]);
        const onClear = vi.fn();
        const token = await foreignToken(entry.family, { jti: "revoked", iat: nowSeconds() });
        const { open } = readOnlySession(entry, {
          cookie: token,
          hooks: {
            onClear,
            onRead: async ({ session }: { session: SessionManager }) => {
              if (revoked.has(session.id!)) await session.clear();
            },
          },
        });

        const session = await open();

        expect(session.id).toBeUndefined();
        expect(session.token).toBeUndefined();
        expect(onClear).toHaveBeenCalledOnce();
      },
    );

    it.each(readOnlyCases)(
      "$label: a header-only session re-mints its token in place",
      async ({ kind, family }) => {
        const { context } = READ_ONLY_CONTEXTS[kind];
        const name = `contract-${family}`;
        const config = {
          name,
          key: family === "jws" ? jwsKey : jweKey,
          cookie: false,
          sessionHeader: true,
        };
        const token = await foreignToken(family, { jti: "headers-only", iat: nowSeconds() });
        const event = context({ [`x-${name}-session`]: token });
        const session = (await OPENERS[family](event, config as never)) as SessionManager;
        expect(session.token).toBe(token);

        await session.update({ user: "alice" });

        expect(session.token).toBeTypeOf("string");
        expect(session.token).not.toBe(token);
        expect(session.id).not.toBe("headers-only");
        expect(await caught(() => session.clear())).toBeUndefined();
      },
    );

    it("two JWS sessions bound under one name share their state", async () => {
      const response = await serveRequest(async (event) => {
        const first = (await OPENERS.jws(event, {
          name: "shared",
          key: jwsKey,
        } as never)) as SessionManager;
        await first.update({ who: "first" });
        const second = (await OPENERS.jws(event, {
          name: "shared",
          key: jwsKey,
          cookie: { secure: false },
        } as never)) as SessionManager;
        const shared = { same: second.id === first.id, who: second.data.who ?? null };
        await second.clear();
        return { ...shared, cleared: first.id ?? null };
      });

      expect(response.body).toEqual({ same: true, who: "first", cleared: null });
    });

    it("the next request binds a name afresh", async () => {
      await serveRequest(async (event) => {
        const jws = (await OPENERS.jws(event, {
          name: "per-request",
          key: jwsKey,
        } as never)) as SessionManager;
        await jws.update({ family: "jws" });
        return { ok: true };
      });

      const response = await serveRequest(async (event) => {
        const error = await caught(() =>
          OPENERS.jwe(event, { name: "per-request", key: jweKey } as never),
        );
        return { error: error === undefined ? null : (error as Error).message };
      });

      expect(response.body).toEqual({ error: null });
    });
  });
  // #endregion

  // #region cookie writes from the session core
  describe("cookie writes from the session core", () => {
    it.each(["jws", "jwe"] as const)(
      "%s: every write hands the jar cookie attributes, the token split at chunkMaxLength",
      async (family) => {
        const recorder = recordingDriver({ token: await foreignToken(family, EXPIRED_CLAIMS) });
        const binding = coreBinding(family, recorder.driver, {
          maxAge: 60,
          cookie: { secure: false, chunkMaxLength: 64 },
        });

        await loadSession(binding);
        const dropped = recorder.writes.length;
        const issued = await issueSession(binding, { user: "alice" });
        const set = recorder.writes.slice(dropped);
        await dropSession(binding);
        const cleared = recorder.writes.slice(dropped + set.length);

        for (const write of recorder.writes) {
          expect(write.attrs).not.toHaveProperty("chunkMaxLength");
          expect(write.attrs).toMatchObject({ path: "/", secure: false, sameSite: "lax" });
        }
        expect(recorder.writes.slice(0, dropped)).toMatchObject([
          { name: "core-" + family, value: "", attrs: { maxAge: 0 } },
        ]);
        const [marker, ...chunks] = set;
        expect(marker.value).toBe(`__chunked__${chunks.length}`);
        expect(chunks.length).toBeGreaterThan(1);
        expect(chunks.every((chunk) => chunk.value.length <= 64)).toBe(true);
        expect(chunks.map((chunk) => chunk.value).join("")).toBe(issued.token);
        for (const write of set) {
          expect(write.attrs).toMatchObject({ expires: new Date(issued.expiresAt!) });
        }
        expect(cleared.map((write) => write.name)).toEqual(set.map((write) => write.name));
        expect(cleared.every((write) => write.value === "" && write.attrs.maxAge === 0)).toBe(true);
      },
    );

    it.each(["jws", "jwe"] as const)(
      "%s: an expired session on a sealed response reports expiry and writes nothing",
      async (family) => {
        const warn = vi.spyOn(console, "warn").mockImplementation(() => {});
        try {
          const onExpire = vi.fn();
          const onError = vi.fn();
          const recorder = recordingDriver({
            token: await foreignToken(family, EXPIRED_CLAIMS),
            writable: false,
          });
          const binding = coreBinding(family, recorder.driver, {
            maxAge: 60,
            hooks: { onExpire, onError },
          });
          const session = await loadSession(binding);

          expect(session.token).toBeUndefined();
          expect(recorder.writes).toEqual([]);
          expect(onExpire).toHaveBeenCalledOnce();
          expect(onError).not.toHaveBeenCalled();
          expect(warn).not.toHaveBeenCalled();
        } finally {
          warn.mockRestore();
        }
      },
    );

    it.each(["jws", "jwe"] as const)(
      "%s: a rolling session on a sealed response is read and not reissued",
      async (family) => {
        const warn = vi.spyOn(console, "warn").mockImplementation(() => {});
        try {
          const hooks = { onRead: vi.fn(), onUpdate: vi.fn(), onError: vi.fn() };
          const claims = { jti: "live-session", iat: nowSeconds() - 30, exp: nowSeconds() + 60 };
          const recorder = recordingDriver({
            token: await foreignToken(family, claims),
            writable: false,
          });
          const binding = coreBinding(family, recorder.driver, {
            maxAge: 60,
            rolling: true,
            hooks,
          });
          const session = await loadSession(binding);

          expect(session.id).toBe("live-session");
          expect(session.token).toBeTypeOf("string");
          expect(recorder.writes).toEqual([]);
          expect(hooks.onRead).toHaveBeenCalledOnce();
          expect(hooks.onUpdate).not.toHaveBeenCalled();
          expect(hooks.onError).not.toHaveBeenCalled();
          expect(warn).not.toHaveBeenCalled();
        } finally {
          warn.mockRestore();
        }
      },
    );

    it.each(["jws", "jwe"] as const)(
      "%s: a jar that cannot take a cookie clears without a write and refuses an update",
      async (family) => {
        const onClear = vi.fn();
        const claims = { jti: "read-only", iat: nowSeconds() };
        const recorder = recordingDriver({
          token: await foreignToken(family, claims),
          write: false,
        });
        const binding = coreBinding(family, recorder.driver, { hooks: { onClear } });

        expect((await loadSession(binding)).id).toBe("read-only");
        const update = await caught(() => issueSession(binding, { user: "alice" }));
        expect(isJWTError(update, "ERR_SESSION_READONLY_EVENT")).toBe(true);
        expect((update as Error).message).toBe("[test] Cannot update session on read-only event.");

        expect(await caught(() => dropSession(binding))).toBeUndefined();
        expect(onClear).toHaveBeenCalledOnce();
        expect((await loadSession(binding)).id).toBeUndefined();
        expect(recorder.writes).toEqual([]);
      },
    );

    it.each(["jws", "jwe"] as const)(
      "%s: a response already sent refuses a clear and keeps the session",
      async (family) => {
        const onClear = vi.fn();
        const claims = { jti: "too-late", iat: nowSeconds() };
        const recorder = recordingDriver({
          token: await foreignToken(family, claims),
          writable: false,
        });
        const binding = coreBinding(family, recorder.driver, { hooks: { onClear } });

        expect((await loadSession(binding)).id).toBe("too-late");
        const update = await caught(() => issueSession(binding, { user: "alice" }));
        const clear = await caught(() => dropSession(binding));

        expect(alreadySent(update)).toBe(true);
        expect(alreadySent(clear)).toBe(true);
        expect((clear as Error).message.startsWith("[test] ")).toBe(true);
        expect(onClear).not.toHaveBeenCalled();
        expect((await loadSession(binding)).id).toBe("too-late");
        expect(recorder.writes).toEqual([]);
      },
    );
  });
  // #endregion

  // #region session definitions
  describe("session definitions", () => {
    it.each(familyCases())(
      "$label: use() shares one request's state with a second use() and the per-call opener",
      async (variant) => {
        const config = baseConfig(variant);
        const definition = definitionOf(variant, config);

        const first = await serveRequest(async (event) => {
          const session = await definition.use(event);
          await session.update({ user: "alice" });
          const again = await definition.use(event);
          const opened = (await OPENERS[variant.family](event, config as never)) as SessionManager;
          return {
            id: session.id ?? null,
            again: again.id ?? null,
            user: again.data.user ?? null,
            opened: opened.id ?? null,
            openedUser: opened.data.user ?? null,
          };
        });
        const next = await serveRequest(async (event) => {
          const session = await definition.use(event);
          return { id: session.id ?? null, user: session.data.user ?? null };
        });

        const id = first.body.id;
        expect(id).toBeTypeOf("string");
        expect(first.body).toEqual({
          id,
          again: id,
          user: "alice",
          opened: id,
          openedUser: "alice",
        });
        expect(next.body).toEqual({ id: null, user: null });
      },
    );

    it.each(familyCases())(
      "$label: token() returns the carried token unopened, the header before the cookie",
      async (variant) => {
        const definition = definitionOf(variant, { ...baseConfig(variant), sessionHeader: true });
        const header = `x-${variant.name}-session`;
        const read = async (options?: ServeOptions) =>
          (
            await serveRequest(
              async (event) => ({ token: definition.token(event) ?? null }),
              options,
            )
          ).body;

        expect(
          await read({
            cookies: { [variant.name]: "opaque-cookie" },
            headers: { [header]: "opaque-header" },
          }),
        ).toEqual({ token: "opaque-header" });
        expect(
          await read({
            cookies: { [variant.name]: "opaque-cookie" },
            headers: { [header]: "Basic opaque-header" },
          }),
        ).toEqual({ token: null });
        expect(await read({ cookies: { [variant.name]: "opaque-cookie" } })).toEqual({
          token: "opaque-cookie",
        });
        expect(await read({ headers: { [header]: "Bearer opaque-header" } })).toEqual({
          token: "opaque-header",
        });
        expect(await read()).toEqual({ token: null });
      },
    );

    it.each(familyCases())(
      "$label: issue() mints a fresh jti and iat per call, exp from maxAge, outside any request",
      async (variant) => {
        const definition = definitionOf(variant, expiringConfig(variant));

        const tokens = await Promise.all([
          definition.issue({ user: "alice", jti: "forged", iat: 1, exp: 1, nbf: 1 }),
          definition.issue({ user: "alice" }),
          definition.issue({}, { maxAge: 60 }),
        ]);
        const [first, second, shorter] = await Promise.all(
          tokens.map((token) => claimsOf(variant.family, token)),
        );

        expect(first.jti).toBeTypeOf("string");
        expect(first.jti).not.toBe("forged");
        expect(first.jti).not.toBe(second.jti);
        expect(first.nbf).toBeUndefined();
        expect(first.user).toBe("alice");
        expect(Math.abs((first.iat as number) - nowSeconds())).toBeLessThanOrEqual(1);
        expect((first.exp as number) - (first.iat as number)).toBe(3600);
        expect((shorter.exp as number) - (shorter.iat as number)).toBe(60);
        expect(protectedHeaderOf(tokens[0]).typ).toBe("session+jwt");
      },
    );

    it.each(familyCases())(
      "$label: issue() refuses data carrying a prototype-polluting key",
      async (variant) => {
        const definition = definitionOf(variant, baseConfig(variant));

        for (const poisoned of [
          JSON.parse('{"__proto__":{"admin":true}}'),
          { constructor: "admin" },
          { prototype: "admin" },
        ]) {
          const error = await caught(() => definition.issue(poisoned));
          expect(isJWTError(error, "ERR_INVALID_OPTION")).toBe(true);
        }
      },
    );

    it.each(familyCases())(
      "$label: an issued token opens with open() and through a request",
      async (variant) => {
        const definition = definitionOf(variant, expiringConfig(variant));
        const token = await definition.issue({ user: "alice" });
        const claims = await claimsOf(variant.family, token);

        const opened = await definition.open(token);
        const viaRequest = await serveRequest(
          async (event) => {
            const session = await definition.use(event);
            return { id: session.id ?? null, user: session.data.user ?? null };
          },
          { cookies: { [variant.name]: token } },
        );

        expect(opened.id).toBe(claims.jti);
        expect({ ...opened.data }).toEqual({ user: "alice" });
        expect(opened.expiresAt! - opened.createdAt).toBe(3600 * SECOND);
        expect(viaRequest.body).toEqual({ id: claims.jti, user: "alice" });
      },
    );

    it.each(familyCases())(
      "$label: open() refuses a foreign typ, an algorithm the key does not serve and a missing exp",
      async (variant) => {
        const claims = { jti: "foreign", iat: nowSeconds() };
        const refused = async (definition: TestDefinition, token: string) =>
          isJWTError(await caught(() => definition.open(token)), "ERR_SESSION_TOKEN_INVALID");

        const typed = definitionOf(variant, baseConfig(variant));
        expect(await refused(typed, await foreignPlainToken(variant.family, claims))).toBe(true);
        expect((await typed.open(await foreignToken(variant.family, claims))).id).toBe("foreign");

        const hsKey = await generateJWK("HS512");
        const pinned = definitionOf(
          variant,
          variant.family === "jws"
            ? { key: { ...hsKey, alg: "HS256" }, jws: { signOptions: { alg: "HS256" } } }
            : { key: jweKey, jwe: { encryptOptions: { alg: "A128KW", enc: "A128GCM" } } },
        );
        const offAlgorithm =
          variant.family === "jws"
            ? await sign(claims, hsKey, { protectedHeader: { typ: "session+jwt" } })
            : await encrypt(
                claims,
                { ...jweKey, alg: "A128GCMKW" },
                {
                  enc: "A128GCM",
                  protectedHeader: { typ: "session+jwt" },
                },
              );
        expect(await refused(pinned, offAlgorithm)).toBe(true);
        expect((await pinned.open(await pinned.issue({}))).id).toBeTypeOf("string");

        const expiring = definitionOf(variant, expiringConfig(variant));
        expect(await refused(expiring, await foreignToken(variant.family, claims))).toBe(true);
        const bounded = { ...claims, exp: nowSeconds() + 60 };
        expect((await expiring.open(await foreignToken(variant.family, bounded))).id).toBe(
          "foreign",
        );
      },
    );

    it.each(familyCases())(
      "$label: the key lookup receives the request from use(), and none from open(token)",
      async (variant) => {
        const seen: string[][] = [];
        const lookup = (args: Record<string, unknown>) => {
          seen.push(Object.keys(args).toSorted());
          return variant.key;
        };
        const hooks =
          variant.family === "jws" ? { onVerifyKeyLookup: lookup } : { onUnsealKeyLookup: lookup };
        const definition = definitionOf(variant, { ...baseConfig(variant), hooks });
        const token = await definition.issue({ user: "alice" });

        const opened = await definition.open(token);
        const viaRequest = await serveRequest(
          async (event) => ({ user: (await definition.use(event)).data.user ?? null }),
          { cookies: { [variant.name]: token } },
        );

        expect(opened.data).toEqual({ user: "alice" });
        expect(viaRequest.body).toEqual({ user: "alice" });
        expect(seen).toEqual([
          ["config", "header"],
          ["config", "event", "header"],
        ]);
      },
    );

    it.each(familyCases())(
      "$label: a token-only definition issues and opens, and refuses use() and token()",
      async (variant) => {
        const definition = definitionOf(variant, {
          name: variant.name,
          key: variant.key,
          cookie: false,
          sessionHeader: false,
        });
        const sourceless = (error: unknown) => isJWTError(error, "ERR_SESSION_CONFIG_INVALID");

        const token = await definition.issue({ user: "alice" });
        const opened = await definition.open(token);
        const viaRequest = await serveRequest(async (event) => ({
          use: sourceless(await caught(() => definition.use(event))),
          token: sourceless(await caught(async () => definition.token(event))),
        }));

        expect({ ...opened.data }).toEqual({ user: "alice" });
        expect(viaRequest.body).toEqual({ use: true, token: true });
        expect(viaRequest.cookies).toEqual([]);
      },
    );

    it("types: the key lookups take the request as optional, the other hooks as required", () => {
      defineJWSSession({
        key: jwsKey,
        hooks: {
          onVerifyKeyLookup: (args) => {
            expectTypeOf(args.event).toEqualTypeOf<WebSessionEvent | undefined>();
            return jwsKey;
          },
          onRead: (args) => {
            expectTypeOf(args.event).toEqualTypeOf<WebSessionEvent>();
          },
        },
      });
      defineJWESession({
        key: jweKey,
        hooks: {
          onUnsealKeyLookup: (args) => {
            expectTypeOf(args.event).toEqualTypeOf<WebSessionEvent | undefined>();
            return jweKey;
          },
        },
      });
    });

    it("types: use() resolves to the manager with the data generic first, open() to the state a token carries", () => {
      type Data = { user: string };
      const jwsWeb = defineJWSSession<Data, 3600>({ key: jwsKey, maxAge: 3600 });
      const jweWeb = defineJWESession<Data, 3600>({ key: jweKey, maxAge: 3600 });

      expectTypeOf(jwsWeb.use).returns.resolves.toEqualTypeOf<SessionManager<Data, 3600>>();
      expectTypeOf(jweWeb.use).returns.resolves.toEqualTypeOf<SessionManager<Data, 3600>>();

      expectTypeOf(jwsWeb.open).returns.resolves.toEqualTypeOf<OpenedSessionState<Data, 3600>>();
      expectTypeOf(jweWeb.open).returns.resolves.toEqualTypeOf<OpenedSessionState<Data, 3600>>();
      expectTypeOf(jwsWeb.open).returns.resolves.toHaveProperty("id").toEqualTypeOf<string>();
      expectTypeOf(jwsWeb.open)
        .returns.resolves.toHaveProperty("createdAt")
        .toEqualTypeOf<number>();
      expectTypeOf(jwsWeb.open)
        .returns.resolves.toHaveProperty("expiresAt")
        .toEqualTypeOf<number>();
      expectTypeOf(jwsWeb.open)
        .returns.resolves.toHaveProperty("data")
        .toEqualTypeOf<SessionData<Data>>();
      expectTypeOf(jwsWeb.issue)
        .parameter(0)
        .toEqualTypeOf<Partial<SessionData<Data>> | undefined>();
      expectTypeOf(jwsWeb).toEqualTypeOf<SessionDefinition<Data, 3600>>();
    });
  });
  // #endregion
});

/** The attributes a `Set-Cookie` header carries, normalized for comparison. */
function setCookieAttributes(setCookie: string): Record<string, unknown> {
  const attributes = setCookie
    .split(";")
    .slice(1)
    .map((part) => part.trim().toLowerCase());
  return {
    path: attributes.find((a) => a.startsWith("path="))?.slice("path=".length),
    secure: attributes.includes("secure"),
    httpOnly: attributes.includes("httponly"),
    sameSite: attributes.find((a) => a.startsWith("samesite="))?.slice("samesite=".length),
  };
}

/** The cookies a response leaves set, last write winning, without the ones it expires. */
function liveCookies(setCookies: string[]): Record<string, string> {
  const cookies: Record<string, string> = {};
  for (const setCookie of setCookies) {
    const pair = setCookie.split(";", 1)[0];
    const separator = pair.indexOf("=");
    cookies[pair.slice(0, separator).trim()] = decodeURIComponent(pair.slice(separator + 1).trim());
  }
  for (const [name, value] of Object.entries(cookies)) if (!value) delete cookies[name];
  return cookies;
}

/** The last `Set-Cookie` header a response writes for `name` with a value. */
function liveSetCookie(setCookies: string[], name: string): string | undefined {
  return setCookies.findLast(
    (setCookie) => setCookie.startsWith(`${name}=`) && !setCookie.startsWith(`${name}=;`),
  );
}

/** One attribute of a `Set-Cookie` header, matched case-insensitively. */
function cookieAttribute(setCookie: string, attribute: string): string | undefined {
  for (const part of setCookie.split(";").slice(1)) {
    const [key = "", ...value] = part.trim().split("=");
    if (key.toLowerCase() === attribute) return value.join("=");
  }
  return undefined;
}

type Family = "jws" | "jwe";
type Opener = (event: WebSessionEvent, config: never) => Promise<unknown>;

interface ServeOptions {
  cookies?: Record<string, string>;
  headers?: Record<string, string>;
}

interface Served {
  status: number;
  body: Record<string, unknown>;
  cookies: string[];
}

/** What a handler returns to answer `401`. */
const UNAUTHORIZED: unique symbol = Symbol("unauthorized");

type Handler = (event: WebSessionEvent) => Promise<Record<string, unknown> | typeof UNAUTHORIZED>;

interface FamilyCase {
  label: string;
  family: Family;
  name: string;
  key: unknown;
  /** One request whose handler opens this session; resolves to the JSON body. */
  run: (
    config: Record<string, unknown>,
    body: (
      open: (override?: Record<string, unknown>) => Promise<SessionManager>,
    ) => Promise<Record<string, unknown>>,
    options?: ServeOptions,
  ) => Promise<Record<string, unknown>>;
  /** Like `run`, resolving to the whole response. */
  serve: (
    config: Record<string, unknown>,
    body: (
      open: (override?: Record<string, unknown>) => Promise<SessionManager>,
    ) => Promise<Record<string, unknown> | typeof UNAUTHORIZED>,
    options?: ServeOptions,
  ) => Promise<Served>;
  /** Open this session from inside a hook, through the request the hook names. */
  reopen: (
    args: Record<string, unknown>,
    config: Record<string, unknown>,
  ) => Promise<SessionManager>;
  /** One request behind a session guard: a handler answering `401` without a session id. */
  guarded: (config: Record<string, unknown>, options?: ServeOptions) => Promise<Served>;
}

const OPENERS: Record<Family, Opener> = {
  jws: (event, config: Parameters<typeof defineJWSSession>[0]) =>
    defineJWSSession(config).use(event),
  jwe: (event, config: Parameters<typeof defineJWESession>[0]) =>
    defineJWESession(config).use(event),
};

type TestDefinition = SessionDefinition<Record<string, unknown>>;

const DEFINERS = {
  jws: defineJWSSession,
  jwe: defineJWESession,
} as unknown as Record<Family, (config: Record<string, unknown>) => TestDefinition>;

/** The session definition of the family `variant` runs, over `config`. */
function definitionOf(variant: FamilyCase, config: Record<string, unknown>): TestDefinition {
  return DEFINERS[variant.family](config);
}

/** The same session case on both families, each through one Web request. */
function familyCases(): FamilyCase[] {
  return (["jws", "jwe"] as const).map((family) => familyCase(family));
}

function familyCase(family: Family): FamilyCase {
  const openWith = (event: WebSessionEvent, config: Record<string, unknown>) =>
    OPENERS[family](event, config as never) as Promise<SessionManager>;

  const serve: FamilyCase["serve"] = (config, body, options) =>
    serveRequest((event) => body((override) => openWith(event, override ?? config)), options);

  return {
    label: family,
    family,
    name: `contract-${family}`,
    key: family === "jws" ? jwsKey : jweKey,
    run: async (config, body, options) => (await serve(config, body, options)).body,
    serve,
    reopen: (args, config) => openWith(args.event as WebSessionEvent, config),
    guarded: (config, options) =>
      serve(
        config,
        async (open) => {
          const session = await open();
          return session.id ? { id: session.id } : UNAUTHORIZED;
        },
        options,
      ),
  };
}

async function serveRequest(handler: Handler, options?: ServeOptions): Promise<Served> {
  const headers = new Headers();
  const request = new Request("http://localhost/", requestInit(options));
  try {
    const out = await handler({ req: request, res: { headers } });
    if (out === UNAUTHORIZED) return served(401, "Unauthorized", headers.getSetCookie());
    return served(200, JSON.stringify(out), headers.getSetCookie());
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    return served(500, JSON.stringify({ message }), headers.getSetCookie());
  }
}

function requestInit(options: ServeOptions | undefined): { headers: Record<string, string> } {
  return { headers: { ...options?.headers, ...cookieHeader(options?.cookies) } };
}

function served(status: number, text: string, cookies: string[]): Served {
  let body: unknown = text;
  try {
    body = JSON.parse(text);
  } catch {}
  return { status, body: body as Record<string, unknown>, cookies };
}

/** A token minted by the session itself, through one request of `variant`. */
async function mintToken(
  variant: FamilyCase,
  config: Record<string, unknown>,
  data: Record<string, unknown>,
  options?: { maxAge?: ExpiresIn },
): Promise<string> {
  const body = await variant.run(config, async (open) => {
    const session = await open();
    await session.update(data, options);
    return { token: session.token };
  });
  return body.token as string;
}

/** A session-shaped token of `family` sealed with the session key, but minted outside the session. */
function foreignToken(
  family: Family,
  claims: Record<string, unknown>,
  header: Record<string, unknown> = {},
): Promise<string> {
  return family === "jws"
    ? foreignJWS(claims, header)
    : encrypt(claims, jweKey, {
        protectedHeader: { typ: "session+jwt", ...header },
      });
}

/** A plain JWT of `family` sealed with the session key, typed `JWT` as `sign()` / `encrypt()` mint it. */
function foreignPlainToken(family: Family, claims: Record<string, unknown>): Promise<string> {
  const options = { protectedHeader: { typ: "JWT" } };
  return family === "jws" ? sign(claims, jwsKey, options) : encrypt(claims, jweKey, options);
}

/** The protected header of a compact token. */
function protectedHeaderOf(token: string): Record<string, unknown> {
  return JSON.parse(base64UrlParse(token.split(".")[0])) as Record<string, unknown>;
}

/** The claims a session token carries, opened with the session key. */
async function claimsOf(family: Family, token: string): Promise<Record<string, unknown>> {
  const opened =
    family === "jws"
      ? await verify(token, jwsKey, { validateClaims: false })
      : await decrypt(token, jweKey, { validateClaims: false });
  return opened.payload;
}

/** The `jws.signOptions` / `jwe.encryptOptions` block of a session config. */
function issueOptions(family: Family, options: Record<string, unknown>): Record<string, unknown> {
  return family === "jws"
    ? { jws: { signOptions: options } }
    : { jwe: { encryptOptions: options } };
}

/** The `jws.verifyOptions` / `jwe.decryptOptions` block of a session config. */
function openOptions(family: Family, options: Record<string, unknown>): Record<string, unknown> {
  return family === "jws"
    ? { jws: { verifyOptions: options } }
    : { jwe: { decryptOptions: options } };
}

/** The attribute names a `Set-Cookie` header carries, lowercased. */
function attributeNames(setCookie: string): string[] {
  return setCookie
    .split(";")
    .slice(1)
    .map((part) => (part.trim().split("=")[0] ?? "").toLowerCase());
}

/** The last `Set-Cookie` header a response expires `name` with. */
function expiredSetCookie(setCookies: string[], name: string): string | undefined {
  return setCookies.findLast(
    (setCookie) => setCookie.startsWith(`${name}=;`) || setCookie === `${name}=`,
  );
}

/** The refusal an update or clear meets once the response was sent. */
function alreadySent(error: unknown): boolean {
  return (
    isJWTError(error, "ERR_SESSION_READONLY_EVENT") &&
    error.message.includes("Cannot update/clear session: the response was already sent.")
  );
}

interface RecordedWrite {
  name: string;
  value: string;
  attrs: Record<string, unknown>;
}

/**
 * A session driver over a plain object, recording every cookie write the core asks of its jar.
 * `write: false` hands a jar that cannot take a cookie; `writable: false` a response already sent.
 */
function recordingDriver(options: { token?: string; write?: boolean; writable?: boolean }): {
  driver: SessionDriver<object>;
  writes: RecordedWrite[];
} {
  const writes: RecordedWrite[] = [];
  const written = new Map<string, string>();
  const record: Record<string, unknown> = Object.create(null);
  const jar: CookieJar = {
    read: (name) => (name.includes(".") ? undefined : options.token),
    written: (name) => written.get(name),
  };
  if (options.write !== false) {
    jar.write = (name, value, attrs) => {
      written.set(name, value);
      writes.push({ name, value, attrs: { ...attrs } });
    };
  }
  const driver: SessionDriver<object> = {
    prefix: "[test]",
    state: () => record,
    header: () => undefined,
    cookies: () => jar,
    writable: () => options.writable ?? true,
  };
  return { driver, writes };
}

/** A session of `family` bound to `driver` straight through the session core. */
function coreBinding(
  family: Family,
  driver: SessionDriver<object>,
  config: Record<string, unknown>,
): SessionBinding<object, SessionCoreConfig> {
  const codec =
    family === "jws"
      ? createJWSCodec({ prefix: "[test]", defaultName: "core-jws" })
      : createJWECodec({ prefix: "[test]", defaultName: "core-jwe" });
  const core = codec as unknown as SessionCodec<SessionCoreConfig>;
  const bound = { key: family === "jws" ? jwsKey : jweKey, ...config } as SessionCoreConfig;
  return bindSession<object, SessionCoreConfig>(
    {},
    {
      config: bound,
      name: bound.name || core.defaultName,
      driver,
      codec: core,
      keys: core.keys(bound),
      actions: sessionActions(),
    },
  );
}

function cookieHeader(cookies: Record<string, string> | undefined): Record<string, string> {
  if (!cookies) return {};
  const cookie = Object.entries(cookies)
    .map(([name, value]) => `${name}=${value}`)
    .join("; ");
  return cookie ? { cookie } : {};
}

const HOOK_NAMES = ["onRead", "onUpdate", "onClear", "onExpire", "onError"] as const;
const HOOK_OPERATIONS = ["read", "update", "clear", "token"] as const;

interface MatrixEntry {
  hook: (typeof HOOK_NAMES)[number];
  operation: (typeof HOOK_OPERATIONS)[number];
}

/** Every hook against every operation it might perform on its own session. */
function hookMatrix(): MatrixEntry[] {
  return HOOK_NAMES.flatMap((hook) => HOOK_OPERATIONS.map((operation) => ({ hook, operation })));
}

/** The cookie a request must carry for `hook` to be dispatched at all. */
async function matrixCookie(hook: MatrixEntry["hook"]): Promise<string | undefined> {
  if (hook === "onRead") {
    return foreignJWS({ jti: "matrix", iat: nowSeconds(), exp: nowSeconds() + 3600 });
  }
  if (hook === "onExpire") return foreignJWS(EXPIRED_CLAIMS);
  if (hook === "onError") return "not.a.token";
  return undefined;
}

/**
 * Hooks that run their operation against the session they were dispatched from,
 * once — a hook that updated on every `onUpdate` would never stop. Each records
 * what it left the session as, for the handler to be compared against.
 */
function reentrantHooks(
  entry: MatrixEntry,
  open: (args: Record<string, unknown>) => Promise<SessionManager>,
  seen: unknown[],
): Record<string, (args: Record<string, unknown>) => Promise<void>> {
  let entered = false;
  return {
    [entry.hook]: async (args) => {
      if (entered) return;
      entered = true;
      const session = await open(args);
      if (entry.operation === "update") await session.update({ hook: entry.hook });
      else if (entry.operation === "clear") await session.clear();
      seen.push(entry.operation === "token" ? (session.token ?? null) : (session.id ?? null));
    },
  };
}

/** What the handler's own session must show once the hook has run its operation. */
function handlerView(entry: MatrixEntry, recorded: unknown): Record<string, unknown> {
  if (entry.operation === "update") return { id: recorded, hook: entry.hook };
  if (entry.operation === "clear") return { id: null, token: null };
  if (entry.operation === "token") return { token: recorded };
  return { id: recorded };
}

/** The call that dispatches `hook` once the request has been read. */
async function triggerHook(entry: MatrixEntry, session: SessionManager): Promise<void> {
  if (entry.hook === "onUpdate") await session.update({ user: "alice" });
  else if (entry.hook === "onClear") await session.clear();
}

/** The session config a contract case starts from: its name and key, cookies over plain HTTP. */
function baseConfig(variant: FamilyCase) {
  return { name: variant.name, key: variant.key, cookie: { secure: false } };
}

/** {@link baseConfig} with a one-hour `maxAge`. */
function expiringConfig(variant: FamilyCase) {
  return { name: variant.name, key: variant.key, maxAge: 3600, cookie: { secure: false } };
}

/** {@link baseConfig} with a `kid` on the session key. */
function kidConfig(variant: FamilyCase) {
  return {
    name: variant.name,
    key: { ...(variant.key as Record<string, unknown>), kid: "key-kid" },
    cookie: { secure: false },
  };
}

/** The RSA key pair of the family `variant` runs; the halves are only ever read. */
function rsaPairFor(variant: FamilyCase) {
  return variant.family === "jws" ? rsaSignPair : rsaEncPair;
}

function decodeSegment(segment: string): Record<string, unknown> {
  const text = atob(segment.replaceAll("-", "+").replaceAll("_", "/"));
  // oxlint-disable-next-line typescript/no-unsafe-type-assertion -- a JWT payload the test just minted
  return JSON.parse(text) as Record<string, unknown>;
}
