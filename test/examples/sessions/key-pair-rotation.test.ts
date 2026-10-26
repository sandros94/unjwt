import { afterEach, describe, expect, it, vi } from "vitest";
import { generateJWK } from "unjwt/jwk";
import { type JWSSessionKey, defineJWSSession } from "unjwt/session";

async function load(env: { signing: string | undefined; earlier?: unknown[] }) {
  vi.resetModules();
  vi.stubEnv("SESSION_SIGNING_KEY", env.signing);
  vi.stubEnv(
    "SESSION_EARLIER_KEYS",
    env.earlier ? JSON.stringify({ keys: env.earlier }) : undefined,
  );
  return import("../../../examples/sessions/key-pair-rotation.ts");
}

function headerOf(token: string): { kid?: string } {
  const [header = ""] = token.split(".");
  return JSON.parse(atob(header.replaceAll("-", "+").replaceAll("_", "/")));
}

afterEach(() => {
  vi.unstubAllEnvs();
});

describe("examples/sessions/key-pair-rotation", async () => {
  const [next, former, retired] = await Promise.all(
    ["2026-10", "2026-09", "2026-08"].map((kid) => generateJWK("ES256", { kid })),
  );
  const issuedBy = (pair: JWSSessionKey) =>
    defineJWSSession({ key: pair, maxAge: "1h" }).issue({ userId: "user_1a2b" });

  it("refuses to load without SESSION_SIGNING_KEY", async () => {
    await expect(load({ signing: undefined })).rejects.toThrow("SESSION_SIGNING_KEY is not set");
  });

  it("signs with the new key, verifies tokens of the earlier keys, refuses a retired one", async () => {
    const { signedSession } = await load({
      signing: JSON.stringify(next.privateKey),
      earlier: [former.publicKey],
    });
    const fresh = await signedSession.issue({ userId: "user_1a2b" });

    expect(headerOf(fresh).kid).toBe("2026-10");
    expect((await signedSession.open(fresh)).data).toEqual({ userId: "user_1a2b" });
    expect((await signedSession.open(await issuedBy(former))).data).toEqual({
      userId: "user_1a2b",
    });
    await expect(signedSession.open(await issuedBy(retired))).rejects.toMatchObject({
      code: "ERR_SESSION_TOKEN_INVALID",
      cause: { code: "ERR_JWK_KEY_NOT_FOUND" },
    });
  });

  it("verifies an earlier key of another algorithm by its own alg", async () => {
    const es384 = await generateJWK("ES384", { kid: "2026-07" });
    const { signedSession } = await load({
      signing: JSON.stringify(next.privateKey),
      earlier: [es384.publicKey],
    });

    expect((await signedSession.open(await issuedBy(es384))).data).toEqual({
      userId: "user_1a2b",
    });
  });

  it("without earlier keys, verifies its own tokens alone", async () => {
    const { signedSession } = await load({ signing: JSON.stringify(next.privateKey) });

    expect((await signedSession.open(await signedSession.issue({ userId: "u1" }))).data).toEqual({
      userId: "u1",
    });
    await expect(signedSession.open(await issuedBy(former))).rejects.toMatchObject({
      code: "ERR_SESSION_TOKEN_INVALID",
    });
  });
});
