import { afterEach, describe, expect, it, vi } from "vitest";
import { generateJWK } from "unjwt/jwk";
import { defineJWESession, defineJWSSession } from "unjwt/session";

async function load(keys: { sealing: unknown[]; signing: unknown[] }) {
  vi.resetModules();
  vi.stubEnv("SESSION_KEYS", JSON.stringify({ keys: keys.sealing }));
  vi.stubEnv("SIGNING_KEYS", JSON.stringify({ keys: keys.signing }));
  return import("../../../examples/sessions/key-rotation.ts");
}

function headerOf(token: string): { alg?: string; kid?: string } {
  const [header = ""] = token.split(".");
  return JSON.parse(atob(header.replaceAll("-", "+").replaceAll("_", "/")));
}

afterEach(() => {
  vi.unstubAllEnvs();
});

describe("examples/sessions/key-rotation", async () => {
  const [sealNew, sealOld, sealGone] = await Promise.all(
    ["2026-10", "2026-09", "2026-08"].map((kid) => generateJWK("A256KW", { kid })),
  );
  const [signNew, signOld, signGone] = await Promise.all([
    generateJWK("HS512", { kid: "2026-10" }),
    generateJWK("HS256", { kid: "2026-09" }),
    generateJWK("HS256", { kid: "2026-08" }),
  ]);

  it("refuses to load without its key sets, or with an empty one", async () => {
    vi.resetModules();
    vi.stubEnv("SESSION_KEYS", undefined);
    await expect(import("../../../examples/sessions/key-rotation.ts")).rejects.toThrow(
      "SESSION_KEYS is not set",
    );
    await expect(load({ sealing: [], signing: [signNew] })).rejects.toThrow(
      "SESSION_KEYS holds no key",
    );
    await expect(load({ sealing: [sealNew], signing: [] })).rejects.toThrow(
      "SIGNING_KEYS holds no key",
    );
  });

  it("refuses to load with ERR_SESSION_KEY_INVALID when the newest key is not an oct JWK", async () => {
    const { privateKey } = await generateJWK("ECDH-ES+A256KW", { kid: "2026-10" });
    await expect(
      load({ sealing: [privateKey, sealOld], signing: [signNew] }),
    ).rejects.toMatchObject({ code: "ERR_SESSION_KEY_INVALID" });
  });

  it("JWE: seals with the newest key, opens tokens of the older ones, refuses retired keys", async () => {
    const { appSession } = await load({ sealing: [sealNew, sealOld], signing: [signNew] });
    const old = await defineJWESession({ key: sealOld, maxAge: "7D" }).issue({ userId: "u1" });
    const gone = await defineJWESession({ key: sealGone, maxAge: "7D" }).issue({ userId: "u2" });

    expect((await appSession.open(old)).data).toEqual({ userId: "u1" });
    const fresh = await appSession.issue({ userId: "u3" });
    expect(headerOf(fresh).kid).toBe("2026-10");
    expect((await appSession.open(fresh)).data).toEqual({ userId: "u3" });
    await expect(appSession.open(gone)).rejects.toMatchObject({
      code: "ERR_SESSION_TOKEN_INVALID",
      cause: { code: "ERR_JWK_KEY_NOT_FOUND" },
    });
  });

  it("a ring that leaves out the key that seals fails every fresh token", async () => {
    const forgetful = defineJWESession({
      key: sealNew,
      maxAge: "7D",
      hooks: { onKeyLookup: () => ({ keys: [sealOld] }) },
    });
    const fresh = await forgetful.issue({ userId: "u1" });

    await expect(forgetful.open(fresh)).rejects.toMatchObject({
      code: "ERR_SESSION_TOKEN_INVALID",
      cause: { code: "ERR_JWK_KEY_NOT_FOUND" },
    });
  });

  it("JWS: signs HS512 with the newest key, verifies the HS256 tokens of the older ones", async () => {
    const { signedSession } = await load({ sealing: [sealNew], signing: [signNew, signOld] });
    const old = await defineJWSSession({ key: signOld, maxAge: "1h" }).issue({ userId: "u1" });
    const gone = await defineJWSSession({ key: signGone, maxAge: "1h" }).issue({ userId: "u2" });

    const read = await signedSession.use({ token: old });
    expect(read.data).toEqual({ userId: "u1" });
    expect(headerOf(await signedSession.issue({ userId: "u3" }))).toMatchObject({
      alg: "HS512",
      kid: "2026-10",
    });
    await expect(signedSession.open(gone)).rejects.toMatchObject({
      code: "ERR_SESSION_TOKEN_INVALID",
      cause: { code: "ERR_JWK_KEY_NOT_FOUND" },
    });
  });

  it("JWS: without algorithms, a token of an older key of another alg is refused", async () => {
    const unlisted = defineJWSSession({
      key: signNew,
      maxAge: "1h",
      hooks: { onKeyLookup: () => ({ keys: [signNew, signOld] }) },
    });
    const old = await defineJWSSession({ key: signOld, maxAge: "1h" }).issue({ userId: "u1" });

    await expect(unlisted.open(old)).rejects.toMatchObject({
      code: "ERR_SESSION_TOKEN_INVALID",
      cause: { code: "ERR_JWS_ALG_NOT_ALLOWED" },
    });
  });
});
