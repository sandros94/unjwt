import { afterEach, describe, expect, it, vi } from "vitest";
import { generateJWK } from "unjwt/jwk";
import { defineJWESession, defineJWSSession } from "unjwt/session";

async function load(keys: { sealing: unknown[]; signing: unknown[] }) {
  vi.resetModules();
  vi.stubEnv("SESSION_KEYS", JSON.stringify({ keys: keys.sealing }));
  vi.stubEnv("SIGNING_KEYS", JSON.stringify({ keys: keys.signing }));
  return import("../../../examples/sessions/key-rotation.ts");
}

function headerOf(token: string): { kid?: string } {
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
  const [signNew, signOld, signGone] = await Promise.all(
    ["2026-10", "2026-09", "2026-08"].map((kid) => generateJWK("HS256", { kid })),
  );

  it("refuses to load without its key sets, or with an empty one", async () => {
    vi.resetModules();
    vi.stubEnv("SESSION_KEYS", undefined);
    await expect(import("../../../examples/sessions/key-rotation.ts")).rejects.toThrow(
      "SESSION_KEYS is not set",
    );
    await expect(load({ sealing: [], signing: [signNew] })).rejects.toThrow(
      "SESSION_KEYS holds no key",
    );
  });

  it("JWE: seals with the first key, opens tokens of the older ones, refuses retired keys", async () => {
    const { appSession } = await load({ sealing: [sealNew, sealOld], signing: [signNew] });
    const old = await defineJWESession({ key: sealOld, maxAge: "7D" }).issue({ userId: "u1" });
    const gone = await defineJWESession({ key: sealGone, maxAge: "7D" }).issue({ userId: "u2" });

    expect((await appSession.open(old)).data).toEqual({ userId: "u1" });
    expect(headerOf(await appSession.issue({ userId: "u3" })).kid).toBe("2026-10");
    await expect(appSession.open(gone)).rejects.toMatchObject({
      code: "ERR_SESSION_TOKEN_INVALID",
    });
  });

  it("JWS: signs with the first key, verifies every key in the set", async () => {
    const { signedSession } = await load({ sealing: [sealNew], signing: [signNew, signOld] });
    const old = await defineJWSSession({ key: signOld, maxAge: "1h" }).issue({ userId: "u1" });
    const gone = await defineJWSSession({ key: signGone, maxAge: "1h" }).issue({ userId: "u2" });

    const read = await signedSession.use({ token: old });
    expect(read.data).toEqual({ userId: "u1" });
    expect(headerOf(await signedSession.issue({ userId: "u3" })).kid).toBe("2026-10");
    await expect(signedSession.open(gone)).rejects.toMatchObject({
      code: "ERR_SESSION_TOKEN_INVALID",
      cause: { code: "ERR_JWK_KEY_NOT_FOUND" },
    });
  });
});
