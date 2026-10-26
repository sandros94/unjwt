import { afterEach, describe, expect, it, vi } from "vitest";
import { generateJWK } from "unjwt/jwk";
import { sign } from "unjwt/jws";

async function load(value: string | undefined) {
  vi.resetModules();
  vi.stubEnv("SIGNING_KEY", value);
  return import("../../../examples/jwk/public-half.ts");
}

afterEach(() => {
  vi.unstubAllEnvs();
});

describe("examples/jwk/public-half", () => {
  it("derives the pair's public half from the stored private JWK", async () => {
    const { privateKey, publicKey } = await generateJWK("ES256", { kid: "2026-10" });
    const { verifyKey, readToken } = await load(JSON.stringify(privateKey));
    expect(verifyKey).toEqual(publicKey);
    expect(verifyKey).not.toHaveProperty("d");
    const token = await sign({ sub: "user_1a2b" }, privateKey);
    expect((await readToken(token)).sub).toBe("user_1a2b");
  });

  it("refuses a token signed by a different key", async () => {
    const { privateKey } = await generateJWK("ES256", { kid: "2026-10" });
    const stranger = await generateJWK("ES256", { kid: "2026-10" });
    const { readToken } = await load(JSON.stringify(privateKey));
    const forged = await sign({ sub: "user_1a2b" }, stranger.privateKey);
    await expect(readToken(forged)).rejects.toMatchObject({ code: "ERR_JWS_SIGNATURE_INVALID" });
  });
});
