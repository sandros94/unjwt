import { afterEach, describe, expect, it, vi } from "vitest";
import { generateJWK } from "unjwt/jwk";
import { sign, verify } from "unjwt/jws";

async function load(value: string | undefined) {
  vi.resetModules();
  vi.stubEnv("SIGNING_KEY", value);
  return import("../../../examples/jwk/signing-key.ts");
}

afterEach(() => {
  vi.unstubAllEnvs();
});

describe("examples/jwk/signing-key", () => {
  it("loads a stored private JWK that signs tokens its public half verifies", async () => {
    const { privateKey, publicKey } = await generateJWK("ES256", { kid: "2026-10" });
    const { signingKey } = await load(JSON.stringify(privateKey));
    const token = await sign({ sub: "user_1a2b" }, signingKey);
    const { payload, protectedHeader } = await verify(token, publicKey);
    expect(payload.sub).toBe("user_1a2b");
    expect(protectedHeader.kid).toBe("2026-10");
  });

  it("stops at start-up when the variable is missing", async () => {
    await expect(load(undefined)).rejects.toThrow("SIGNING_KEY is not set");
  });

  it("stops at start-up when the variable holds the public half or another algorithm's key", async () => {
    const { publicKey } = await generateJWK("ES256");
    await expect(load(JSON.stringify(publicKey))).rejects.toMatchObject({
      code: "ERR_JWK_INVALID",
    });
    const rsa = await generateJWK("RS256");
    await expect(load(JSON.stringify(rsa.privateKey))).rejects.toMatchObject({
      code: "ERR_JWK_INVALID",
    });
  });
});
