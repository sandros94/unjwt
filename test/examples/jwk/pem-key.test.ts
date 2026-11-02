import { afterEach, describe, expect, it, vi } from "vitest";
import { exportPEM, generateJWK } from "unjwt/jwk";
import { verify } from "unjwt/jws";

async function load(value: string | undefined) {
  vi.resetModules();
  vi.stubEnv("SIGNING_KEY_PEM", value);
  return import("../../../examples/jwk/pem-key.ts");
}

afterEach(() => {
  vi.unstubAllEnvs();
});

describe("examples/jwk/pem-key", () => {
  it("signs with a PKCS#8 key and names it in the header", async () => {
    const { privateKey, publicKey } = await generateJWK("RS256");
    const { issueToken } = await load(await exportPEM(privateKey));
    const token = await issueToken("user_1a2b");
    const { payload, protectedHeader } = await verify(token, publicKey);
    expect(payload.sub).toBe("user_1a2b");
    expect(protectedHeader).toMatchObject({ alg: "RS256", kid: "2026-10" });
    expect(payload.exp).toBe((payload.iat as number) + 15 * 60);
  });

  it("stops at start-up when the variable is missing", async () => {
    await expect(load(undefined)).rejects.toThrow("SIGNING_KEY_PEM is not set");
  });

  it("refuses a public key, a legacy label and a key of another type", async () => {
    const rsa = await generateJWK("RS256");
    await expect(load(await exportPEM(rsa.publicKey))).rejects.toMatchObject({
      code: "ERR_JWK_INVALID",
    });
    const legacy = (await exportPEM(rsa.privateKey)).replaceAll("PRIVATE KEY", "RSA PRIVATE KEY");
    await expect(load(legacy)).rejects.toMatchObject({ code: "ERR_JWK_INVALID" });
    const ec = await generateJWK("ES256");
    await expect(load(await exportPEM(ec.privateKey))).rejects.toMatchObject({
      code: "ERR_JWK_INVALID",
    });
  });
});
