import { afterEach, describe, expect, it, vi } from "vitest";
import { exportPEM, generateJWK } from "unjwt/jwk";
import { verify } from "unjwt/jws";

async function load(pem: string | undefined) {
  vi.resetModules();
  vi.stubEnv("SESSION_SIGNING_PEM", pem);
  return import("../../../examples/sessions/pem-signing-key.ts");
}

afterEach(() => {
  vi.unstubAllEnvs();
});

describe("examples/sessions/pem-signing-key", () => {
  it("refuses to load without SESSION_SIGNING_PEM", async () => {
    await expect(load(undefined)).rejects.toThrow("SESSION_SIGNING_PEM is not set");
  });

  it("signs with the key from the PEM; its public half verifies the token", async () => {
    const { privateKey, publicKey } = await generateJWK("ES256");
    const { signedSession } = await load(await exportPEM(privateKey));
    const headers = new Headers();
    const session = await signedSession.use({
      req: new Request("https://app.example.com/"),
      res: { headers },
    });
    await session.update({ userId: "user_1a2b" });
    expect(headers.getSetCookie()[0]?.startsWith("__Host-unjwt-jws=")).toBe(true);

    const { payload, protectedHeader } = await verify(String(session.token), publicKey, {
      algorithms: ["ES256"],
    });
    expect(protectedHeader).toMatchObject({ alg: "ES256", kid: "2026-10", typ: "session+jwt" });
    expect(payload).toMatchObject({ userId: "user_1a2b", jti: session.id });
  });

  it("refuses to load a public key PEM", async () => {
    const { publicKey } = await generateJWK("ES256");
    await expect(load(await exportPEM(publicKey))).rejects.toMatchObject({
      code: "ERR_JWK_INVALID",
    });
  });
});
