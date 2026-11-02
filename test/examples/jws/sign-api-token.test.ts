import { afterEach, describe, expect, it, vi } from "vitest";
import { verify } from "unjwt/jws";
import { generateJWK } from "unjwt/jwk";
import { isJWTError } from "unjwt/error";
import { base64UrlParse } from "unjwt/utils";

const issuer = await generateJWK("ES256", { kid: "2026-10" });

async function load(value: string | undefined) {
  vi.resetModules();
  vi.stubEnv("TOKEN_SIGNING_KEY", value);
  return import("../../../examples/jws/sign-api-token.ts");
}

afterEach(() => {
  vi.unstubAllEnvs();
});

describe("examples/jws/sign-api-token", () => {
  it("issues a 15-minute access token any holder of the public key can verify", async () => {
    const { issueAccessToken } = await load(JSON.stringify(issuer.privateKey));
    const token = await issueAccessToken("user_1a2b", ["invoices:read", "invoices:write"]);
    expect(token.split(".")).toHaveLength(3);

    const { payload, protectedHeader } = await verify(token, issuer.publicKey, {
      typ: "at+jwt",
      issuer: "https://auth.example.com",
      audience: "https://api.example.com",
    });
    expect(protectedHeader).toEqual({ kid: "2026-10", alg: "ES256", typ: "at+jwt" });
    expect(payload).toMatchObject({ sub: "user_1a2b", scope: "invoices:read invoices:write" });
    expect(payload.exp! - payload.iat!).toBe(15 * 60);
  });

  it("keeps the claims readable without any key", async () => {
    const { issueAccessToken } = await load(JSON.stringify(issuer.privateKey));
    const token = await issueAccessToken("user_1a2b", []);
    const claims = JSON.parse(base64UrlParse(token.split(".")[1]));
    expect(claims.sub).toBe("user_1a2b");
  });

  it("fails at start-up without a key, or with a public one", async () => {
    await expect(load(undefined)).rejects.toThrow("TOKEN_SIGNING_KEY is not set");
    await expect(load(JSON.stringify(issuer.publicKey))).rejects.toThrow("must be a private JWK");
  });

  it("refuses a token signed by another issuer", async () => {
    const { issueAccessToken } = await load(JSON.stringify(issuer.privateKey));
    const other = await generateJWK("ES256", { kid: "2026-10" });
    const error = await verify(await issueAccessToken("user_1a2b", []), other.publicKey).catch(
      (e: unknown) => e,
    );
    expect(isJWTError(error, "ERR_JWS_SIGNATURE_INVALID")).toBe(true);
  });
});
