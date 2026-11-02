import { afterEach, describe, expect, it, vi } from "vitest";
import { generateJWK } from "unjwt/jwk";
import { sign } from "unjwt/jws";
import { env } from "../../../examples/getting-started/create-keys.ts";

async function load(vars: Partial<typeof env> = env) {
  vi.resetModules();
  vi.stubEnv("TOKEN_PRIVATE_JWK", vars.TOKEN_PRIVATE_JWK);
  vi.stubEnv("TOKEN_PUBLIC_JWK", vars.TOKEN_PUBLIC_JWK);
  // A fresh module graph has its own JWTError class, so take the guard from it
  const { isJWTError } = await import("unjwt/error");
  const api = await import("../../../examples/getting-started/api-token.ts");
  return { ...api, isJWTError };
}

function bearer(token: string): Request {
  return new Request("https://api.example.com/invoices", {
    headers: { authorization: `Bearer ${token}` },
  });
}

afterEach(() => {
  vi.unstubAllEnvs();
});

describe("examples/getting-started/api-token", () => {
  it("issues a 15-minute token for the API audience and reads it back", async () => {
    const { issueToken, authenticate } = await load();
    const claims = await authenticate(bearer(await issueToken("client_7f3c", "invoices:read")));
    expect(claims).toMatchObject({
      sub: "client_7f3c",
      aud: "https://api.example.com",
      scope: "invoices:read",
    });
    expect(claims.exp! - claims.iat!).toBe(15 * 60);
  });

  it("throws a JWTError for a missing, foreign, expired or misaddressed token", async () => {
    const { authenticate, isJWTError } = await load();
    const codeOf = async (promise: Promise<unknown>) => {
      const error = await promise.then(
        () => undefined,
        (reason: unknown) => reason,
      );
      return isJWTError(error) ? error.code : undefined;
    };
    const privateKey = JSON.parse(env.TOKEN_PRIVATE_JWK);
    const foreign = await generateJWK("ES256", { kid: "2026-10" });
    const stale = await sign({ sub: "client_7f3c", aud: "https://api.example.com" }, privateKey, {
      expiresIn: "15m",
      currentDate: new Date(Date.now() - 60 * 60 * 1000),
    });
    const elsewhere = await sign(
      { sub: "client_7f3c", aud: "https://billing.example.com" },
      privateKey,
    );

    expect(await codeOf(authenticate(new Request("https://api.example.com/")))).toBe(
      "ERR_JWS_INVALID",
    );
    expect(await codeOf(authenticate(bearer(await sign({ sub: "x" }, foreign.privateKey))))).toBe(
      "ERR_JWS_SIGNATURE_INVALID",
    );
    expect(await codeOf(authenticate(bearer(stale)))).toBe("ERR_JWT_EXPIRED");
    expect(await codeOf(authenticate(bearer(elsewhere)))).toBe("ERR_JWT_CLAIM_INVALID");
  });

  it("fails at start-up when a key is missing", async () => {
    await expect(load({ TOKEN_PUBLIC_JWK: env.TOKEN_PUBLIC_JWK })).rejects.toThrow(
      "TOKEN_PRIVATE_JWK is not set",
    );
    await expect(load({ TOKEN_PRIVATE_JWK: env.TOKEN_PRIVATE_JWK })).rejects.toThrow(
      "TOKEN_PUBLIC_JWK is not set",
    );
  });
});
