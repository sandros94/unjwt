import { afterEach, describe, expect, it, vi } from "vitest";
import { generateJWK } from "unjwt/jwk";
import { sign } from "unjwt/jws";
import { env } from "../../../examples/getting-started/create-keys.ts";

async function load() {
  vi.resetModules();
  vi.stubEnv("TOKEN_PRIVATE_JWK", env.TOKEN_PRIVATE_JWK);
  vi.stubEnv("TOKEN_PUBLIC_JWK", env.TOKEN_PUBLIC_JWK);
  const api = await import("../../../examples/getting-started/api-token.ts");
  const errors = await import("../../../examples/getting-started/handle-errors.ts");
  return { ...api, ...errors };
}

function bearer(token: string): Request {
  return new Request("https://api.example.com/invoices", {
    headers: { authorization: `Bearer ${token}` },
  });
}

afterEach(() => {
  vi.unstubAllEnvs();
});

describe("examples/getting-started/handle-errors", () => {
  it("serves a valid token", async () => {
    const { issueToken, listInvoices } = await load();
    const response = await listInvoices(bearer(await issueToken("client_7f3c", "invoices:read")));
    expect(response.status).toBe(200);
    expect(await response.json()).toEqual({ client: "client_7f3c", invoices: [] });
  });

  it("answers an expired token with 401 and says so", async () => {
    const { listInvoices } = await load();
    const stale = await sign(
      { sub: "client_7f3c", aud: "https://api.example.com" },
      JSON.parse(env.TOKEN_PRIVATE_JWK),
      { expiresIn: "15m", currentDate: new Date(Date.now() - 60 * 60 * 1000) },
    );
    const response = await listInvoices(bearer(stale));
    expect(response.status).toBe(401);
    expect(response.headers.get("www-authenticate")).toBe(
      'Bearer error="invalid_token", error_description="expired"',
    );
  });

  it("answers a forged, missing or malformed token with 401", async () => {
    const { listInvoices } = await load();
    const forger = await generateJWK("ES256", { kid: "2026-10" });
    const forged = await sign(
      { sub: "client_7f3c", aud: "https://api.example.com" },
      forger.privateKey,
    );
    for (const request of [
      bearer(forged),
      bearer("not-a-token"),
      new Request("https://api.example.com/invoices"),
    ]) {
      const response = await listInvoices(request);
      expect(response.status).toBe(401);
      expect(response.headers.get("www-authenticate")).toBe('Bearer error="invalid_token"');
    }
  });

  it("rethrows an error that is not about the token", async () => {
    const { listInvoices } = await load();
    const request = bearer("x.y.z");
    vi.spyOn(request.headers, "get").mockImplementation(() => {
      throw new TypeError("headers unavailable");
    });
    await expect(listInvoices(request)).rejects.toThrow(TypeError);
  });
});
