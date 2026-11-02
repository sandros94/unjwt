import { afterEach, describe, expect, it, vi } from "vitest";
import { sign } from "unjwt/jws";
import { generateJWK } from "unjwt/jwk";

const current = await generateJWK("ES256", { kid: "2026-10" });
const previous = await generateJWK("ES256", { kid: "2026-09" });
const stranger = await generateJWK("ES256", { kid: "2026-10" });
const jwks = JSON.stringify({ keys: [current.publicKey, previous.publicKey] });

async function load(value: string | undefined) {
  vi.resetModules();
  vi.stubEnv("ISSUER_JWKS", value);
  return import("../../../examples/jws/verify-with-jwks.ts");
}

afterEach(() => {
  vi.unstubAllEnvs();
});

const claims = {
  iss: "https://auth.example.com",
  aud: "https://api.example.com",
  sub: "user_1a2b",
  scope: "invoices:read",
};
const options = { expiresIn: "15m", protectedHeader: { typ: "at+jwt" } } as const;

function request(token?: string): Request {
  return new Request("https://api.example.com/invoices", {
    headers: token ? { authorization: `Bearer ${token}` } : {},
  });
}

describe("examples/jws/verify-with-jwks", () => {
  it("accepts tokens from the current and the previous key", async () => {
    const { authenticate } = await load(jwks);
    for (const key of [current.privateKey, previous.privateKey]) {
      const payload = await authenticate(request(await sign(claims, key, options)));
      expect(payload).toMatchObject({ sub: "user_1a2b", scope: "invoices:read" });
    }
  });

  it("returns null for a missing header and for every refused token", async () => {
    const { authenticate } = await load(jwks);
    const refused = [
      undefined,
      "not-a-token",
      await sign(claims, stranger.privateKey, options),
      await sign(claims, current.privateKey, { expiresIn: "15m" }),
      await sign({ ...claims, aud: "https://billing.example.com" }, current.privateKey, options),
      await sign(claims, current.privateKey, { protectedHeader: { typ: "at+jwt" } }),
      await sign(claims, current.privateKey, {
        ...options,
        currentDate: new Date(Date.now() - 3_600_000),
      }),
    ];
    for (const token of refused) expect(await authenticate(request(token))).toBeNull();
  });

  it("fails at start-up without a JWK Set", async () => {
    await expect(load(undefined)).rejects.toThrow("ISSUER_JWKS is not set");
    await expect(load(JSON.stringify(current.publicKey))).rejects.toThrow("must be a JWK Set");
  });
});
