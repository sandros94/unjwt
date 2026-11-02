import { afterEach, describe, expect, it, vi } from "vitest";
import { generateJWK } from "unjwt/jwk";
import { sign, verify } from "unjwt/jws";

async function load(value: string | undefined) {
  vi.resetModules();
  vi.stubEnv("MASTER_KEY", value);
  return import("../../../examples/jwk/tenant-keys.ts");
}

afterEach(() => {
  vi.unstubAllEnvs();
});

describe("examples/jwk/tenant-keys", () => {
  it("seals a tenant key and opens it back to a key that verifies its tokens", async () => {
    const { sealTenantKey, openTenantKey } = await load(
      JSON.stringify(await generateJWK("A256KW")),
    );
    const tenantKey = await generateJWK("HS256", { kid: "tenant_1a2b" });
    const sealed = await sealTenantKey(tenantKey);
    expect(sealed.kid).toBe("tenant_1a2b");
    expect(sealed.wrapped).not.toContain(tenantKey.k);
    const opened = await openTenantKey(sealed);
    expect(opened).toEqual({ kty: "oct", k: tenantKey.k, alg: "HS256", kid: "tenant_1a2b" });
    const token = await sign({ sub: "user_1a2b" }, tenantKey);
    expect((await verify(token, opened)).payload.sub).toBe("user_1a2b");
  });

  it("fails to open a key under another master key, or a tampered one", async () => {
    const first = await load(JSON.stringify(await generateJWK("A256KW")));
    const sealed = await first.sealTenantKey(await generateJWK("HS256", { kid: "tenant_1a2b" }));
    const second = await load(JSON.stringify(await generateJWK("A256KW")));
    await expect(second.openTenantKey(sealed)).rejects.toMatchObject({
      code: "ERR_JWE_DECRYPTION_FAILED",
    });
    const flipped = `${sealed.wrapped[0] === "A" ? "B" : "A"}${sealed.wrapped.slice(1)}`;
    await expect(first.openTenantKey({ ...sealed, wrapped: flipped })).rejects.toMatchObject({
      code: "ERR_JWE_DECRYPTION_FAILED",
    });
  });

  it("stops at start-up when the master key is missing", async () => {
    await expect(load(undefined)).rejects.toThrow("MASTER_KEY is not set");
  });
});
