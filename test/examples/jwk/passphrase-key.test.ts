import { afterEach, describe, expect, it, vi } from "vitest";
import { base64UrlParse } from "unjwt/utils";

const SALT = "Wq3vYB0nH2kR8sLmT5xJ4a";

async function load(env: { passphrase?: string; salt?: string }) {
  vi.resetModules();
  vi.stubEnv("EXPORT_PASSPHRASE", env.passphrase);
  vi.stubEnv("EXPORT_SALT", env.salt);
  return import("../../../examples/jwk/passphrase-key.ts");
}

afterEach(() => {
  vi.unstubAllEnvs();
});

describe("examples/jwk/passphrase-key", () => {
  it("seals and opens a manifest with a key derived once from the passphrase", async () => {
    const { sealManifest, openManifest } = await load({
      passphrase: "orbit-lantern-quarry-velvet",
      salt: SALT,
    });
    const manifest = { accountId: "acct_9f8e", files: ["invoices-2026-09.csv"] };
    const token = await sealManifest(manifest);
    expect(JSON.parse(base64UrlParse(token.split(".")[0]))).toMatchObject({
      alg: "A128KW",
      kid: "exports-2026",
    });
    expect(await openManifest(token)).toMatchObject(manifest);
  });

  it("derives a different key from another passphrase or salt", async () => {
    const original = await load({ passphrase: "orbit-lantern-quarry-velvet", salt: SALT });
    const token = await original.sealManifest({ accountId: "acct_9f8e", files: [] });
    const otherPassphrase = await load({ passphrase: "orbit-lantern-quarry-velvel", salt: SALT });
    await expect(otherPassphrase.openManifest(token)).rejects.toMatchObject({
      code: "ERR_JWE_DECRYPTION_FAILED",
    });
    const otherSalt = await load({ passphrase: "orbit-lantern-quarry-velvet", salt: `${SALT}x` });
    await expect(otherSalt.openManifest(token)).rejects.toMatchObject({
      code: "ERR_JWE_DECRYPTION_FAILED",
    });
  });

  it("stops at start-up when a variable is missing or the salt is short", async () => {
    await expect(load({ salt: SALT })).rejects.toThrow("must be set");
    await expect(
      load({ passphrase: "orbit-lantern-quarry-velvet", salt: "abc" }),
    ).rejects.toMatchObject({
      code: "ERR_INVALID_OPTION",
    });
  });
});
