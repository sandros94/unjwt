import { afterEach, describe, expect, it, vi } from "vitest";
import { encrypt } from "unjwt/jwe";
import { generateJWK } from "unjwt/jwk";

const current = await generateJWK("ECDH-ES+A256KW", { kid: "2026-10" });
const previous = await generateJWK("ECDH-ES+A256KW", { kid: "2026-09" });
const retired = await generateJWK("ECDH-ES+A256KW", { kid: "2026-08" });
const keyring = JSON.stringify({ keys: [current.privateKey, previous.privateKey] });
const record = { customerId: "cus_88f1", email: "ada@example.com", country: "IT" };

async function load(value: string | undefined) {
  vi.resetModules();
  vi.stubEnv("REPORTS_DECRYPTION_KEYS", value);
  return import("../../../examples/jwe/decrypt-with-keyring.ts");
}

afterEach(() => {
  vi.unstubAllEnvs();
});

/** The `code` of the rejection; the example loads its own copy of the library, so `instanceof` does not apply. */
async function codeOf(promise: Promise<unknown>): Promise<unknown> {
  const error = await promise.then(
    () => undefined,
    (e: unknown) => e,
  );
  return error instanceof Error && "code" in error ? error.code : undefined;
}

describe("examples/jwe/decrypt-with-keyring", () => {
  it("opens records sealed for the current or the previous key", async () => {
    const { openCustomer } = await load(keyring);
    for (const key of [current.publicKey, previous.publicKey]) {
      const token = await encrypt(record, key, { expiresIn: "10m" });
      expect(await openCustomer(token)).toMatchObject(record);
    }
  });

  it("refuses a retired kid, another algorithm, a missing exp and an expired record", async () => {
    const { openCustomer } = await load(keyring);
    expect(await codeOf(openCustomer(await encrypt(record, retired.publicKey)))).toBe(
      "ERR_JWK_KEY_NOT_FOUND",
    );
    const rsa = await generateJWK("RSA-OAEP-256", { kid: "2026-10" });
    expect(await codeOf(openCustomer(await encrypt(record, rsa.publicKey)))).toBe(
      "ERR_JWE_ALG_NOT_ALLOWED",
    );
    expect(
      await codeOf(openCustomer(await encrypt(record, current.publicKey, { enc: "A128GCM" }))),
    ).toBe("ERR_JWE_ALG_NOT_ALLOWED");
    expect(await codeOf(openCustomer(await encrypt(record, current.publicKey)))).toBe(
      "ERR_JWT_CLAIM_MISSING",
    );
    const stale = await encrypt(record, current.publicKey, {
      expiresIn: "10m",
      currentDate: new Date(Date.now() - 3_600_000),
    });
    expect(await codeOf(openCustomer(stale))).toBe("ERR_JWT_EXPIRED");
  });

  it("fails at start-up without a keyring", async () => {
    await expect(load(undefined)).rejects.toThrow("REPORTS_DECRYPTION_KEYS is not set");
    await expect(load(JSON.stringify(current.privateKey))).rejects.toThrow("must be a JWK Set");
  });
});
