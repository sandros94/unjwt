import { describe, expect, it } from "vitest";
import { decrypt } from "unjwt/jwe";
import { generateJWK } from "unjwt/jwk";
import { isJWTError } from "unjwt/error";
import { base64UrlParse } from "unjwt/utils";
import { sealCustomer, type CustomerRecord } from "../../../examples/jwe/encrypt-for-recipient.ts";

const reports = await generateJWK("ECDH-ES+A256KW", { kid: "reports-2026-10" });
const record: CustomerRecord = { customerId: "cus_88f1", email: "ada@example.com", country: "IT" };

describe("examples/jwe/encrypt-for-recipient", () => {
  it("seals a record only the private key opens", async () => {
    const token = await sealCustomer(record, reports.publicKey);
    expect(token.split(".")).toHaveLength(5);
    const header = JSON.parse(base64UrlParse(token.split(".")[0]));
    expect(header).toMatchObject({
      kid: "reports-2026-10",
      alg: "ECDH-ES+A256KW",
      enc: "A256GCM",
      typ: "JWT",
      epk: { kty: "EC", crv: "P-256" },
    });
    expect(token).not.toContain(btoa("ada@example.com").slice(0, 8));

    const { payload } = await decrypt(token, reports.privateKey);
    expect(payload).toMatchObject(record);
    expect(payload.exp! - payload.iat!).toBe(600);
  });

  it("refuses the private half as an encryption key", async () => {
    const error = await sealCustomer(record, reports.privateKey as never).catch((e: unknown) => e);
    expect(isJWTError(error, "ERR_JWK_INVALID")).toBe(true);
  });

  it("does not open with another key", async () => {
    const token = await sealCustomer(record, reports.publicKey);
    const other = await generateJWK("ECDH-ES+A256KW", { kid: "reports-2026-10" });
    const error = await decrypt(token, other.privateKey).catch((e: unknown) => e);
    expect(isJWTError(error, "ERR_JWE_DECRYPTION_FAILED")).toBe(true);
  });
});
