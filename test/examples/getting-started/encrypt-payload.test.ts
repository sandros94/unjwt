import { describe, expect, it } from "vitest";
import { isJWTError } from "unjwt/error";
import { encrypt } from "unjwt/jwe";
import { generateJWK } from "unjwt/jwk";
import { openInvoice, sealInvoice } from "../../../examples/getting-started/encrypt-payload.ts";

const invoice = { id: "inv_2026_0042", iban: "DE89370400440532013000" };

describe("examples/getting-started/encrypt-payload", () => {
  it("seals an invoice that only the billing key opens", async () => {
    const token = await sealInvoice(invoice);
    expect(token.split(".")).toHaveLength(5);
    expect(token).not.toContain(btoa(invoice.iban));
    expect(await openInvoice(token)).toMatchObject(invoice);
  });

  it("refuses a token sealed for another key", async () => {
    const other = await generateJWK("ECDH-ES+A256KW", { kid: "billing-2026-10" });
    const token = await encrypt(invoice, other.publicKey);
    const error = await openInvoice(token).catch((reason: unknown) => reason);
    expect(isJWTError(error, "ERR_JWE_DECRYPTION_FAILED")).toBe(true);
  });
});
