import { describe, expect, it } from "vitest";
import { decrypt } from "unjwt/jwe";
import { generateJWK } from "unjwt/jwk";
import { isJWTError } from "unjwt/error";
import { issueSealedGrant, openSealedGrant } from "../../../examples/jwe/nested-token.ts";

const issuer = await generateJWK("ES256", { kid: "issuer-2026-10" });
const recipient = await generateJWK("ECDH-ES+A256KW", { kid: "partner-2026-10" });
const grant = { sub: "user_1a2b", plan: "pro" };

describe("examples/jwe/nested-token", () => {
  it("signs, encrypts, then decrypts and verifies", async () => {
    const token = await issueSealedGrant(grant, {
      issuer: issuer.privateKey,
      recipient: recipient.publicKey,
    });
    const outer = await decrypt(token, recipient.privateKey, { payload: "string" });
    expect(outer.protectedHeader.cty).toBe("JWT");
    expect(outer.protectedHeader.typ).toBeUndefined();
    expect(outer.payload.split(".")).toHaveLength(3);

    const opened = await openSealedGrant(token, {
      recipient: recipient.privateKey,
      issuer: issuer.publicKey,
    });
    expect(opened).toMatchObject(grant);
  });

  it('needs payload: "string" to read the inner token', async () => {
    const token = await issueSealedGrant(grant, {
      issuer: issuer.privateKey,
      recipient: recipient.publicKey,
    });
    const error = await decrypt(token, recipient.privateKey).catch((e: unknown) => e);
    expect(isJWTError(error, "ERR_JWE_INVALID")).toBe(true);
  });

  it("refuses an inner token from another issuer", async () => {
    const forger = await generateJWK("ES256", { kid: "issuer-2026-10" });
    const token = await issueSealedGrant(grant, {
      issuer: forger.privateKey,
      recipient: recipient.publicKey,
    });
    const error = await openSealedGrant(token, {
      recipient: recipient.privateKey,
      issuer: issuer.publicKey,
    }).catch((e: unknown) => e);
    expect(isJWTError(error, "ERR_JWS_SIGNATURE_INVALID")).toBe(true);
  });
});
