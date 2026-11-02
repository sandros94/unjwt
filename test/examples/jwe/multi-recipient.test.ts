import { describe, expect, it } from "vitest";
import { decryptMulti, encryptMulti, generalToFlattened } from "unjwt/jwe";
import { generateJWK } from "unjwt/jwk";
import { isJWTError } from "unjwt/error";
import { base64UrlParse } from "unjwt/utils";
import {
  readIncident,
  sealIncident,
  type IncidentReport,
} from "../../../examples/jwe/multi-recipient.ts";

const security = await generateJWK("ECDH-ES+A256KW", { kid: "security-2026-10" });
const legal = await generateJWK("RSA-OAEP-256", { kid: "legal-2026-10" });
const archive = await generateJWK("A256KW", { kid: "archive-2026" });
const recipients = { security: security.publicKey, legal: legal.publicKey, archive };
const report: IncidentReport = { incidentId: "inc_3107", summary: "Leaked API token rotated" };

describe("examples/jwe/multi-recipient", () => {
  it("lets every recipient open the same ciphertext with its own key", async () => {
    const sealed = await sealIncident(report, recipients);
    expect(sealed.recipients).toHaveLength(3);
    expect(JSON.parse(base64UrlParse(sealed.protected!))).toEqual({ enc: "A256GCM", typ: "JWT" });
    expect(sealed.recipients.map((r) => r.header?.alg)).toEqual([
      "ECDH-ES+A256KW",
      "RSA-OAEP-256",
      "A256KW",
    ]);
    expect(sealed.recipients[2].header).toMatchObject({
      "x-retention": "7y",
      "kid": "archive-2026",
    });
    for (const key of [security.privateKey, legal.privateKey, archive]) {
      expect(await readIncident(sealed, key)).toMatchObject(report);
    }
    const { recipientIndex, recipientHeader } = await decryptMulti(sealed, legal.privateKey);
    expect(recipientIndex).toBe(1);
    expect(recipientHeader?.alg).toBe("RSA-OAEP-256");
  });

  it("binds the aad: changing it breaks every recipient", async () => {
    const sealed = await sealIncident(report, recipients);
    const moved = { ...sealed, aad: "aW5jaWRlbnQ6aW5jXzMxMDg" };
    const error = await readIncident(moved, archive).catch((e: unknown) => e);
    expect(isJWTError(error, "ERR_JWE_DECRYPTION_FAILED")).toBe(true);
  });

  it("refuses dir and bare ECDH-ES recipients", async () => {
    const cek = await generateJWK("A256GCM");
    const direct = await encryptMulti(report, [{ key: cek }]).catch((e: unknown) => e);
    expect(isJWTError(direct, "ERR_JWE_ALG_FORBIDDEN_IN_MULTI")).toBe(true);
    const bare = await generateJWK("ECDH-ES");
    const agreed = await encryptMulti(report, [{ key: bare.publicKey }]).catch((e: unknown) => e);
    expect(isJWTError(agreed, "ERR_JWE_ALG_FORBIDDEN_IN_MULTI")).toBe(true);
  });

  it("flattens a one-recipient object and refuses three", async () => {
    const one = await encryptMulti(report, [{ key: archive }]);
    const flat = generalToFlattened(one);
    expect((await decryptMulti(flat, archive)).recipientIndex).toBe(0);
    const three = await sealIncident(report, recipients);
    expect(() => generalToFlattened(three)).toThrow("exactly one recipient");
  });

  it("reports each recipient's failure when none of several opens", async () => {
    const sealed = await sealIncident(report, recipients);
    const otherKey = await generateJWK("A256KW", { kid: "archive-2025" });
    const error = await decryptMulti(sealed, { keys: [otherKey] }).catch((e: unknown) => e);
    expect(isJWTError(error, "ERR_JWE_DECRYPTION_FAILED")).toBe(true);
    const causes = (error as Error).cause as unknown[];
    expect(causes.map((cause) => isJWTError(cause) && cause.code)).toEqual([
      "ERR_JWE_ALG_NOT_ALLOWED",
      "ERR_JWE_ALG_NOT_ALLOWED",
      "ERR_JWK_KEY_NOT_FOUND",
    ]);
  });

  it("throws a lone recipient's own error, as decrypt does", async () => {
    const one = await encryptMulti(report, [{ key: archive }]);
    const error = await decryptMulti(one, legal.privateKey).catch((e: unknown) => e);
    expect(isJWTError(error, "ERR_JWE_ALG_NOT_ALLOWED")).toBe(true);
    expect((error as Error).cause).toBeUndefined();
  });

  it("under strictRecipientMatch, refuses a key that fits no recipient without trying it", async () => {
    const sealed = await sealIncident(report, recipients);
    const x25519 = await generateJWK("ECDH-ES+A256KW", { namedCurve: "X25519", kid: false });
    const { alg: _alg, ...anyEcdh } = x25519.privateKey;
    const error = await decryptMulti(sealed, anyEcdh, {
      strictRecipientMatch: true,
      algorithms: ["ECDH-ES+A256KW"],
    }).catch((e: unknown) => e);
    expect(isJWTError(error, "ERR_JWE_NO_MATCHING_RECIPIENT")).toBe(true);
  });
});
