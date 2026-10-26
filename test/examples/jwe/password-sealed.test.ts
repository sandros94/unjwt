import { describe, expect, it } from "vitest";
import { encrypt } from "unjwt/jwe";
import { isJWTError } from "unjwt/error";
import { base64UrlParse } from "unjwt/utils";
import { openBackup, sealBackup } from "../../../examples/jwe/password-sealed.ts";

const file = new TextEncoder().encode("invoice_2041,1200.00,EUR\n");
const passphrase = "orbit-lantern-quarry-velvet";

describe("examples/jwe/password-sealed", () => {
  it("round-trips the bytes with the passphrase", async () => {
    const token = await sealBackup(file, passphrase);
    const header = JSON.parse(base64UrlParse(token.split(".")[0]));
    expect(header).toMatchObject({ alg: "PBES2-HS512+A256KW", enc: "A256GCM", p2c: 600_000 });
    expect(header.typ).toBeUndefined();
    expect(base64UrlParse(header.p2s, { returnAs: "uint8array" })).toHaveLength(16);
    expect(await openBackup(token, passphrase)).toEqual(file);
  }, 20_000);

  it("refuses a wrong passphrase and a token asking for more iterations", async () => {
    const token = await sealBackup(file, passphrase);
    const wrong = await openBackup(token, "orbit-lantern-quarry").catch((e: unknown) => e);
    expect(isJWTError(wrong, "ERR_JWE_DECRYPTION_FAILED")).toBe(true);

    const cheaper = await encrypt(file, passphrase, { alg: "PBES2-HS256+A128KW", p2c: 1000 });
    const otherAlg = await openBackup(cheaper, passphrase).catch((e: unknown) => e);
    expect(isJWTError(otherAlg, "ERR_JWE_ALG_NOT_ALLOWED")).toBe(true);
  }, 20_000);
});
