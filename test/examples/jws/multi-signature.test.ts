import { describe, expect, it } from "vitest";
import { signMulti, verifyMulti } from "unjwt/jws";
import { generateJWK } from "unjwt/jwk";
import { isJWTError } from "unjwt/error";
import {
  isFullySigned,
  notarized,
  signContract,
  signers,
  type Contract,
} from "../../../examples/jws/multi-signature.ts";

const contract: Contract = { contractId: "ctr_2041", customer: "cus_88f1", total: 1200 };

describe("examples/jws/multi-signature", () => {
  it("signs one payload twice and reports it fully signed", async () => {
    const jws = await signContract(contract);
    expect(jws.signatures).toHaveLength(2);
    expect(await isFullySigned(jws)).toBe(true);
    expect(await notarized(jws)).toMatchObject(contract);
  });

  it("is not fully signed once a signature is dropped or the payload changes", async () => {
    const jws = await signContract(contract);
    expect(await isFullySigned({ ...jws, signatures: [jws.signatures[0]] })).toBe(false);
    const tampered = { ...jws, payload: jws.payload.replace(/.$/, "A") };
    expect(await isFullySigned(tampered)).toBe(false);
  });

  it("does not count a duplicated signature twice", async () => {
    const jws = await signContract(contract);
    const duplicated = { ...jws, signatures: [jws.signatures[0], jws.signatures[0]] };
    expect(await isFullySigned(duplicated)).toBe(false);
  });

  it("verifyMulti accepts any one signature the key verifies", async () => {
    const jws = await signContract(contract);
    const { signerIndex } = await verifyMulti(jws, signers);
    expect(signerIndex).toBe(0);
    const outsider = await generateJWK("ES256", { kid: "outsider" });
    const error = await verifyMulti(jws, { keys: [outsider.publicKey] }).catch((e: unknown) => e);
    expect(isJWTError(error, "ERR_JWS_SIGNATURE_INVALID")).toBe(true);
    const causes = (error as Error).cause as unknown[];
    expect(causes.map((cause) => isJWTError(cause) && cause.code)).toEqual([
      "ERR_JWK_KEY_NOT_FOUND",
      "ERR_JWS_ALG_NOT_ALLOWED",
    ]);
  });

  it("spends one key-attempt budget across every signature", async () => {
    const jws = await signContract(contract);
    expect((await verifyMulti(jws, signers, { limits: { keyAttempts: 1 } })).signerIndex).toBe(0);

    const kidless = async () => {
      const { privateKey, publicKey } = await generateJWK("ES256", { kid: false });
      return { privateKey, publicKey };
    };
    const parties = await Promise.all(Array.from({ length: 9 }, kidless));
    const strangers = await Promise.all(Array.from({ length: 2 }, kidless));
    const crowded = await signMulti(
      contract,
      parties.map((party) => ({ key: party.privateKey })),
    );
    const error = await verifyMulti(crowded, {
      keys: strangers.map((stranger) => stranger.publicKey),
    }).catch((e: unknown) => e);
    expect(isJWTError(error, "ERR_JWK_KEY_NOT_FOUND")).toBe(true);
    expect((error as Error).message).toContain("limits.keyAttempts");
  });
});
