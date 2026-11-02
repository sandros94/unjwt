import { describe, expect, it } from "vitest";
import { isJWTError } from "unjwt/error";
import { generateJWK, type JWK } from "unjwt/jwk";
import { DEFAULT_JOSE_LIMITS, sign, signMulti, verify } from "unjwt/jws";
import { isApproved, readPartnerToken } from "../../../examples/safety/limits.ts";

async function codeOf(promise: Promise<unknown>): Promise<string | undefined> {
  const error = await promise.then(
    () => undefined,
    (e: unknown) => e,
  );
  return isJWTError(error) ? error.code : undefined;
}

const pairs = await Promise.all(
  Array.from({ length: 12 }, () => generateJWK("ES256", { kid: false })),
);
const partnerKeys = { keys: pairs.map((pair) => pair.publicKey as JWK) };
const token = await sign(
  { iss: "https://partner.example.com", sub: "order_9f8e" },
  pairs[11].privateKey,
  {
    alg: "ES256",
  },
);

describe("examples/safety/limits", () => {
  it("has the documented defaults", () => {
    expect(DEFAULT_JOSE_LIMITS).toEqual({
      signatures: 16,
      recipients: 16,
      keyCandidates: 8,
      keyAttempts: 16,
      pbes2Iterations: 2_400_000,
    });
  });

  it("reads a token against all 12 partner keys", async () => {
    expect((await readPartnerToken(token, partnerKeys)).sub).toBe("order_9f8e");
  });

  it("refuses the same set at the default bound", async () => {
    expect(await codeOf(verify(token, partnerKeys, { algorithms: ["ES256"] }))).toBe(
      "ERR_JWK_KEY_NOT_FOUND",
    );
  });

  it("refuses a malformed limit", async () => {
    expect(
      await codeOf(
        verify(token, partnerKeys, { algorithms: ["ES256"], limits: { keyCandidates: 0 } }),
      ),
    ).toBe("ERR_INVALID_OPTION");
  });

  it("approves a release with 20 signatures once 3 verify", async () => {
    const maintainers = await Promise.all(
      Array.from({ length: 20 }, (_, i) => generateJWK("Ed25519", { kid: `maintainer-${i}` })),
    );
    const keys = { keys: maintainers.map((pair) => pair.publicKey as JWK) };
    const outsider = await generateJWK("Ed25519", { kid: "maintainer-0" });
    const all = await signMulti(
      { release: "2.4.0" },
      maintainers.map((pair) => ({ key: pair.privateKey })),
    );
    expect(await isApproved(all, keys)).toBe(true);
    const forged = await signMulti({ release: "2.4.0" }, [
      { key: outsider.privateKey },
      { key: maintainers[1].privateKey },
    ]);
    expect(await isApproved(forged, keys)).toBe(false);
  });

  it("refuses more than 24 signatures", async () => {
    const pair = await generateJWK("Ed25519", { kid: "maintainer-0" });
    const many = await signMulti(
      { release: "2.4.0" },
      Array.from({ length: 25 }, () => ({ key: pair.privateKey })),
    );
    expect(await codeOf(isApproved(many, { keys: [pair.publicKey as JWK] }))).toBe(
      "ERR_JWS_INVALID",
    );
  });
});
