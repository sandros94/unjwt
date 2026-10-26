import { describe, expect, it } from "vitest";
import { deriveSharedSecret, generateJWK } from "unjwt/jwk";
import { decrypt, encrypt } from "unjwt/jwe";
import { channelKey } from "../../../examples/jwk/shared-secret.ts";

async function ecPair(namedCurve: "P-256" | "P-384" = "P-256") {
  const { privateKey, publicKey } = await generateJWK("ECDH-ES", { namedCurve });
  if (privateKey.kty !== "EC" || publicKey.kty !== "EC") throw new Error("Expected an EC pair");
  return { privateKey, publicKey };
}

const billing = await ecPair();
const api = await ecPair();

describe("examples/jwk/shared-secret", () => {
  it("gives both services the same key without sending it", async () => {
    const onBilling = await channelKey(billing.privateKey, api.publicKey);
    const onApi = await channelKey(api.privateKey, billing.publicKey);
    expect(onBilling).toEqual(onApi);
    const token = await encrypt({ invoice: "inv_7c1d" }, onBilling);
    expect((await decrypt(token, onApi)).payload).toMatchObject({ invoice: "inv_7c1d" });
  });

  it("derives the same key on every call, and another key with a third pair", async () => {
    const first = await channelKey(billing.privateKey, api.publicKey);
    expect(await channelKey(billing.privateKey, api.publicKey)).toEqual(first);
    const stranger = await ecPair();
    expect((await channelKey(stranger.privateKey, api.publicKey)).k).not.toBe(first.k);
  });

  it("refuses keys of another curve, another algorithm, or the wrong half", async () => {
    const p384 = await ecPair("P-384");
    await expect(channelKey(billing.privateKey, p384.publicKey)).rejects.toMatchObject({
      code: "ERR_JWK_INVALID",
    });
    const es = await generateJWK("ES256");
    await expect(channelKey(billing.privateKey, es.publicKey as never)).rejects.toMatchObject({
      code: "ERR_JWK_INVALID",
    });
    await expect(channelKey(billing.privateKey, api.privateKey)).rejects.toMatchObject({
      code: "ERR_JWK_INVALID",
    });
  });

  it("takes X25519 pairs too, and refuses one against a P-256 key", async () => {
    const left = await generateJWK("ECDH-ES", { namedCurve: "X25519" });
    const right = await generateJWK("ECDH-ES", { namedCurve: "X25519" });
    const options = { enc: "A256GCM" } as const;
    const one = await deriveSharedSecret(right.publicKey, left.privateKey, options);
    const other = await deriveSharedSecret(left.publicKey, right.privateKey, options);
    expect(one).toEqual(other);
    await expect(
      deriveSharedSecret(left.publicKey, billing.privateKey, options),
    ).rejects.toMatchObject({ code: "ERR_JWK_INVALID" });
  });
});
