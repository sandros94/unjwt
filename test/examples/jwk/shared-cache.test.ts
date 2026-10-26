import { afterAll, describe, expect, it } from "vitest";
import { clearJWKCache, generateJWK, importKey } from "unjwt/jwk";
import { sign, verify } from "unjwt/jws";
import { entries } from "../../../examples/jwk/shared-cache.ts";

afterAll(() => {
  clearJWKCache();
});

describe("examples/jwk/shared-cache", () => {
  it("serves one CryptoKey for every copy of the same JWK", async () => {
    const { publicKey } = await generateJWK("ES256", { kid: "2026-10" });
    const fromJson = () => JSON.parse(JSON.stringify(publicKey));
    expect(await importKey(fromJson())).toBe(await importKey(fromJson()));
    expect([...entries.keys()].some((name) => name.endsWith(":public:ES256"))).toBe(true);
  });

  it("keeps the two halves of a pair apart", async () => {
    const { privateKey, publicKey } = await generateJWK("ES256");
    const token = await sign({ sub: "user_1a2b" }, { ...privateKey });
    const signer = await importKey({ ...privateKey });
    const verifier = await importKey({ ...publicKey });
    expect(signer.type).toBe("private");
    expect(verifier.type).toBe("public");
    expect((await verify(token, { ...publicKey })).payload.sub).toBe("user_1a2b");
  });

  it("never names an entry by kid, so two keys sharing one stay apart", async () => {
    const a = await generateJWK("ES256", { kid: "2026-10" });
    const b = await generateJWK("ES256", { kid: "2026-10" });
    expect(await importKey(a.publicKey)).not.toBe(await importKey(b.publicKey));
    const token = await sign({}, b.privateKey);
    await expect(verify(token, a.publicKey)).rejects.toMatchObject({
      code: "ERR_JWS_SIGNATURE_INVALID",
    });
  });
});
