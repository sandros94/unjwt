import { describe, expect, it } from "vitest";
import { generateJWK } from "unjwt/jwk";
import { sign } from "unjwt/jws";
import {
  addKey,
  createKeyring,
  issueToken,
  publishedSet,
  readToken,
  retireKey,
  switchSigning,
} from "../../../examples/jwk/keyring.ts";

describe("examples/jwk/keyring", () => {
  it("publishes public halves only and verifies by kid", async () => {
    const ring = await createKeyring("2026-09");
    const set = publishedSet(ring);
    expect(set.keys).toHaveLength(1);
    expect(set.keys[0]).not.toHaveProperty("d");
    expect((await readToken(set, await issueToken(ring, "user_1a2b"))).sub).toBe("user_1a2b");
  });

  it("rotates in four steps without refusing a token that is still valid", async () => {
    let ring = await createKeyring("2026-09");
    const before = await issueToken(ring, "user_1a2b");

    ring = await addKey(ring, "2026-10");
    expect(publishedSet(ring).keys.map((k) => k.kid)).toEqual(["2026-09", "2026-10"]);
    const stillOld = await issueToken(ring, "user_1a2b");

    ring = switchSigning(ring, "2026-10");
    const after = await issueToken(ring, "user_1a2b");
    const set = publishedSet(ring);
    for (const token of [before, stillOld, after]) {
      expect((await readToken(set, token)).sub).toBe("user_1a2b");
    }

    ring = retireKey(ring, "2026-09");
    const retired = publishedSet(ring);
    expect((await readToken(retired, after)).sub).toBe("user_1a2b");
    await expect(readToken(retired, before)).rejects.toMatchObject({
      code: "ERR_JWK_KEY_NOT_FOUND",
    });
  });

  it("refuses to retire the signing key or switch to a key nobody has seen", async () => {
    const ring = await createKeyring("2026-09");
    expect(() => retireKey(ring, "2026-09")).toThrow("still signs new tokens");
    expect(() => switchSigning(ring, "2026-10")).toThrow('Add "2026-10" first');
  });

  it("refuses a token from a key outside the set, named or not", async () => {
    const set = publishedSet(await createKeyring("2026-09"));
    const stranger = await generateJWK("ES256", { kid: "2026-11" });
    await expect(readToken(set, await sign({}, stranger.privateKey))).rejects.toMatchObject({
      code: "ERR_JWK_KEY_NOT_FOUND",
    });
    const nameless = await generateJWK("ES256", { kid: false });
    await expect(readToken(set, await sign({}, nameless.privateKey))).rejects.toMatchObject({
      code: "ERR_JWS_SIGNATURE_INVALID",
    });
    const hs = await generateJWK("HS256", { kid: "2026-09" });
    await expect(readToken(set, await sign({}, hs))).rejects.toMatchObject({
      code: "ERR_JWS_ALG_NOT_ALLOWED",
    });
  });
});
