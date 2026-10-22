import { describe, it, expect } from "vitest";
import { sign, signMulti } from "../src/core/jws.ts";
import { encrypt, encryptMulti, decrypt } from "../src/core/jwe.ts";
import { generateJWK } from "../src/core/jwk.ts";
import type { JWK_EC_Public } from "../src/core/types/index.ts";

const [ec, rsa, ecdh, oct] = await Promise.all([
  generateJWK("ES256"),
  generateJWK("RSA-OAEP-256"),
  generateJWK("ECDH-ES+A128KW"),
  generateJWK("HS256"),
]);

const publicOnly = expect.objectContaining({
  code: "ERR_INVALID_OPTION",
  message: expect.stringContaining('"jwk" in the'),
});
const epkOwned = expect.objectContaining({
  code: "ERR_INVALID_OPTION",
  message: expect.stringContaining('"epk" is written by the ECDH-ES key agreement'),
});
const cnfPublic = expect.objectContaining({
  code: "ERR_JWT_CLAIM_INVALID",
  message: 'Invalid JWT "cnf" (Confirmation) Claim: "jwk" must be a public JWK (RFC 7800 §3.2).',
});

// A caller has to defeat the types to reach these paths.
const asPublic = (jwk: unknown): JWK_EC_Public => jwk as JWK_EC_Public;

describe('"jwk" header carries a public key only', () => {
  it("sign refuses a private JWK and a secret", async () => {
    await expect(
      sign({ a: 1 }, ec.privateKey, { protectedHeader: { jwk: asPublic(ec.privateKey) } }),
    ).rejects.toThrow(publicOnly);
    await expect(sign({ a: 1 }, oct, { protectedHeader: { jwk: asPublic(oct) } })).rejects.toThrow(
      publicOnly,
    );
    await expect(
      sign({ a: 1 }, ec.privateKey, { protectedHeader: { jwk: asPublic("nope") } }),
    ).rejects.toThrow(publicOnly);
  });

  it("sign accepts the public half", async () => {
    await expect(
      sign({ a: 1 }, ec.privateKey, { protectedHeader: { jwk: ec.publicKey } }),
    ).resolves.toBeTypeOf("string");
  });

  it("signMulti refuses it in both tiers", async () => {
    await expect(
      signMulti({ a: 1 }, [
        { key: ec.privateKey, protectedHeader: { jwk: asPublic(ec.privateKey) } },
      ]),
    ).rejects.toThrow(publicOnly);
    await expect(
      signMulti({ a: 1 }, [
        { key: ec.privateKey, unprotectedHeader: { jwk: asPublic(ec.privateKey) } },
      ]),
    ).rejects.toThrow(publicOnly);
  });

  it("encrypt and encryptMulti refuse it in every tier", async () => {
    const jwk = asPublic(rsa.privateKey);
    await expect(
      encrypt({ a: 1 }, rsa.publicKey, { enc: "A256GCM", protectedHeader: { jwk } }),
    ).rejects.toThrow(publicOnly);
    await expect(
      encryptMulti({ a: 1 }, [{ key: rsa.publicKey }], {
        enc: "A256GCM",
        protectedHeader: { jwk },
      }),
    ).rejects.toThrow(publicOnly);
    await expect(
      encryptMulti({ a: 1 }, [{ key: rsa.publicKey }], {
        enc: "A256GCM",
        sharedUnprotectedHeader: { jwk },
      }),
    ).rejects.toThrow(publicOnly);
    await expect(
      encryptMulti({ a: 1 }, [{ key: rsa.publicKey, header: { jwk } }], { enc: "A256GCM" }),
    ).rejects.toThrow(publicOnly);
  });
});

describe('"epk" header belongs to the key agreement', () => {
  it("is refused in a caller's header, public or private, under any alg", async () => {
    for (const epk of [ecdh.publicKey, ecdh.privateKey]) {
      await expect(
        encrypt({ a: 1 }, ecdh.publicKey, {
          enc: "A256GCM",
          protectedHeader: { epk: asPublic(epk) },
        }),
      ).rejects.toThrow(epkOwned);
      await expect(
        encrypt({ a: 1 }, rsa.publicKey, {
          enc: "A256GCM",
          protectedHeader: { epk: asPublic(epk) },
        }),
      ).rejects.toThrow(epkOwned);
      await expect(
        encryptMulti({ a: 1 }, [{ key: ecdh.publicKey, header: { epk: asPublic(epk) } }], {
          enc: "A256GCM",
        }),
      ).rejects.toThrow(epkOwned);
    }
  });

  it("still travels through ecdh.ephemeralKey", async () => {
    const ephemeral = await generateJWK("ECDH-ES+A128KW");
    const jwe = await encrypt({ a: 1 }, ecdh.publicKey, {
      enc: "A256GCM",
      ecdh: { ephemeralKey: ephemeral.privateKey },
    });
    expect((await decrypt(jwe, ecdh.privateKey)).payload).toEqual({ a: 1 });
  });
});

describe('"cnf.jwk" claim is a public key', () => {
  it("every producer refuses private material or a secret", async () => {
    for (const jwk of [ec.privateKey, oct]) {
      const payload = { cnf: { jwk: asPublic(jwk) } };
      await expect(sign(payload, ec.privateKey)).rejects.toThrow(cnfPublic);
      await expect(signMulti(payload, [{ key: ec.privateKey }])).rejects.toThrow(cnfPublic);
      await expect(encrypt(payload, rsa.publicKey, { enc: "A256GCM" })).rejects.toThrow(cnfPublic);
      await expect(
        encryptMulti(payload, [{ key: rsa.publicKey }], { enc: "A256GCM" }),
      ).rejects.toThrow(cnfPublic);
    }
  });

  it("accepts a public key and leaves other cnf members alone", async () => {
    await expect(
      sign({ cnf: { jwk: ec.publicKey, jkt: "abc" } }, ec.privateKey),
    ).resolves.toBeTypeOf("string");
    await expect(sign({ cnf: { jkt: "abc" } }, ec.privateKey)).resolves.toBeTypeOf("string");
    await expect(sign({ cnf: "not-an-object" }, ec.privateKey)).resolves.toBeTypeOf("string");
    await expect(sign("text payload", ec.privateKey)).resolves.toBeTypeOf("string");
  });
});
