import * as jose from "jose";
import { describe, it, expect, beforeAll } from "vitest";
import { textEncoder, textDecoder } from "unsecure/utils";

import {
  encryptMulti,
  decryptMulti,
  generalToFlattened,
  JWTError,
  isJWTError,
} from "../src/core/jwe";
import { generateJWK } from "../src/core/jwk";
import type {
  JWK,
  JWK_EC_Public,
  JWK_EC_Private,
  JWK_oct,
  JWK_Pair,
  JWKSet,
  JWEGeneralSerialization,
  JWEFlattenedSerialization,
  JWKLookupFunction,
  JWTClaims,
} from "../src/core/types";

describe.concurrent("JWE Multi-recipient (General JSON Serialization)", () => {
  const keys: {
    rsa256: JWK_Pair<"RSA-OAEP-256">;
    rsa384: JWK_Pair<"RSA-OAEP-384">;
    ecdhP256: JWK_Pair<"ECDH-ES+A256KW">;
    ecdhX25519: JWK_Pair<"ECDH-ES+A256KW">;
    a128kw: JWK_oct<"A128KW">;
    a256kw: JWK_oct<"A256KW">;
    a256gcmkw: JWK_oct<"A256GCMKW">;
    a256gcm_dir: JWK_oct<"A256GCM">;
  } = {} as any;

  beforeAll(async () => {
    const [rsa256, rsa384, ecdhP256, ecdhX25519, a128kw, a256kw, a256gcmkw, a256gcm_dir] =
      await Promise.all([
        generateJWK("RSA-OAEP-256", { modulusLength: 2048 }),
        generateJWK("RSA-OAEP-384", { modulusLength: 2048 }),
        generateJWK("ECDH-ES+A256KW", { namedCurve: "P-256" }),
        generateJWK("ECDH-ES+A256KW", { namedCurve: "X25519" }),
        generateJWK("A128KW"),
        generateJWK("A256KW"),
        generateJWK("A256GCMKW"),
        generateJWK("A256GCM"),
      ]);
    keys.rsa256 = rsa256;
    keys.rsa384 = rsa384;
    keys.ecdhP256 = ecdhP256;
    keys.ecdhX25519 = ecdhX25519;
    keys.a128kw = a128kw;
    keys.a256kw = a256kw;
    keys.a256gcmkw = a256gcmkw;
    keys.a256gcm_dir = a256gcm_dir;
  });

  describe("encryptMulti", () => {
    it("encrypts to 3 recipients with mixed algs (RSA + ECDH + AES-KW)", async () => {
      const jwe = await encryptMulti(
        { sub: "u1", role: "admin" },
        [{ key: keys.rsa256.publicKey }, { key: keys.ecdhP256.publicKey }, { key: keys.a256kw }],
        { enc: "A256GCM" },
      );

      expect(jwe.recipients).toHaveLength(3);
      expect(jwe.recipients[0]?.header?.alg).toBe("RSA-OAEP-256");
      expect(jwe.recipients[1]?.header?.alg).toBe("ECDH-ES+A256KW");
      expect(jwe.recipients[2]?.header?.alg).toBe("A256KW");
      expect(typeof jwe.iv).toBe("string");
      expect(typeof jwe.ciphertext).toBe("string");
      expect(typeof jwe.tag).toBe("string");
      expect(typeof jwe.protected).toBe("string");
    });

    it("emits General shape for a single recipient (not Flattened)", async () => {
      const jwe = await encryptMulti({ foo: "bar" }, [{ key: keys.a256kw }], {
        enc: "A256GCM",
      });
      expect(Array.isArray(jwe.recipients)).toBe(true);
      expect(jwe.recipients).toHaveLength(1);
      expect("encrypted_key" in (jwe as any)).toBe(false);
      expect("header" in (jwe as any)).toBe(false);
    });

    it("applies JWT claim auto-generation (iat, exp)", async () => {
      const jwe = await encryptMulti({ sub: "u1" }, [{ key: keys.a256kw }], {
        enc: "A256GCM",
        expiresIn: "1h",
      });
      const { payload } = await decryptMulti<JWTClaims>(jwe, keys.a256kw);
      expect(payload.iat).toBeTypeOf("number");
      expect(payload.exp).toBeTypeOf("number");
      expect(payload.exp! - payload.iat!).toBe(3600);
    });

    it("embeds external AAD and round-trips", async () => {
      const jwe = await encryptMulti({ secret: "s" }, [{ key: keys.a256kw }], {
        enc: "A256GCM",
        aad: "binding-context",
      });
      expect(jwe.aad).toBeTypeOf("string");
      const { payload } = await decryptMulti(jwe, keys.a256kw);
      expect((payload as Record<string, unknown>).secret).toBe("s");
    });

    it("preserves sharedUnprotectedHeader in output", async () => {
      const jwe = await encryptMulti({ x: 1 }, [{ key: keys.a256kw }], {
        enc: "A256GCM",
        sharedUnprotectedHeader: { app: "web" },
      });
      expect(jwe.unprotected).toEqual({ app: "web" });
    });

    it("preserves per-recipient header extras", async () => {
      const jwe = await encryptMulti(
        { x: 1 },
        [
          { key: keys.a256kw, header: { "x-region": "eu-west" } },
          { key: keys.a128kw, header: { "x-region": "us-east" } },
        ],
        { enc: "A256GCM" },
      );
      expect(jwe.recipients[0]?.header?.["x-region"]).toBe("eu-west");
      expect(jwe.recipients[1]?.header?.["x-region"]).toBe("us-east");
    });

    it("propagates kid from JWK to per-recipient header", async () => {
      const jwe = await encryptMulti({ x: 1 }, [{ key: keys.a256kw }], {
        enc: "A256GCM",
      });
      expect(jwe.recipients[0]?.header?.kid).toBe(keys.a256kw.kid);
    });

    it("uses the provided cek across all recipients", async () => {
      const cek = crypto.getRandomValues(new Uint8Array(32));
      const jwe = await encryptMulti({ x: 1 }, [{ key: keys.a256kw }, { key: keys.a128kw }], {
        enc: "A256GCM",
        cek,
      });
      const a = await decryptMulti(jwe, keys.a256kw, { returnCek: true });
      const b = await decryptMulti(jwe, keys.a128kw, { returnCek: true });
      expect(a.cek).toEqual(cek);
      expect(b.cek).toEqual(cek);
    });

    it("throws on empty recipients array", async () => {
      await expect(encryptMulti({ x: 1 }, [], { enc: "A256GCM" })).rejects.toSatisfy((e) =>
        isJWTError(e, "ERR_JWE_INVALID"),
      );
    });

    it("throws ERR_JWE_RECIPIENT_ALG_INFERENCE when JWK has no alg", async () => {
      const noAlg: JWK = { ...keys.a256kw };
      delete (noAlg as { alg?: string }).alg;
      await expect(
        // @ts-expect-error intentionally passing an alg-less JWK to exercise runtime guard
        encryptMulti({ x: 1 }, [{ key: noAlg }]),
      ).rejects.toSatisfy((e) => isJWTError(e, "ERR_JWE_RECIPIENT_ALG_INFERENCE"));
    });

    it("throws ERR_JWE_ALG_FORBIDDEN_IN_MULTI on dir alg", async () => {
      await expect(
        encryptMulti({ x: 1 }, [{ key: { ...keys.a256gcm_dir, alg: "dir" } }], {
          enc: "A256GCM",
        }),
      ).rejects.toSatisfy((e) => isJWTError(e, "ERR_JWE_ALG_FORBIDDEN_IN_MULTI"));
    });

    it("throws ERR_JWE_ALG_FORBIDDEN_IN_MULTI on bare ECDH-ES", async () => {
      await expect(
        encryptMulti({ x: 1 }, [{ key: { ...keys.ecdhP256.publicKey, alg: "ECDH-ES" } }], {
          enc: "A256GCM",
        }),
      ).rejects.toSatisfy((e) => isJWTError(e, "ERR_JWE_ALG_FORBIDDEN_IN_MULTI"));
    });

    it("throws ERR_JWE_HEADER_PARAMS_NOT_DISJOINT on header tier overlap", async () => {
      await expect(
        encryptMulti({ x: 1 }, [{ key: keys.a256kw }], {
          enc: "A256GCM",
          sharedUnprotectedHeader: { typ: "JWT" },
        }),
      ).rejects.toSatisfy((e) => isJWTError(e, "ERR_JWE_HEADER_PARAMS_NOT_DISJOINT"));
    });
  });

  describe("decryptMulti", () => {
    it("decrypts using the first recipient's key", async () => {
      const jwe = await encryptMulti(
        { sub: "u1" },
        [{ key: keys.rsa256.publicKey }, { key: keys.a256kw }],
        { enc: "A256GCM" },
      );
      const { payload, recipientIndex } = await decryptMulti(jwe, keys.rsa256.privateKey);
      expect((payload as JWTClaims).sub).toBe("u1");
      expect(recipientIndex).toBe(0);
    });

    it("decrypts using the second recipient's key", async () => {
      const jwe = await encryptMulti(
        { sub: "u1" },
        [{ key: keys.rsa256.publicKey }, { key: keys.a256kw }],
        { enc: "A256GCM" },
      );
      const { payload, recipientIndex } = await decryptMulti(jwe, keys.a256kw);
      expect((payload as JWTClaims).sub).toBe("u1");
      expect(recipientIndex).toBe(1);
    });

    it("surfaces recipientHeader and sharedUnprotectedHeader on result", async () => {
      const jwe = await encryptMulti(
        { x: 1 },
        [{ key: keys.a256kw, header: { "x-route": "r1" } }],
        { enc: "A256GCM", sharedUnprotectedHeader: { app: "web" } },
      );
      const { recipientHeader, sharedUnprotectedHeader } = await decryptMulti(jwe, keys.a256kw);
      expect(recipientHeader?.["x-route"]).toBe("r1");
      expect(sharedUnprotectedHeader?.app).toBe("web");
    });

    it("accepts Flattened JSON Serialization input", async () => {
      const jwe = await encryptMulti({ x: 1 }, [{ key: keys.a256kw }], {
        enc: "A256GCM",
      });
      const flattened: JWEFlattenedSerialization = {
        protected: jwe.protected,
        header: jwe.recipients[0]?.header,
        encrypted_key: jwe.recipients[0]?.encrypted_key,
        iv: jwe.iv,
        ciphertext: jwe.ciphertext,
        tag: jwe.tag,
      };
      const { payload } = await decryptMulti(flattened, keys.a256kw);
      expect((payload as Record<string, unknown>).x).toBe(1);
    });

    it("accepts a JWKSet and finds the matching key", async () => {
      const jwe = await encryptMulti(
        { sub: "u1" },
        [{ key: keys.rsa256.publicKey }, { key: keys.a256kw }],
        { enc: "A256GCM" },
      );
      const set: JWKSet = { keys: [keys.a128kw, keys.a256kw] };
      const { payload, recipientIndex } = await decryptMulti(jwe, set);
      expect((payload as JWTClaims).sub).toBe("u1");
      expect(recipientIndex).toBe(1);
    });

    it("accepts a JWKLookupFunction", async () => {
      const jwe = await encryptMulti(
        { sub: "u1" },
        [{ key: keys.rsa256.publicKey }, { key: keys.a256kw }],
        { enc: "A256GCM" },
      );
      const lookup: JWKLookupFunction = (header) => {
        if (header.kid === keys.a256kw.kid) return keys.a256kw;
        if (header.kid === keys.rsa256.publicKey.kid) return keys.rsa256.privateKey;
        throw new Error("no key");
      };
      const { payload, recipientIndex } = await decryptMulti(jwe, lookup);
      expect((payload as JWTClaims).sub).toBe("u1");
      expect(recipientIndex).toBe(0);
    });

    it("validates JWT claims on the payload", async () => {
      const jwe = await encryptMulti(
        { sub: "u1", exp: Math.floor(Date.now() / 1000) - 10 },
        [{ key: keys.a256kw }],
        { enc: "A256GCM" },
      );
      await expect(decryptMulti(jwe, keys.a256kw)).rejects.toSatisfy((e) =>
        isJWTError(e, "ERR_JWT_EXPIRED"),
      );
    });

    it("returns cek and aad when returnCek: true", async () => {
      const jwe = await encryptMulti({ x: 1 }, [{ key: keys.a256kw }], {
        enc: "A256GCM",
      });
      const { cek, aad } = await decryptMulti(jwe, keys.a256kw, { returnCek: true });
      expect(cek).toBeInstanceOf(Uint8Array);
      expect(aad).toBeInstanceOf(Uint8Array);
    });

    it("reports invalid tag as decryption failure across all recipients", async () => {
      const jwe = await encryptMulti({ x: 1 }, [{ key: keys.a256kw }, { key: keys.a128kw }], {
        enc: "A256GCM",
      });
      const tampered: JWEGeneralSerialization = { ...jwe, tag: jwe.tag!.slice(0, -2) + "AA" };
      await expect(decryptMulti(tampered, keys.a256kw)).rejects.toBeInstanceOf(JWTError);
    });

    it("roundtrips an external AAD without mutation", async () => {
      const jwe = await encryptMulti({ x: 1 }, [{ key: keys.a256kw }], {
        enc: "A256GCM",
        aad: "ctx",
      });
      // If aad is stripped, the tag check would fail.
      const tampered: JWEGeneralSerialization = { ...jwe, aad: undefined };
      await expect(decryptMulti(tampered, keys.a256kw)).rejects.toBeInstanceOf(JWTError);
    });

    describe("strictRecipientMatch", () => {
      it("skips recipients whose kid does not match the key kid", async () => {
        const jwe = await encryptMulti(
          { sub: "u1" },
          [{ key: keys.rsa256.publicKey }, { key: keys.a256kw }],
          { enc: "A256GCM" },
        );
        const { recipientIndex } = await decryptMulti(jwe, keys.a256kw, {
          strictRecipientMatch: true,
        });
        expect(recipientIndex).toBe(1);
      });

      it("throws ERR_JWE_NO_MATCHING_RECIPIENT when no kid matches", async () => {
        const jwe = await encryptMulti({ x: 1 }, [{ key: keys.a256kw }], {
          enc: "A256GCM",
        });
        const unrelated: JWK_oct<"A128KW"> = { ...keys.a128kw, kid: "unrelated" };
        await expect(
          decryptMulti(jwe, unrelated, { strictRecipientMatch: true }),
        ).rejects.toSatisfy((e) => isJWTError(e, "ERR_JWE_NO_MATCHING_RECIPIENT"));
      });
    });

    describe("error paths", () => {
      it("rejects an object missing iv/ciphertext/tag", async () => {
        await expect(
          decryptMulti({ recipients: [{}] } as unknown as JWEGeneralSerialization, keys.a256kw),
        ).rejects.toSatisfy((e) => isJWTError(e, "ERR_JWE_INVALID_SERIALIZATION"));
      });

      it("rejects disallowed key-management alg via options.algorithms", async () => {
        const jwe = await encryptMulti({ x: 1 }, [{ key: keys.a256kw }], {
          enc: "A256GCM",
        });
        await expect(
          decryptMulti(jwe, keys.a256kw, { algorithms: ["A128KW"] }),
        ).rejects.toBeInstanceOf(JWTError);
      });

      it("rejects disallowed content enc alg via options.encryptionAlgorithms", async () => {
        const jwe = await encryptMulti({ x: 1 }, [{ key: keys.a256kw }], {
          enc: "A256GCM",
        });
        await expect(
          decryptMulti(jwe, keys.a256kw, { encryptionAlgorithms: ["A128GCM"] }),
        ).rejects.toSatisfy((e) => isJWTError(e, "ERR_JWE_ALG_NOT_ALLOWED"));
      });

      it("rejects non-object input (ERR_JWE_INVALID_SERIALIZATION)", async () => {
        await expect(
          decryptMulti(null as unknown as JWEGeneralSerialization, keys.a256kw),
        ).rejects.toSatisfy((e) => isJWTError(e, "ERR_JWE_INVALID_SERIALIZATION"));
      });

      it("rejects an object with neither recipients[] nor flattened fields", async () => {
        await expect(
          decryptMulti(
            { iv: "x", ciphertext: "y", tag: "z" } as unknown as JWEGeneralSerialization,
            keys.a256kw,
          ),
        ).rejects.toSatisfy((e) => isJWTError(e, "ERR_JWE_INVALID_SERIALIZATION"));
      });

      it("rejects a JWE missing enc in protected header", async () => {
        const badProtected = Buffer.from(JSON.stringify({})).toString("base64url");
        const jwe: JWEGeneralSerialization = {
          protected: badProtected,
          recipients: [{ header: { alg: "A256KW" }, encrypted_key: "x" }],
          iv: "AAAA",
          ciphertext: "AAAA",
          tag: "AAAA",
        };
        await expect(decryptMulti(jwe, keys.a256kw)).rejects.toSatisfy((e) =>
          isJWTError(e, "ERR_JWE_INVALID"),
        );
      });

      it("skips recipient with no alg in effective header and tries the next", async () => {
        const good = await encryptMulti(
          { sub: "u1" },
          [{ key: keys.a128kw }, { key: keys.a256kw }],
          { enc: "A256GCM" },
        );
        // Strip alg from first recipient — library should fall through to recipient[1]
        const noAlg: JWEGeneralSerialization = {
          ...good,
          recipients: [
            { header: { ...good.recipients[0]!.header, alg: undefined } },
            good.recipients[1]!,
          ],
        };
        const { payload, recipientIndex } = await decryptMulti(noAlg, keys.a256kw);
        expect((payload as JWTClaims).sub).toBe("u1");
        expect(recipientIndex).toBe(1);
      });
    });

    describe("options coverage", () => {
      it("merges user-supplied protectedHeader into the JWE protected header", async () => {
        const jwe = await encryptMulti({ x: 1 }, [{ key: keys.a256kw }], {
          enc: "A256GCM",
          protectedHeader: { typ: "custom+jwt" },
        });
        expect(jwe.protected).toBeTypeOf("string");
        const decoded = JSON.parse(Buffer.from(jwe.protected!, "base64url").toString("utf8"));
        expect(decoded.typ).toBe("custom+jwt");
        const { protectedHeader } = await decryptMulti(jwe, keys.a256kw);
        expect(protectedHeader.typ).toBe("custom+jwt");
      });

      it("honors crit header via options.recognizedHeaders", async () => {
        const jwe = await encryptMulti({ x: 1 }, [{ key: keys.a256kw }], {
          enc: "A256GCM",
          protectedHeader: { crit: ["app"], app: "web" },
        });
        const { protectedHeader } = await decryptMulti(jwe, keys.a256kw, {
          recognizedHeaders: ["app"],
        });
        expect(protectedHeader.app).toBe("web");
      });

      it("throws when a crit header param is not in recognizedHeaders", async () => {
        const jwe = await encryptMulti({ x: 1 }, [{ key: keys.a256kw }], {
          enc: "A256GCM",
          protectedHeader: { crit: ["app"], app: "web" },
        });
        await expect(decryptMulti(jwe, keys.a256kw)).rejects.toBeInstanceOf(JWTError);
      });

      it("forceUint8Array returns payload as Uint8Array", async () => {
        const jwe = await encryptMulti({ x: 1 }, [{ key: keys.a256kw }], {
          enc: "A256GCM",
        });
        const { payload } = await decryptMulti(jwe, keys.a256kw, { forceUint8Array: true });
        expect(payload).toBeInstanceOf(Uint8Array);
      });

      it("AES-GCMKW recipient round-trips (exercises iv/tag in per-recipient header)", async () => {
        const jwe = await encryptMulti({ x: 1 }, [{ key: keys.a256gcmkw }], {
          enc: "A256GCM",
        });
        expect(jwe.recipients[0]?.header?.iv).toBeTypeOf("string");
        expect(jwe.recipients[0]?.header?.tag).toBeTypeOf("string");
        const { payload } = await decryptMulti(jwe, keys.a256gcmkw);
        expect((payload as Record<string, unknown>).x).toBe(1);
      });
    });

    describe("ECDH-ES+A*KW recipient ephemeral key variants", () => {
      it("accepts a pre-computed CryptoKeyPair as ecdh.ephemeralKey", async () => {
        const ephemeral = await crypto.subtle.generateKey(
          { name: "ECDH", namedCurve: "P-256" },
          true,
          ["deriveBits"],
        );
        const jwe = await encryptMulti(
          { sub: "u1" },
          [
            {
              key: (keys.ecdhP256 as { publicKey: JWK_EC_Public<"ECDH-ES+A256KW"> }).publicKey,
              ecdh: { ephemeralKey: ephemeral },
            },
          ],
          { enc: "A256GCM" },
        );
        const ecdhPriv = (keys.ecdhP256 as { privateKey: JWK_EC_Private<"ECDH-ES+A256KW"> })
          .privateKey;
        const { payload } = await decryptMulti(jwe, ecdhPriv);
        expect((payload as JWTClaims).sub).toBe("u1");
      });
    });

    describe("JWKSet candidate rotation", () => {
      it("tries next candidate when first same-alg JWK fails to unwrap", async () => {
        const jwe = await encryptMulti({ sub: "u1" }, [{ key: keys.a256kw }], {
          enc: "A256GCM",
        });
        // Strip kid from the wire recipient so the set filter can't narrow by kid —
        // forces both a128kw (wrong alg, filtered out) and an unrelated A256KW to be tried.
        const anotherA256 = await generateJWK("A256KW");
        const jweNoKid: JWEGeneralSerialization = {
          ...jwe,
          recipients: [
            { header: { alg: "A256KW" }, encrypted_key: jwe.recipients[0]!.encrypted_key },
          ],
        };
        const set: JWKSet = { keys: [anotherA256, keys.a256kw] };
        const { payload } = await decryptMulti(jweNoKid, set);
        expect((payload as JWTClaims).sub).toBe("u1");
      });

      it("throws DECRYPTION_FAILED when every candidate in the set fails", async () => {
        const jwe = await encryptMulti({ sub: "u1" }, [{ key: keys.a256kw }], {
          enc: "A256GCM",
        });
        const jweNoKid: JWEGeneralSerialization = {
          ...jwe,
          recipients: [
            { header: { alg: "A256KW" }, encrypted_key: jwe.recipients[0]!.encrypted_key },
          ],
        };
        const wrong1 = await generateJWK("A256KW");
        const wrong2 = await generateJWK("A256KW");
        const set: JWKSet = { keys: [wrong1, wrong2] };
        await expect(decryptMulti(jweNoKid, set)).rejects.toBeInstanceOf(JWTError);
      });
    });

    describe("strictRecipientMatch edge cases", () => {
      it("skips when header has kid but key material is a CryptoKey (no kid)", async () => {
        const jwe = await encryptMulti(
          { sub: "u1" },
          [{ key: keys.rsa256.publicKey }, { key: keys.a256kw }],
          { enc: "A256GCM" },
        );
        // Import a256kw as a raw CryptoKey — no kid metadata on it
        const cryptoKey = await crypto.subtle.importKey(
          "raw",
          Buffer.from(keys.a256kw.k!, "base64url"),
          { name: "AES-KW" },
          false,
          ["wrapKey", "unwrapKey"],
        );
        await expect(
          decryptMulti(jwe, cryptoKey, { strictRecipientMatch: true }),
        ).rejects.toSatisfy((e) => isJWTError(e, "ERR_JWE_NO_MATCHING_RECIPIENT"));
      });
    });

    it("ecdh.partyUInfo / partyVInfo propagate to apu/apv and round-trip", async () => {
      const pub = (keys.ecdhP256 as { publicKey: JWK_EC_Public<"ECDH-ES+A256KW"> }).publicKey;
      const jwe = await encryptMulti(
        { sub: "u1" },
        [
          {
            key: pub,
            ecdh: {
              partyUInfo: textEncoder.encode("alice"),
              partyVInfo: textEncoder.encode("bob"),
            },
          },
        ],
        { enc: "A256GCM" },
      );
      expect(jwe.recipients[0]?.header?.apu).toBeTypeOf("string");
      expect(jwe.recipients[0]?.header?.apv).toBeTypeOf("string");
      const priv = (keys.ecdhP256 as { privateKey: JWK_EC_Private<"ECDH-ES+A256KW"> }).privateKey;
      const { payload } = await decryptMulti(jwe, priv);
      expect((payload as JWTClaims).sub).toBe("u1");
    });
  });

  describe("alg matrix round-trip", () => {
    const matrix = [
      "rsa256",
      "rsa384",
      "ecdhP256",
      "ecdhX25519",
      "a128kw",
      "a256kw",
      "a256gcmkw",
    ] as const;

    for (const keyName of matrix) {
      it(`round-trips payload via ${keyName}`, async () => {
        const isPair =
          keyName === "rsa256" ||
          keyName === "rsa384" ||
          keyName === "ecdhP256" ||
          keyName === "ecdhX25519";
        const encKey = isPair ? (keys as any)[keyName].publicKey : (keys as any)[keyName];
        const decKey = isPair ? (keys as any)[keyName].privateKey : (keys as any)[keyName];
        const jwe = await encryptMulti(
          { sub: "u1", data: keyName },
          [{ key: encKey }, { key: keys.a256kw }],
          { enc: "A256GCM" },
        );
        const { payload, recipientIndex } = await decryptMulti(jwe, decKey);
        expect((payload as JWTClaims).sub).toBe("u1");
        expect(recipientIndex).toBe(0);
      });
    }
  });

  describe("generalToFlattened", () => {
    it("converts single-recipient General to Flattened", async () => {
      const jwe = await encryptMulti({ x: 1 }, [{ key: keys.a256kw }], {
        enc: "A256GCM",
      });
      const flattened = generalToFlattened(jwe);
      expect("recipients" in flattened).toBe(false);
      expect(flattened.header).toEqual(jwe.recipients[0]?.header);
      expect(flattened.encrypted_key).toEqual(jwe.recipients[0]?.encrypted_key);
      expect(flattened.protected).toBe(jwe.protected);
      expect(flattened.iv).toBe(jwe.iv);
      expect(flattened.ciphertext).toBe(jwe.ciphertext);
      expect(flattened.tag).toBe(jwe.tag);
    });

    it("preserves top-level aad and unprotected", async () => {
      const jwe = await encryptMulti({ x: 1 }, [{ key: keys.a256kw }], {
        enc: "A256GCM",
        aad: "ctx",
        sharedUnprotectedHeader: { app: "web" },
      });
      const flattened = generalToFlattened(jwe);
      expect(flattened.aad).toBe(jwe.aad);
      expect(flattened.unprotected).toEqual(jwe.unprotected);
    });

    it("throws on multi-recipient input", async () => {
      const jwe = await encryptMulti({ x: 1 }, [{ key: keys.a256kw }, { key: keys.a128kw }], {
        enc: "A256GCM",
      });
      try {
        generalToFlattened(jwe);
        expect.fail("should have thrown");
      } catch (err) {
        expect(isJWTError(err, "ERR_JWE_INVALID_SERIALIZATION")).toBe(true);
      }
    });

    it("round-trips via Flattened back into decryptMulti", async () => {
      const jwe = await encryptMulti({ x: 1 }, [{ key: keys.a256kw }], {
        enc: "A256GCM",
      });
      const flattened = generalToFlattened(jwe);
      const { payload } = await decryptMulti(flattened, keys.a256kw);
      expect((payload as Record<string, unknown>).x).toBe(1);
    });
  });

  describe("interop with jose", () => {
    it("unjwt encryptMulti → jose.generalDecrypt (single AES recipient)", async () => {
      const jwe = await encryptMulti({ sub: "u1" }, [{ key: keys.a256kw }], {
        enc: "A256GCM",
      });
      const joseKey = await jose.importJWK(keys.a256kw);
      const { plaintext } = await jose.generalDecrypt(jwe, joseKey);
      expect(JSON.parse(textDecoder.decode(plaintext))).toEqual({ sub: "u1" });
    });

    it("unjwt encryptMulti → jose.generalDecrypt (RSA + AES recipients)", async () => {
      const jwe = await encryptMulti(
        { sub: "u1" },
        [{ key: keys.rsa256.publicKey }, { key: keys.a256kw }],
        { enc: "A256GCM" },
      );
      const rsaPriv = await jose.importJWK(keys.rsa256.privateKey);
      const aesKey = await jose.importJWK(keys.a256kw);

      const { plaintext: pa } = await jose.generalDecrypt(jwe, rsaPriv);
      expect(JSON.parse(textDecoder.decode(pa))).toEqual({ sub: "u1" });

      const { plaintext: pb } = await jose.generalDecrypt(jwe, aesKey);
      expect(JSON.parse(textDecoder.decode(pb))).toEqual({ sub: "u1" });
    });

    it("unjwt encryptMulti → jose.generalDecrypt (ECDH recipient)", async () => {
      const jwe = await encryptMulti({ sub: "u1" }, [{ key: keys.ecdhP256.publicKey }], {
        enc: "A256GCM",
      });
      const ecdhPriv = await jose.importJWK(keys.ecdhP256.privateKey);
      const { plaintext } = await jose.generalDecrypt(jwe, ecdhPriv);
      expect(JSON.parse(textDecoder.decode(plaintext))).toEqual({ sub: "u1" });
    });

    it("unjwt encryptMulti with external aad → jose.generalDecrypt honors aad", async () => {
      const jwe = await encryptMulti({ sub: "u1" }, [{ key: keys.a256kw }], {
        enc: "A256GCM",
        aad: "bind-me",
      });
      const joseKey = await jose.importJWK(keys.a256kw);
      const { plaintext, additionalAuthenticatedData } = await jose.generalDecrypt(jwe, joseKey);
      expect(JSON.parse(textDecoder.decode(plaintext))).toEqual({ sub: "u1" });
      expect(textDecoder.decode(additionalAuthenticatedData!)).toBe("bind-me");
    });

    it("jose.GeneralEncrypt → unjwt decryptMulti (RSA + AES recipients)", async () => {
      const rsaPub = await jose.importJWK(keys.rsa256.publicKey);
      const aesKey = await jose.importJWK(keys.a256kw);
      const payloadBytes = textEncoder.encode(JSON.stringify({ sub: "u1" }));

      const enc = new jose.GeneralEncrypt(payloadBytes).setProtectedHeader({
        enc: "A256GCM",
      });
      enc.addRecipient(rsaPub).setUnprotectedHeader({ alg: "RSA-OAEP-256" });
      enc.addRecipient(aesKey).setUnprotectedHeader({ alg: "A256KW" });
      // jose's JWEHeaderParameters.jwk is looser than ours (kty?: string vs the
      // RFC-correct discriminated union) — legitimate boundary cast.
      const jwe = (await enc.encrypt()) as unknown as JWEGeneralSerialization;

      const { payload: pa } = await decryptMulti(jwe, keys.rsa256.privateKey);
      expect(pa).toEqual({ sub: "u1" });

      const { payload: pb } = await decryptMulti(jwe, keys.a256kw);
      expect(pb).toEqual({ sub: "u1" });
    });

    it("unjwt encryptMulti + generalToFlattened → jose.flattenedDecrypt", async () => {
      const jwe = await encryptMulti({ sub: "u1" }, [{ key: keys.a256kw }], {
        enc: "A256GCM",
      });
      const flattened = generalToFlattened(jwe);
      const joseKey = await jose.importJWK(keys.a256kw);
      const { plaintext } = await jose.flattenedDecrypt(flattened, joseKey);
      expect(JSON.parse(textDecoder.decode(plaintext))).toEqual({ sub: "u1" });
    });

    it("jose.FlattenedEncrypt → unjwt decryptMulti", async () => {
      const joseKey = await jose.importJWK(keys.a256kw);
      const payloadBytes = textEncoder.encode(JSON.stringify({ sub: "u1" }));
      const jwe = (await new jose.FlattenedEncrypt(payloadBytes)
        .setProtectedHeader({ alg: "A256KW", enc: "A256GCM" })
        .encrypt(joseKey)) as unknown as JWEFlattenedSerialization;

      const { payload } = await decryptMulti(jwe, keys.a256kw);
      expect(payload).toEqual({ sub: "u1" });
    });
  });
});
