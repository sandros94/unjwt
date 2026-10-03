import * as jose from "jose";
import { describe, it, expect, beforeAll } from "vitest";
import { textEncoder, textDecoder } from "unsecure/utils";

import {
  encrypt,
  encryptMulti,
  decryptMulti,
  generalToFlattened,
  JWTError,
  isJWTError,
  isUnsecureError,
} from "../src/core/jwe";
import { generateJWK, wrapKey } from "../src/core/jwk";
import { base64UrlStringify, base64UrlParse } from "../src/core/utils/base64";
import { secureRandomBytes } from "unsecure/random";
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
  KeyManagementAlgorithm,
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
      const { payload, recipientIndex } = await decryptMulti(jwe, set, {
        allowSymmetricJWKSet: true,
      });
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

      it("reads an object without recipients[] as the Flattened form", async () => {
        const error = await decryptMulti(
          { iv: "x", ciphertext: "y", tag: "z" } as unknown as JWEGeneralSerialization,
          keys.a256kw,
        ).catch((e) => e);
        expect(isJWTError(error, "ERR_JWE_INVALID")).toBe(true);
        expect(error.message).toBe(
          'Invalid JWE: "enc" is missing from the protected and shared unprotected headers.',
        );
      });

      it.each(["header", "encrypted_key"])(
        "rejects recipients[] alongside a top-level %s",
        async (member) => {
          const jwe = await encryptMulti({ x: 1 }, [{ key: keys.a256kw }]);
          const ambiguous = {
            ...jwe,
            [member]: member === "header" ? { alg: "A256KW" } : jwe.recipients[0]!.encrypted_key,
          };
          const error = await decryptMulti(ambiguous, keys.a256kw).catch((e) => e);
          expect(isJWTError(error, "ERR_JWE_INVALID_SERIALIZATION")).toBe(true);
        },
      );

      it("decrypts a Flattened dir token that carries neither header nor encrypted_key", async () => {
        const cek = await generateJWK("A256GCM");
        const compact = await encrypt({ x: 1 }, cek, { alg: "dir", enc: "A256GCM" });
        const [protectedHeader, , iv, ciphertext, tag] = compact.split(".");
        const flattened: JWEFlattenedSerialization = {
          protected: protectedHeader!,
          iv: iv!,
          ciphertext: ciphertext!,
          tag: tag!,
        };
        const { payload, recipientIndex } = await decryptMulti(flattened, cek);
        expect(payload).toEqual({ x: 1 });
        expect(recipientIndex).toBe(0);
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

      it('forceUint8Array matches payload: "bytes"', async () => {
        const jwe = await encryptMulti({ x: 1 }, [{ key: keys.a256kw }], {
          enc: "A256GCM",
        });
        const { payload } = await decryptMulti(jwe, keys.a256kw, { forceUint8Array: true });
        expect(payload).toBeInstanceOf(Uint8Array);
        const explicit = await decryptMulti(jwe, keys.a256kw, { payload: "bytes" });
        expect(explicit.payload).toEqual(payload);
      });

      it("rejects a non-JSON-object payload under the default mode", async () => {
        const jwe = await encryptMulti("plain text", [{ key: keys.a256kw }], {
          enc: "A256GCM",
        });
        const error = await decryptMulti(jwe, keys.a256kw).catch((e) => e);
        expect(isJWTError(error, "ERR_JWE_INVALID")).toBe(true);
        expect(error.message).toBe("Invalid JWE: Payload is not a JSON object.");
      });

      it('returns a JSON-shaped string verbatim under payload: "string"', async () => {
        const jwe = await encryptMulti('{"sub":"admin"}', [{ key: keys.a256kw }], {
          enc: "A256GCM",
        });
        const { payload } = await decryptMulti(jwe, keys.a256kw, { payload: "string" });
        expect(payload).toBe('{"sub":"admin"}');
      });

      it('rejects validateClaims: true outside payload: "json"', async () => {
        const jwe = await encryptMulti({ x: 1 }, [{ key: keys.a256kw }], {
          enc: "A256GCM",
        });
        const error = await decryptMulti(jwe, keys.a256kw, {
          payload: "bytes",
          validateClaims: true,
        }).catch((e) => e);
        expect(isJWTError(error, "ERR_INVALID_OPTION")).toBe(true);
      });

      it("rejects a string key under a non-PBES2 recipient alg", async () => {
        const jwe = await encryptMulti({ x: 1 }, [{ key: keys.a256kw }], {
          enc: "A256GCM",
        });
        const error = await decryptMulti(jwe, "a-256-bit-secret-value-as-string", {
          algorithms: ["A256KW"],
        }).catch((e) => e);
        expect(isJWTError(error, "ERR_JWK_INVALID")).toBe(true);
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
        const { payload } = await decryptMulti(jweNoKid, set, { allowSymmetricJWKSet: true });
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
      // Key material without a `kid` (a CryptoKey) is unknown, not mismatched: the
      // recipient is matched on algorithm compatibility instead.
      it("matches a kid-bearing recipient by alg compatibility when the key is a CryptoKey", async () => {
        const jwe = await encryptMulti(
          { sub: "u1" },
          [{ key: keys.rsa256.publicKey }, { key: keys.a256kw }],
          { enc: "A256GCM" },
        );
        const cryptoKey = await crypto.subtle.importKey(
          "raw",
          base64UrlParse(keys.a256kw.k!, { returnAs: "uint8array" }),
          { name: "AES-KW" },
          false,
          ["wrapKey", "unwrapKey"],
        );
        const { payload, recipientIndex } = await decryptMulti(jwe, cryptoKey, {
          strictRecipientMatch: true,
          algorithms: ["A256KW"],
        });
        expect((payload as JWTClaims).sub).toBe("u1");
        expect(recipientIndex).toBe(1);
      });

      it("skips a recipient whose alg the key material cannot serve", async () => {
        const jwe = await encryptMulti({ sub: "u1" }, [{ key: keys.rsa256.publicKey }], {
          enc: "A256GCM",
        });
        const cryptoKey = await crypto.subtle.importKey(
          "raw",
          base64UrlParse(keys.a256kw.k!, { returnAs: "uint8array" }),
          { name: "AES-KW" },
          false,
          ["wrapKey", "unwrapKey"],
        );
        await expect(
          decryptMulti(jwe, cryptoKey, {
            strictRecipientMatch: true,
            algorithms: ["A256KW", "RSA-OAEP-256"],
          }),
        ).rejects.toSatisfy((e) => isJWTError(e, "ERR_JWE_NO_MATCHING_RECIPIENT"));
      });

      it("skips an ECDH recipient whose epk curve differs from the key curve", async () => {
        const jwe = await encryptMulti({ sub: "u1" }, [{ key: keys.ecdhP256.publicKey }], {
          enc: "A256GCM",
        });
        await expect(
          decryptMulti(jwe, keys.ecdhX25519.privateKey, { strictRecipientMatch: true }),
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
      expect(() => generalToFlattened(jwe)).toThrow(
        expect.objectContaining({ name: "JWTError", code: "ERR_JWE_INVALID_SERIALIZATION" }),
      );
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

  describe("codec failures wrap into JWTError", () => {
    async function general(): Promise<JWEGeneralSerialization> {
      return encryptMulti({ sub: "u1" }, [{ key: keys.a256kw }], { enc: "A256GCM" });
    }

    it("ERR_JWE_INVALID — malformed iv carries the UnsecureError cause", async () => {
      const jwe = await general();
      const error = await decryptMulti({ ...jwe, iv: `${jwe.iv}=` }, keys.a256kw).catch((e) => e);
      expect(error).toBeInstanceOf(JWTError);
      expect(isJWTError(error, "ERR_JWE_INVALID")).toBe(true);
      expect(error.message).toBe("Invalid JWE: Initialization vector could not be decoded.");
      expect(isUnsecureError(error.cause, "MALFORMED")).toBe(true);
    });

    it("ERR_JWE_INVALID — malformed ciphertext carries the UnsecureError cause", async () => {
      const jwe = await general();
      const error = await decryptMulti(
        { ...jwe, ciphertext: `${jwe.ciphertext}=` },
        keys.a256kw,
      ).catch((e) => e);
      expect(isJWTError(error, "ERR_JWE_INVALID")).toBe(true);
      expect(error.message).toBe("Invalid JWE: Ciphertext could not be decoded.");
      expect(isUnsecureError(error.cause, "MALFORMED")).toBe(true);
    });

    it("ERR_JWE_INVALID — malformed tag carries the UnsecureError cause", async () => {
      const jwe = await general();
      const error = await decryptMulti({ ...jwe, tag: `${jwe.tag}=` }, keys.a256kw).catch((e) => e);
      expect(isJWTError(error, "ERR_JWE_INVALID")).toBe(true);
      expect(error.message).toBe("Invalid JWE: Authentication tag could not be decoded.");
      expect(isUnsecureError(error.cause, "MALFORMED")).toBe(true);
    });

    it("ERR_JWE_INVALID — malformed encrypted_key carries the UnsecureError cause", async () => {
      const jwe = await general();
      const tampered: JWEGeneralSerialization = {
        ...jwe,
        recipients: [
          {
            ...jwe.recipients[0]!,
            encrypted_key: `${jwe.recipients[0]!.encrypted_key}=`,
          },
        ],
      };
      const error = await decryptMulti(tampered, keys.a256kw).catch((e) => e);
      expect(isJWTError(error, "ERR_JWE_INVALID")).toBe(true);
      expect(error.message).toBe("Invalid JWE: Encrypted key could not be decoded.");
      expect(isUnsecureError(error.cause, "MALFORMED")).toBe(true);
    });

    it("ERR_JWE_INVALID — malformed Flattened encrypted_key carries the cause", async () => {
      const flattened = generalToFlattened(await general());
      const error = await decryptMulti(
        { ...flattened, encrypted_key: `${flattened.encrypted_key}=` },
        keys.a256kw,
      ).catch((e) => e);
      expect(isJWTError(error, "ERR_JWE_INVALID")).toBe(true);
      expect(isUnsecureError(error.cause, "MALFORMED")).toBe(true);
    });
  });

  describe("RFC 7516 strictness — recipients, headers and segments", () => {
    function reheader(
      jwe: JWEGeneralSerialization,
      mutate: (header: Record<string, unknown>) => void,
    ): JWEGeneralSerialization {
      const header = JSON.parse(base64UrlParse(jwe.protected!) as string);
      mutate(header);
      return { ...jwe, protected: base64UrlStringify(JSON.stringify(header)) };
    }

    function prependRecipient(
      jwe: JWEGeneralSerialization,
      header: Record<string, unknown>,
    ): JWEGeneralSerialization {
      return {
        ...jwe,
        recipients: [
          { header, encrypted_key: jwe.recipients[0]!.encrypted_key },
          ...jwe.recipients,
        ],
      };
    }

    it("an injected recipient with an overlapping header does not block the holder", async () => {
      const jwe = await encryptMulti({ sub: "u1" }, [{ key: keys.a256kw }], { enc: "A256GCM" });
      const tampered = prependRecipient(jwe, { alg: "A256KW", enc: "A256GCM" });
      const { payload, recipientIndex } = await decryptMulti(tampered, keys.a256kw);
      expect((payload as JWTClaims).sub).toBe("u1");
      expect(recipientIndex).toBe(1);
    });

    it("an injected PBES2 recipient without p2s does not block the holder", async () => {
      const password: JWK_oct<"PBES2-HS256+A128KW"> = {
        kty: "oct",
        alg: "PBES2-HS256+A128KW",
        k: base64UrlStringify(secureRandomBytes(32)),
      };
      const jwe = await encryptMulti({ sub: "u1" }, [{ key: password, p2c: 2048 }], {
        enc: "A256GCM",
      });
      const tampered = prependRecipient(jwe, { alg: "PBES2-HS256+A128KW" });
      const { payload, recipientIndex } = await decryptMulti(tampered, password);
      expect((payload as JWTClaims).sub).toBe("u1");
      expect(recipientIndex).toBe(1);
    });

    it("an injected ECDH recipient without epk does not block the holder", async () => {
      const jwe = await encryptMulti({ sub: "u1" }, [{ key: keys.ecdhP256.publicKey }], {
        enc: "A256GCM",
      });
      const tampered = prependRecipient(jwe, { alg: "ECDH-ES+A256KW" });
      const { payload, recipientIndex } = await decryptMulti(tampered, keys.ecdhP256.privateKey);
      expect((payload as JWTClaims).sub).toBe("u1");
      expect(recipientIndex).toBe(1);
    });

    it("an injected AES-GCMKW recipient without iv/tag does not block the holder", async () => {
      const jwe = await encryptMulti({ sub: "u1" }, [{ key: keys.a256gcmkw }], { enc: "A256GCM" });
      const tampered = prependRecipient(jwe, { alg: "A256GCMKW" });
      const { payload, recipientIndex } = await decryptMulti(tampered, keys.a256gcmkw);
      expect((payload as JWTClaims).sub).toBe("u1");
      expect(recipientIndex).toBe(1);
    });

    it("rejects a non-empty encrypted_key for ECDH-ES", async () => {
      const pair = await generateJWK("ECDH-ES", { namedCurve: "P-256" });
      const compact = await encrypt({ sub: "u1" }, pair.publicKey, {
        alg: "ECDH-ES",
        enc: "A256GCM",
      });
      const [protectedHeader, , iv, ciphertext, tag] = compact.split(".");
      const flattened: JWEFlattenedSerialization = {
        protected: protectedHeader,
        encrypted_key: base64UrlStringify(secureRandomBytes(40)),
        iv,
        ciphertext: ciphertext!,
        tag,
      };
      const error = await decryptMulti(flattened, pair.privateKey).catch((e) => e);
      expect(isJWTError(error, "ERR_JWE_INVALID")).toBe(true);
      expect(error.message).toBe("Invalid JWE: Encrypted key must be empty for ECDH-ES.");
    });

    it("rejects an authentication tag grown out of the ciphertext", async () => {
      const jwe = await encryptMulti({ sub: "u1" }, [{ key: keys.a256kw }], { enc: "A256GCM" });
      const ciphertext = base64UrlParse(jwe.ciphertext, { returnAs: "uint8array" });
      const tag = base64UrlParse(jwe.tag!, { returnAs: "uint8array" });
      const shifted = ciphertext.subarray(ciphertext.length - 4);
      const tampered: JWEGeneralSerialization = {
        ...jwe,
        ciphertext: base64UrlStringify(ciphertext.subarray(0, ciphertext.length - 4)),
        tag: base64UrlStringify(new Uint8Array([...shifted, ...tag])),
      };
      const error = await decryptMulti(tampered, keys.a256kw).catch((e) => e);
      expect(isJWTError(error, "ERR_JWE_INVALID")).toBe(true);
      expect(error.message).toBe(
        "Invalid JWE: Authentication tag must be 16 bytes for A256GCM (got 20).",
      );
    });

    it("rejects a protected header carrying zip", async () => {
      const jwe = await encryptMulti({ sub: "u1" }, [{ key: keys.a256kw }], { enc: "A256GCM" });
      const tampered = reheader(jwe, (h) => {
        h.zip = "DEF";
      });
      const error = await decryptMulti(tampered, keys.a256kw).catch((e) => e);
      expect(isJWTError(error, "ERR_JWE_INVALID")).toBe(true);
      expect(error.message).toBe("Invalid JWE: compression is not supported.");
    });

    it("refuses zip in every header tier on encryptMulti", async () => {
      const zipProtected = await encryptMulti({ sub: "u1" }, [{ key: keys.a256kw }], {
        enc: "A256GCM",
        // @ts-expect-error `zip` is not an accepted protected header parameter
        protectedHeader: { zip: "DEF" },
      }).catch((e) => e);
      expect(isJWTError(zipProtected, "ERR_INVALID_OPTION")).toBe(true);

      const zipShared = await encryptMulti({ sub: "u1" }, [{ key: keys.a256kw }], {
        enc: "A256GCM",
        sharedUnprotectedHeader: { zip: "DEF" },
      }).catch((e) => e);
      expect(isJWTError(zipShared, "ERR_INVALID_OPTION")).toBe(true);

      const zipRecipient = await encryptMulti(
        { sub: "u1" },
        // @ts-expect-error `zip` is not an accepted per-recipient header parameter
        [{ key: keys.a256kw, header: { zip: "DEF" } }],
        { enc: "A256GCM" },
      ).catch((e) => e);
      expect(isJWTError(zipRecipient, "ERR_INVALID_OPTION")).toBe(true);
    });

    it("rejects crit in the shared unprotected header", async () => {
      const jwe = await encryptMulti({ sub: "u1" }, [{ key: keys.a256kw }], { enc: "A256GCM" });
      const tampered: JWEGeneralSerialization = { ...jwe, unprotected: { crit: ["myparam"] } };
      const error = await decryptMulti(tampered, keys.a256kw).catch((e) => e);
      expect(isJWTError(error, "ERR_JWE_INVALID")).toBe(true);
      expect(error.message).toMatch(/"crit" must be integrity protected/);
    });

    it("a per-recipient crit skips that recipient only", async () => {
      const jwe = await encryptMulti({ sub: "u1" }, [{ key: keys.a256kw }], { enc: "A256GCM" });
      const tampered = prependRecipient(jwe, { alg: "A256KW", crit: ["myparam"] });
      const { recipientIndex } = await decryptMulti(tampered, keys.a256kw);
      expect(recipientIndex).toBe(1);
    });

    it("validates crit before key management", async () => {
      const jwe = await encryptMulti({ sub: "u1" }, [{ key: keys.a256kw }], { enc: "A256GCM" });
      const tampered = reheader(jwe, (h) => {
        h.crit = ["myparam"];
      });
      const wrongKey = await generateJWK("A256KW");
      const error = await decryptMulti(tampered, wrongKey).catch((e) => e);
      expect(isJWTError(error, "ERR_JWE_INVALID")).toBe(true);
      expect(error.message).toMatch(/"myparam"/);
    });

    it("rejects an unsupported enc before key management", async () => {
      const jwe = await encryptMulti({ sub: "u1" }, [{ key: keys.a256kw }], { enc: "A256GCM" });
      const tampered = reheader(jwe, (h) => {
        h.enc = "A256CBC";
      });
      const error = await decryptMulti(tampered, keys.a256kw).catch((e) => e);
      expect(isJWTError(error, "ERR_JWE_INVALID")).toBe(true);
      expect(error.message).toBe('Invalid JWE: unsupported "enc" A256CBC');
    });

    it('rejects a recipient alg of "none" even when allowlisted', async () => {
      const jwe = await encryptMulti({ sub: "u1" }, [{ key: keys.a256kw }], { enc: "A256GCM" });
      const tampered: JWEGeneralSerialization = {
        ...jwe,
        recipients: [{ header: { alg: "none" }, encrypted_key: "" }],
      };
      const error = await decryptMulti(tampered, keys.a256kw, {
        algorithms: ["none" as KeyManagementAlgorithm],
      }).catch((e) => e);
      expect(isJWTError(error, "ERR_JWE_ALG_NOT_ALLOWED")).toBe(true);
    });

    it("compares typ under media-type normalization", async () => {
      const jwe = await encryptMulti({ sub: "u1" }, [{ key: keys.a256kw }], {
        enc: "A256GCM",
        protectedHeader: { typ: "application/AT+JWT" },
      });
      await expect(decryptMulti(jwe, keys.a256kw, { typ: "at+jwt" })).resolves.toBeDefined();
      const error = await decryptMulti(jwe, keys.a256kw, { typ: "other+jwt" }).catch((e) => e);
      expect(isJWTError(error, "ERR_JWE_INVALID")).toBe(true);
      expect(error.message).toMatch(/"typ"/);
    });
  });
});

describe.concurrent("encryptMulti producer option gates", () => {
  let aesKey: JWK_oct<"A256KW">;
  let ecdhKey: JWK_Pair<"ECDH-ES+A256KW">;

  beforeAll(async () => {
    [aesKey, ecdhKey] = await Promise.all([generateJWK("A256KW"), generateJWK("ECDH-ES+A256KW")]);
  });

  it.each([
    ["too short", secureRandomBytes(16)],
    ["not bytes", "a cek" as never],
  ])("refuses a cek that is %s", async (_label, cek) => {
    const error = await encryptMulti("payload", [{ key: aesKey }], {
      enc: "A256GCM",
      cek,
    }).catch((e) => e);
    expect(isJWTError(error, "ERR_INVALID_OPTION")).toBe(true);
    expect(error.message).toContain('"cek"');
  });

  it("refuses a content encryption IV of the wrong length", async () => {
    const error = await encryptMulti("payload", [{ key: aesKey }], {
      enc: "A256GCM",
      contentEncryptionIV: secureRandomBytes(16),
    }).catch((e) => e);
    expect(isJWTError(error, "ERR_INVALID_OPTION")).toBe(true);
    expect(error.message).toContain('"contentEncryptionIV"');
  });

  it("accepts a cek of the size enc names", async () => {
    const cek = secureRandomBytes(32);
    const jwe = await encryptMulti("payload", [{ key: aesKey }], { enc: "A256GCM", cek });
    const { payload } = await decryptMulti(jwe, aesKey, { payload: "string" });
    expect(payload).toBe("payload");
  });

  it("refuses a crit the protected header does not carry", async () => {
    const error = await encryptMulti("payload", [{ key: aesKey }], {
      protectedHeader: { crit: ["app"] },
    }).catch((e) => e);
    expect(isJWTError(error, "ERR_INVALID_OPTION")).toBe(true);
    expect(error.message).toContain("app");
  });

  it("refuses a crit listing a registered header parameter", async () => {
    const error = await encryptMulti("payload", [{ key: aesKey }], {
      protectedHeader: { crit: ["enc"] },
    }).catch((e) => e);
    expect(isJWTError(error, "ERR_INVALID_OPTION")).toBe(true);
  });

  it("refuses a protected header that cannot be serialized", async () => {
    const error = await encryptMulti("payload", [{ key: aesKey }], {
      protectedHeader: { n: 1n } as never,
    }).catch((e) => e);
    expect(isJWTError(error, "ERR_INVALID_OPTION")).toBe(true);
    expect(error.message).toContain("protected header");
  });

  it.each(["partyUInfo", "partyVInfo"] as const)(
    "refuses a recipient %s that is not bytes",
    async (name) => {
      const error = await encryptMulti("payload", [
        { key: ecdhKey.publicKey, ecdh: { [name]: "not-bytes" } as never },
      ]).catch((e) => e);
      expect(isJWTError(error, "ERR_INVALID_OPTION")).toBe(true);
    },
  );

  it("refuses recipient party info over 1024 bytes", async () => {
    const error = await encryptMulti("payload", [
      { key: ecdhKey.publicKey, ecdh: { partyVInfo: secureRandomBytes(1025) } },
    ]).catch((e) => e);
    expect(isJWTError(error, "ERR_INVALID_OPTION")).toBe(true);
    expect(error.message).toContain("1024");
  });
});

describe.concurrent("encryptMulti header tiers", () => {
  let key: JWK_oct<"A256KW">;

  beforeAll(async () => {
    key = await generateJWK("A256KW");
  });

  it("refuses crit in the shared unprotected header", async () => {
    const error = await encryptMulti("payload", [{ key }], {
      sharedUnprotectedHeader: { crit: ["app"], app: "web" },
    }).catch((e) => e);
    expect(isJWTError(error, "ERR_INVALID_OPTION")).toBe(true);
    expect(error.message).toContain('"crit"');
  });

  it("refuses crit in a per-recipient header", async () => {
    const error = await encryptMulti("payload", [
      { key, header: { crit: ["app"], app: "web" } as never },
    ]).catch((e) => e);
    expect(isJWTError(error, "ERR_INVALID_OPTION")).toBe(true);
    expect(error.message).toContain('"crit"');
  });

  it.each([
    ["null", null],
    ["a string", "recipient"],
    ["an array", []],
  ])("refuses a recipient entry that is %s", async (_label, recipient) => {
    const error = await encryptMulti("payload", [{ key }, recipient as never]).catch((e) => e);
    expect(isJWTError(error, "ERR_INVALID_OPTION")).toBe(true);
    expect(error.message).toBe('"recipients[1]" must be an object.');
  });

  it("refuses a per-recipient header that is not an object", async () => {
    const error = await encryptMulti("payload", [{ key, header: "abc" as never }]).catch((e) => e);
    expect(isJWTError(error, "ERR_INVALID_OPTION")).toBe(true);
    expect(error.message).toBe('"recipients[0].header" must be an object.');
  });

  it.each(["protectedHeader", "sharedUnprotectedHeader"])(
    "refuses a %s option that is not an object",
    async (member) => {
      const error = await encryptMulti("payload", [{ key }], { [member]: "abc" } as never).catch(
        (e) => e,
      );
      expect(isJWTError(error, "ERR_INVALID_OPTION")).toBe(true);
      expect(error.message).toBe(`"options.${member}" must be an object.`);
    },
  );

  it("reads typ from the protected header only", async () => {
    const jwe = await encryptMulti("payload", [{ key, header: { typ: "at+jwt" } }], {
      sharedUnprotectedHeader: { cty: "text/plain" },
    });
    const error = await decryptMulti(jwe, key, { typ: "at+jwt", payload: "string" }).catch(
      (e) => e,
    );
    expect(isJWTError(error, "ERR_JWE_INVALID")).toBe(true);
    expect(error.message).toBe(
      'Invalid JWE: the protected header carries no "typ"; expected "at+jwt".',
    );
  });
});

describe.concurrent("JWE JSON serialization entries", () => {
  let a128kw: JWK_oct<"A128KW">;
  let a256kw: JWK_oct<"A256KW">;

  beforeAll(async () => {
    [a128kw, a256kw] = await Promise.all([generateJWK("A128KW"), generateJWK("A256KW")]);
  });

  const notObjects: [string, unknown][] = [
    ["null", null],
    ["a number", 42],
    ["a string", "recipient"],
    ["an array", []],
  ];

  it.each(notObjects)(
    "decryptMulti treats %s in recipients as that entry's failure",
    async (_label, entry) => {
      const jwe = await encryptMulti({ sub: "u1" }, [{ key: a256kw }], { enc: "A256GCM" });
      const mixed = { ...jwe, recipients: [entry, jwe.recipients[0]!] } as JWEGeneralSerialization;
      const { recipientIndex } = await decryptMulti(mixed, a256kw);
      expect(recipientIndex).toBe(1);

      const lone = { ...jwe, recipients: [entry] } as JWEGeneralSerialization;
      const error = await decryptMulti(lone, a256kw).catch((e) => e);
      expect(isJWTError(error, "ERR_JWE_INVALID")).toBe(true);
    },
  );

  it.each([...notObjects.filter(([label]) => label !== "an array"), ["an array", [1]]])(
    "a recipient whose header is %s fails without aborting the next one",
    async (_label, header) => {
      const jwe = await encryptMulti({ sub: "u1" }, [{ key: a128kw }, { key: a256kw }], {
        enc: "A256GCM",
      });
      const mixed = {
        ...jwe,
        recipients: [{ ...jwe.recipients[1]!, header }, jwe.recipients[1]!],
      } as JWEGeneralSerialization;
      const { recipientIndex } = await decryptMulti(mixed, a256kw);
      expect(recipientIndex).toBe(1);
    },
  );

  it("a recipient whose encrypted_key is not a string fails without aborting the next one", async () => {
    const jwe = await encryptMulti({ sub: "u1" }, [{ key: a256kw }], { enc: "A256GCM" });
    const mixed = {
      ...jwe,
      recipients: [{ ...jwe.recipients[0]!, encrypted_key: 7 }, jwe.recipients[0]!],
    } as unknown as JWEGeneralSerialization;
    const { recipientIndex } = await decryptMulti(mixed, a256kw);
    expect(recipientIndex).toBe(1);
  });

  it.each(notObjects)(
    "rejects a Flattened JWE whose header is %s as ERR_JWE_INVALID",
    async (_label, header) => {
      const flat = generalToFlattened(
        await encryptMulti({ sub: "u1" }, [{ key: a256kw }], { enc: "A256GCM" }),
      );
      const tampered = { ...flat, header } as JWEFlattenedSerialization;
      const error = await decryptMulti(tampered, a256kw).catch((e) => e);
      expect(isJWTError(error, "ERR_JWE_INVALID")).toBe(true);
    },
  );

  it.each(notObjects)(
    "rejects a shared unprotected header that is %s as ERR_JWE_INVALID",
    async (_label, unprotected) => {
      const jwe = await encryptMulti({ sub: "u1" }, [{ key: a256kw }], { enc: "A256GCM" });
      const tampered = { ...jwe, unprotected } as JWEGeneralSerialization;
      const error = await decryptMulti(tampered, a256kw).catch((e) => e);
      expect(isJWTError(error, "ERR_JWE_INVALID")).toBe(true);
    },
  );
});

describe.concurrent("JWE enc in the shared unprotected header", () => {
  const bytes = textEncoder.encode("payload bytes");
  let key: JWK_oct<"A256KW">;

  beforeAll(async () => {
    key = await generateJWK("A256KW");
  });

  async function generalWithSharedEnc(
    enc: string = "A256GCM",
    protectedHeader?: Record<string, unknown>,
  ): Promise<JWEGeneralSerialization> {
    const builder = new jose.GeneralEncrypt(bytes).setSharedUnprotectedHeader({ enc });
    if (protectedHeader) builder.setProtectedHeader(protectedHeader);
    builder.addRecipient(await jose.importJWK(key)).setUnprotectedHeader({ alg: "A256KW" });
    return (await builder.encrypt()) as unknown as JWEGeneralSerialization;
  }

  it("decryptMulti accepts enc carried only in the shared unprotected header", async () => {
    const result = await decryptMulti(await generalWithSharedEnc(), key, { payload: "bytes" });
    expect(result.payload).toEqual(bytes);
    expect(result.sharedUnprotectedHeader).toEqual({ enc: "A256GCM" });
    expect(result.recipientHeader).toEqual({ alg: "A256KW" });
    expect(result.protectedHeader).toEqual({});
  });

  it("decryptMulti accepts a Flattened JWE with no protected member", async () => {
    const flat = (await new jose.FlattenedEncrypt(bytes)
      .setSharedUnprotectedHeader({ enc: "A128GCM" })
      .setUnprotectedHeader({ alg: "A256KW" })
      .encrypt(await jose.importJWK(key))) as unknown as JWEFlattenedSerialization;
    const result = await decryptMulti(flat, key, { payload: "bytes" });
    expect(result.payload).toEqual(bytes);
    expect(result.protectedHeader).toEqual({});
  });

  it("reports the protected header without members it did not protect", async () => {
    const jwe = await encryptMulti({ sub: "u1" }, [{ key }], {
      enc: "A256GCM",
      protectedHeader: { typ: "JWT" },
    });
    const result = await decryptMulti(jwe, key);
    expect(result.protectedHeader.alg).toBeUndefined();
    expect(result.protectedHeader).toMatchObject({ enc: "A256GCM", typ: "JWT" });
    expect(result.recipientHeader?.alg).toBe("A256KW");
  });

  it("applies the encryptionAlgorithms allowlist to a shared enc", async () => {
    const error = await decryptMulti(await generalWithSharedEnc(), key, {
      payload: "bytes",
      encryptionAlgorithms: ["A128GCM"],
    }).catch((e) => e);
    expect(isJWTError(error, "ERR_JWE_ALG_NOT_ALLOWED")).toBe(true);
  });

  it("rejects an unsupported shared enc", async () => {
    const jwe = await generalWithSharedEnc();
    const tampered = { ...jwe, unprotected: { enc: "A256CBC" } } as JWEGeneralSerialization;
    const error = await decryptMulti(tampered, key, { payload: "bytes" }).catch((e) => e);
    expect(isJWTError(error, "ERR_JWE_INVALID")).toBe(true);
    expect(error.message).toBe('Invalid JWE: unsupported "enc" A256CBC');
  });

  it("rejects enc carried in both the protected and the shared unprotected header", async () => {
    const jwe = await generalWithSharedEnc();
    const tampered = {
      ...jwe,
      protected: base64UrlStringify(JSON.stringify({ enc: "A256GCM" })),
    } as JWEGeneralSerialization;
    const error = await decryptMulti(tampered, key, { payload: "bytes" }).catch((e) => e);
    expect(isJWTError(error, "ERR_JWE_HEADER_PARAMS_NOT_DISJOINT")).toBe(true);
  });

  it("rejects enc carried only in a per-recipient header", async () => {
    const jwe = await generalWithSharedEnc();
    const { unprotected: _shared, ...rest } = jwe;
    const tampered = {
      ...rest,
      recipients: [{ ...jwe.recipients[0]!, header: { alg: "A256KW", enc: "A256GCM" } }],
    } as JWEGeneralSerialization;
    const error = await decryptMulti(tampered, key, { payload: "bytes" }).catch((e) => e);
    expect(isJWTError(error, "ERR_JWE_INVALID")).toBe(true);
    expect(error.message).toContain('"enc"');
  });
});

describe.concurrent("JWE JSON additional authenticated data and option gates", () => {
  let key: JWK_oct<"A256KW">;
  let jwe: JWEGeneralSerialization;

  beforeAll(async () => {
    key = await generateJWK("A256KW");
    jwe = await encryptMulti({ sub: "u" }, [{ key }], { enc: "A256GCM" });
  });

  it("omits an empty aad from the token (RFC 7516 §7.2.1)", async () => {
    for (const aad of ["", new Uint8Array(0)]) {
      const withEmptyAad = await encryptMulti("payload", [{ key }], { aad });
      expect(withEmptyAad).not.toHaveProperty("aad");
      const { payload } = await decryptMulti(withEmptyAad, key, { payload: "string" });
      expect(payload).toBe("payload");
    }
  });

  it("opens a token whose aad member is present but empty (RFC 7516 §5.2 step 15)", async () => {
    const protectedHeader = base64UrlStringify(JSON.stringify({ alg: "A256KW", enc: "A256GCM" }));
    const cek = secureRandomBytes(32);
    const { encryptedKey } = await wrapKey(cek, key, { alg: "A256KW" });
    const iv = secureRandomBytes(12);
    const sealed = new Uint8Array(
      await crypto.subtle.encrypt(
        { name: "AES-GCM", iv, additionalData: textEncoder.encode(`${protectedHeader}.`) },
        await crypto.subtle.importKey("raw", cek, "AES-GCM", false, ["encrypt"]),
        textEncoder.encode("payload"),
      ),
    );
    const token: JWEFlattenedSerialization = {
      protected: protectedHeader,
      encrypted_key: base64UrlStringify(encryptedKey),
      iv: base64UrlStringify(iv),
      ciphertext: base64UrlStringify(sealed.slice(0, -16)),
      tag: base64UrlStringify(sealed.slice(-16)),
      aad: "",
    };
    const { payload, aad } = await decryptMulti(token, key, { payload: "string", returnCek: true });
    expect(payload).toBe("payload");
    expect(textDecoder.decode(aad)).toBe(`${protectedHeader}.`);
  });

  it.each([
    ["a number", 123],
    ["an object", { a: 1 }],
    ["null", null],
  ])("refuses an aad that is %s", async (_label, aad) => {
    const error = await encryptMulti("payload", [{ key }], { aad } as never).catch((e) => e);
    expect(isJWTError(error, "ERR_INVALID_OPTION")).toBe(true);
    expect(error.message).toBe('"aad" must be a string or a Uint8Array.');
  });

  it("honours extractable: false for the unwrapped content encryption key", async () => {
    const error = await decryptMulti(jwe, key, { returnCek: true, extractable: false }).catch(
      (e) => e,
    );
    expect(isJWTError(error, "ERR_INVALID_OPTION")).toBe(true);
    expect(error.message).toContain('"returnCek"');
  });

  it.each([
    ["an empty typ", { typ: "" }],
    [
      "an encryptionAlgorithms allowlist that is not an array",
      { encryptionAlgorithms: "A256GCM-disabled" },
    ],
    ["an algorithms allowlist that is not an array", { algorithms: "A256KW-disabled" }],
    ["requiredClaims that is not an array", { requiredClaims: "sub" }],
  ])("decryptMulti refuses %s", async (_label, options) => {
    const error = await decryptMulti(jwe, key, options as never).catch((e) => e);
    expect(isJWTError(error, "ERR_INVALID_OPTION")).toBe(true);
  });
});
