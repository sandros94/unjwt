import * as jose from "jose";
import { describe, it, expect, beforeAll } from "vitest";
import { textEncoder, textDecoder } from "unsecure";
import {
  signMulti,
  verifyMulti,
  verifyMultiAll,
  generalToFlattenedJWS,
  isJWTError,
} from "../src/core/jws";
import { generateJWK } from "../src/core/jwk";
import type {
  JWK,
  JWK_RSA_Public,
  JWK_RSA_Private,
  JWK_EC_Public,
  JWK_EC_Private,
  JWK_OKP_Public,
  JWK_OKP_Private,
  JWK_Symmetric,
  JWKSet,
  JWSGeneralSerialization,
  JWSFlattenedSerialization,
  JWKLookupFunction,
  JWTClaims,
} from "../src/core/types";

describe.concurrent("JWS Multi-signature (General JSON Serialization)", () => {
  const keys: {
    rs256: { publicKey: JWK_RSA_Public; privateKey: JWK_RSA_Private };
    ps256: { publicKey: JWK_RSA_Public; privateKey: JWK_RSA_Private };
    es256: { publicKey: JWK_EC_Public; privateKey: JWK_EC_Private };
    ed25519: { publicKey: JWK_OKP_Public; privateKey: JWK_OKP_Private };
    hs256: JWK_Symmetric;
    hs384: JWK_Symmetric;
  } = {} as any;

  beforeAll(async () => {
    const [rs256, ps256, es256, ed25519, hs256, hs384] = await Promise.all([
      generateJWK("RS256", { modulusLength: 2048 }),
      generateJWK("PS256", { modulusLength: 2048 }),
      generateJWK("ES256"),
      generateJWK("Ed25519"),
      generateJWK("HS256"),
      generateJWK("HS384"),
    ]);
    keys.rs256 = rs256 as typeof keys.rs256;
    keys.ps256 = ps256 as typeof keys.ps256;
    keys.es256 = es256 as typeof keys.es256;
    keys.ed25519 = ed25519 as typeof keys.ed25519;
    keys.hs256 = hs256 as JWK_Symmetric;
    keys.hs384 = hs384 as JWK_Symmetric;
  });

  describe("signMulti", () => {
    it("signs with 4 signers (RSA + PSS + ECDSA + Ed25519)", async () => {
      const jws = await signMulti({ sub: "u1" }, [
        { key: keys.rs256.privateKey },
        { key: keys.ps256.privateKey },
        { key: keys.es256.privateKey },
        { key: keys.ed25519.privateKey },
      ]);
      expect(jws.signatures).toHaveLength(4);
      expect(jws.payload).toBeTypeOf("string");
      // Protected headers carry per-signer alg
      const algs = jws.signatures.map(
        (s) => JSON.parse(Buffer.from(s.protected!, "base64url").toString("utf8")).alg,
      );
      expect(algs).toEqual(["RS256", "PS256", "ES256", "Ed25519"]);
    });

    it("emits General shape for a single signer (not Flattened)", async () => {
      const jws = await signMulti({ x: 1 }, [{ key: keys.hs256 }]);
      expect(Array.isArray(jws.signatures)).toBe(true);
      expect(jws.signatures).toHaveLength(1);
      expect("signature" in (jws as any)).toBe(false);
      expect("protected" in (jws as any)).toBe(false);
    });

    it("applies JWT claim auto-generation to the shared payload (iat, exp)", async () => {
      const jws = await signMulti({ sub: "u1" }, [{ key: keys.hs256 }], {
        expiresIn: "1h",
      });
      const { payload } = await verifyMulti<JWTClaims>(jws, keys.hs256);
      expect(payload.iat).toBeTypeOf("number");
      expect(payload.exp).toBeTypeOf("number");
      expect(payload.exp! - payload.iat!).toBe(3600);
    });

    it("propagates kid from JWK to per-signer protected header", async () => {
      const jws = await signMulti({ x: 1 }, [{ key: keys.hs256 }]);
      const protectedHeader = JSON.parse(
        Buffer.from(jws.signatures[0]!.protected!, "base64url").toString("utf8"),
      );
      expect(protectedHeader.kid).toBe(keys.hs256.kid);
    });

    it("preserves per-signer protectedHeader additions", async () => {
      const jws = await signMulti({ x: 1 }, [
        { key: keys.rs256.privateKey, protectedHeader: { typ: "vc+jwt" } },
        { key: keys.hs256 },
      ]);
      const h0 = JSON.parse(Buffer.from(jws.signatures[0]!.protected!, "base64url").toString());
      const h1 = JSON.parse(Buffer.from(jws.signatures[1]!.protected!, "base64url").toString());
      expect(h0.typ).toBe("vc+jwt");
      expect(h1.typ).toBe("JWT"); // default for object payloads
    });

    it("preserves per-signer unprotected header extras", async () => {
      const jws = await signMulti({ x: 1 }, [
        { key: keys.hs256, unprotectedHeader: { "x-region": "eu" } },
        { key: keys.hs384, unprotectedHeader: { "x-region": "us" } },
      ]);
      expect(jws.signatures[0]?.header?.["x-region"]).toBe("eu");
      expect(jws.signatures[1]?.header?.["x-region"]).toBe("us");
    });

    it("throws on empty signers array", async () => {
      await expect(signMulti({ x: 1 }, [])).rejects.toSatisfy((e) =>
        isJWTError(e, "ERR_JWS_INVALID"),
      );
    });

    it("throws ERR_JWS_SIGNER_ALG_INFERENCE when JWK has no alg", async () => {
      const noAlg: JWK = { ...keys.hs256 };
      delete (noAlg as { alg?: string }).alg;
      await expect(signMulti({ x: 1 }, [{ key: noAlg }])).rejects.toSatisfy((e) =>
        isJWTError(e, "ERR_JWS_SIGNER_ALG_INFERENCE"),
      );
    });

    it('throws on "none" alg', async () => {
      await expect(
        signMulti({ x: 1 }, [{ key: { ...keys.hs256, alg: "none" } as JWK }]),
      ).rejects.toSatisfy((e) => isJWTError(e, "ERR_JWS_ALG_NOT_ALLOWED"));
    });

    it("throws ERR_JWS_HEADER_PARAMS_NOT_DISJOINT on header overlap", async () => {
      await expect(
        signMulti({ x: 1 }, [
          {
            key: keys.hs256,
            protectedHeader: { typ: "JWT" },
            unprotectedHeader: { typ: "JWT" },
          },
        ]),
      ).rejects.toSatisfy((e) => isJWTError(e, "ERR_JWS_HEADER_PARAMS_NOT_DISJOINT"));
    });

    it("throws ERR_JWS_B64_INCONSISTENT when signers disagree on b64", async () => {
      await expect(
        signMulti({ x: 1 } as unknown as string, [
          { key: keys.hs256, protectedHeader: { b64: false } },
          { key: keys.hs384, protectedHeader: { b64: true } },
        ]),
      ).rejects.toSatisfy((e) => isJWTError(e, "ERR_JWS_B64_INCONSISTENT"));
    });

    it("round-trips b64:false (RFC 7797) when all signers agree", async () => {
      const jws = await signMulti("raw-payload", [
        { key: keys.hs256, protectedHeader: { b64: false } },
        { key: keys.hs384, protectedHeader: { b64: false } },
      ]);
      // Raw payload field, not base64url-encoded
      expect(jws.payload).toBe("raw-payload");
      const { payload } = await verifyMulti(jws, keys.hs256);
      expect(payload).toBe("raw-payload");
    });
  });

  describe("verifyMulti", () => {
    it("verifies using the first signer's key", async () => {
      const jws = await signMulti({ sub: "u1" }, [
        { key: keys.rs256.privateKey },
        { key: keys.hs256 },
      ]);
      const { payload, signerIndex } = await verifyMulti(jws, keys.rs256.publicKey);
      expect((payload as JWTClaims).sub).toBe("u1");
      expect(signerIndex).toBe(0);
    });

    it("verifies using the second signer's key", async () => {
      const jws = await signMulti({ sub: "u1" }, [
        { key: keys.rs256.privateKey },
        { key: keys.hs256 },
      ]);
      const { payload, signerIndex } = await verifyMulti(jws, keys.hs256);
      expect((payload as JWTClaims).sub).toBe("u1");
      expect(signerIndex).toBe(1);
    });

    it("surfaces signerHeader for per-signer unprotected header", async () => {
      const jws = await signMulti({ x: 1 }, [
        { key: keys.hs256, unprotectedHeader: { "x-route": "r1" } },
      ]);
      const { signerHeader } = await verifyMulti(jws, keys.hs256);
      expect(signerHeader?.["x-route"]).toBe("r1");
    });

    it("accepts Flattened JSON Serialization input", async () => {
      const general = await signMulti({ x: 1 }, [{ key: keys.hs256 }]);
      const flattened: JWSFlattenedSerialization = {
        payload: general.payload,
        protected: general.signatures[0]?.protected,
        signature: general.signatures[0]!.signature,
      };
      const { payload } = await verifyMulti(flattened, keys.hs256);
      expect((payload as Record<string, unknown>).x).toBe(1);
    });

    it("accepts a JWKSet and finds the matching key", async () => {
      const jws = await signMulti({ sub: "u1" }, [
        { key: keys.rs256.privateKey },
        { key: keys.hs256 },
      ]);
      const otherHmac = (await generateJWK("HS256")) as JWK_Symmetric;
      const set: JWKSet = { keys: [otherHmac, keys.hs256] };
      const { payload, signerIndex } = await verifyMulti(jws, set);
      expect((payload as JWTClaims).sub).toBe("u1");
      expect(signerIndex).toBe(1);
    });

    it("accepts a JWKLookupFunction", async () => {
      const jws = await signMulti({ sub: "u1" }, [
        { key: keys.rs256.privateKey },
        { key: keys.hs256 },
      ]);
      const lookup: JWKLookupFunction = (header) => {
        if (header.kid === keys.hs256.kid) return keys.hs256;
        if (header.kid === keys.rs256.publicKey.kid) return keys.rs256.publicKey;
        throw new Error("no key");
      };
      const { payload } = await verifyMulti(jws, lookup);
      expect((payload as JWTClaims).sub).toBe("u1");
    });

    it("validates JWT claims on the payload", async () => {
      const jws = await signMulti({ sub: "u1", exp: Math.floor(Date.now() / 1000) - 10 }, [
        { key: keys.hs256 },
      ]);
      await expect(verifyMulti(jws, keys.hs256)).rejects.toSatisfy((e) =>
        isJWTError(e, "ERR_JWT_EXPIRED"),
      );
    });

    it("forceUint8Array returns payload as Uint8Array", async () => {
      const jws = await signMulti({ x: 1 }, [{ key: keys.hs256 }]);
      const { payload } = await verifyMulti(jws, keys.hs256, { forceUint8Array: true });
      expect(payload).toBeInstanceOf(Uint8Array);
    });

    it("fails when signature has been tampered with across all signers", async () => {
      const jws = await signMulti({ x: 1 }, [{ key: keys.rs256.privateKey }, { key: keys.hs256 }]);
      const tampered: JWSGeneralSerialization = {
        ...jws,
        signatures: jws.signatures.map((s) => ({
          ...s,
          signature: s.signature.slice(0, -2) + "AA",
        })),
      };
      await expect(verifyMulti(tampered, keys.hs256)).rejects.toSatisfy((e) =>
        isJWTError(e, "ERR_JWS_SIGNATURE_INVALID"),
      );
    });

    it("honors crit header via options.recognizedHeaders", async () => {
      const jws = await signMulti({ x: 1 }, [
        { key: keys.hs256, protectedHeader: { crit: ["app"], app: "web" } },
      ]);
      const { protectedHeader } = await verifyMulti(jws, keys.hs256, {
        recognizedHeaders: ["app"],
      });
      expect(protectedHeader.app).toBe("web");
    });

    describe("strictSignerMatch", () => {
      it("skips signatures whose kid does not match the key kid", async () => {
        const jws = await signMulti({ sub: "u1" }, [
          { key: keys.rs256.privateKey },
          { key: keys.hs256 },
        ]);
        const { signerIndex } = await verifyMulti(jws, keys.hs256, {
          strictSignerMatch: true,
        });
        expect(signerIndex).toBe(1);
      });

      it("throws ERR_JWS_NO_MATCHING_SIGNER when no kid matches", async () => {
        const jws = await signMulti({ x: 1 }, [{ key: keys.hs256 }]);
        const unrelated: JWK_Symmetric = { ...keys.hs384, kid: "unrelated" };
        await expect(verifyMulti(jws, unrelated, { strictSignerMatch: true })).rejects.toSatisfy(
          (e) => isJWTError(e, "ERR_JWS_NO_MATCHING_SIGNER"),
        );
      });
    });

    describe("error paths", () => {
      it("rejects null input", async () => {
        await expect(
          verifyMulti(null as unknown as JWSGeneralSerialization, keys.hs256),
        ).rejects.toSatisfy((e) => isJWTError(e, "ERR_JWS_INVALID_SERIALIZATION"));
      });

      it("rejects an object with neither signatures[] nor flattened signature", async () => {
        await expect(
          verifyMulti({ payload: "x" } as unknown as JWSGeneralSerialization, keys.hs256),
        ).rejects.toSatisfy((e) => isJWTError(e, "ERR_JWS_INVALID_SERIALIZATION"));
      });

      it("rejects disallowed alg via options.algorithms", async () => {
        const jws = await signMulti({ x: 1 }, [{ key: keys.hs256 }]);
        await expect(verifyMulti(jws, keys.hs256, { algorithms: ["HS384"] })).rejects.toSatisfy(
          (e) => isJWTError(e, "ERR_JWS_ALG_NOT_ALLOWED"),
        );
      });

      it("rejects typ mismatch via options.typ", async () => {
        const jws = await signMulti({ x: 1 }, [{ key: keys.hs256 }]);
        await expect(verifyMulti(jws, keys.hs256, { typ: "dpop+jwt" })).rejects.toSatisfy((e) =>
          isJWTError(e, "ERR_JWS_INVALID"),
        );
      });
    });
  });

  describe("verifyMultiAll", () => {
    it("returns a per-signature outcome array for a fully valid multi-sig JWS", async () => {
      const jws = await signMulti({ sub: "u1" }, [
        { key: keys.rs256.privateKey },
        { key: keys.es256.privateKey },
        { key: keys.hs256 },
      ]);

      const outcomes = await verifyMultiAll(jws, (header) => {
        if (header.kid === keys.rs256.publicKey.kid) return keys.rs256.publicKey;
        if (header.kid === keys.es256.publicKey.kid) return keys.es256.publicKey;
        if (header.kid === keys.hs256.kid) return keys.hs256;
        throw new Error("unknown kid");
      });

      expect(outcomes).toHaveLength(3);
      expect(outcomes.every((o) => o.verified)).toBe(true);
      const verified = outcomes.filter((o) => o.verified);
      expect(verified[0]?.signerIndex).toBe(0);
      expect(verified[2]?.signerIndex).toBe(2);
      for (const o of verified) {
        expect((o.payload as JWTClaims).sub).toBe("u1");
        expect(o.protectedHeader.alg).toBeTypeOf("string");
      }
    });

    it("collects mixed valid/invalid outcomes when one key is wrong", async () => {
      const jws = await signMulti({ sub: "u1" }, [
        { key: keys.rs256.privateKey },
        { key: keys.hs256 },
      ]);

      // Return the *wrong* HMAC key for signature[1] to force a crypto failure.
      const wrongHmac = (await generateJWK("HS256")) as JWK_Symmetric;
      const outcomes = await verifyMultiAll(jws, (header) => {
        if (header.kid === keys.rs256.publicKey.kid) return keys.rs256.publicKey;
        return wrongHmac;
      });

      expect(outcomes).toHaveLength(2);
      expect(outcomes[0]?.verified).toBe(true);
      expect(outcomes[1]?.verified).toBe(false);
      if (outcomes[1] && !outcomes[1].verified) {
        expect(isJWTError(outcomes[1].error, "ERR_JWS_SIGNATURE_INVALID")).toBe(true);
        expect(outcomes[1].protectedHeader?.alg).toBe("HS256");
      }
    });

    it("captures a throwing key resolver as a verified:false outcome", async () => {
      const jws = await signMulti({ x: 1 }, [{ key: keys.rs256.privateKey }, { key: keys.hs256 }]);

      let call = 0;
      const outcomes = await verifyMultiAll(jws, (header) => {
        call += 1;
        if (header.kid === keys.rs256.publicKey.kid) return keys.rs256.publicKey;
        throw new Error("resolver: hmac key unavailable");
      });

      expect(call).toBe(2);
      expect(outcomes[0]?.verified).toBe(true);
      expect(outcomes[1]?.verified).toBe(false);
      if (outcomes[1] && !outcomes[1].verified) {
        expect(isJWTError(outcomes[1].error, "ERR_JWK_KEY_NOT_FOUND")).toBe(true);
      }
    });

    it("captures disallowed alg per-signer via options.algorithms", async () => {
      const jws = await signMulti({ x: 1 }, [{ key: keys.rs256.privateKey }, { key: keys.hs256 }]);
      const resolver: JWKLookupFunction = (header) => {
        if (header.kid === keys.rs256.publicKey.kid) return keys.rs256.publicKey;
        return keys.hs256;
      };

      const outcomes = await verifyMultiAll(jws, resolver, { algorithms: ["RS256"] });

      expect(outcomes[0]?.verified).toBe(true);
      expect(outcomes[1]?.verified).toBe(false);
      if (outcomes[1] && !outcomes[1].verified) {
        expect(isJWTError(outcomes[1].error, "ERR_JWS_ALG_NOT_ALLOWED")).toBe(true);
      }
    });

    it("captures expired JWT claims on verified signatures as verified:false", async () => {
      const jws = await signMulti({ sub: "u1", exp: Math.floor(Date.now() / 1000) - 10 }, [
        { key: keys.hs256 },
      ]);

      const outcomes = await verifyMultiAll(jws, () => keys.hs256);

      expect(outcomes).toHaveLength(1);
      expect(outcomes[0]?.verified).toBe(false);
      if (outcomes[0] && !outcomes[0].verified) {
        expect(isJWTError(outcomes[0].error, "ERR_JWT_EXPIRED")).toBe(true);
        // Protected header is surfaced even on claim-validation failure.
        expect(outcomes[0].protectedHeader?.alg).toBe("HS256");
      }
    });

    it("supports 'all must verify' policy at the call site", async () => {
      const jws = await signMulti({ sub: "u1" }, [
        { key: keys.rs256.privateKey },
        { key: keys.hs256 },
      ]);

      const outcomes = await verifyMultiAll(jws, (header) => {
        if (header.kid === keys.rs256.publicKey.kid) return keys.rs256.publicKey;
        return keys.hs256;
      });
      const allOk = outcomes.every((o) => o.verified);
      expect(allOk).toBe(true);
    });

    it("supports quorum policy — 'at least 2 of N by distinct kid'", async () => {
      const jws = await signMulti({ sub: "u1" }, [
        { key: keys.rs256.privateKey },
        { key: keys.es256.privateKey },
        { key: keys.hs256 },
      ]);

      const outcomes = await verifyMultiAll(jws, (header) => {
        if (header.kid === keys.rs256.publicKey.kid) return keys.rs256.publicKey;
        if (header.kid === keys.es256.publicKey.kid) return keys.es256.publicKey;
        // Reject the third signer in this policy
        throw new Error("unauthorised signer");
      });
      const validKids = outcomes
        .filter((o): o is Extract<typeof o, { verified: true }> => o.verified)
        .map((o) => o.protectedHeader.kid);
      expect(new Set(validKids).size).toBeGreaterThanOrEqual(2);
    });

    it("throws structurally on non-object input", async () => {
      await expect(
        verifyMultiAll(null as unknown as JWSGeneralSerialization, () => keys.hs256),
      ).rejects.toSatisfy((e) => isJWTError(e, "ERR_JWS_INVALID_SERIALIZATION"));
    });

    it("throws structurally on missing signatures[]", async () => {
      await expect(
        verifyMultiAll({ payload: "x" } as unknown as JWSGeneralSerialization, () => keys.hs256),
      ).rejects.toSatisfy((e) => isJWTError(e, "ERR_JWS_INVALID_SERIALIZATION"));
    });

    it("accepts Flattened input (single-signature outcome array of length 1)", async () => {
      const general = await signMulti({ x: 1 }, [{ key: keys.hs256 }]);
      const flattened: JWSFlattenedSerialization = {
        payload: general.payload,
        protected: general.signatures[0]?.protected,
        signature: general.signatures[0]!.signature,
      };
      const outcomes = await verifyMultiAll(flattened, () => keys.hs256);
      expect(outcomes).toHaveLength(1);
      expect(outcomes[0]?.verified).toBe(true);
    });

    it("reports a malformed signature as verified:false without crashing", async () => {
      const jws = await signMulti({ x: 1 }, [{ key: keys.hs256 }]);
      const tampered: JWSGeneralSerialization = {
        ...jws,
        signatures: [{ ...jws.signatures[0]!, signature: undefined as unknown as string }],
      };
      const outcomes = await verifyMultiAll(tampered, () => keys.hs256);
      expect(outcomes[0]?.verified).toBe(false);
      if (outcomes[0] && !outcomes[0].verified) {
        expect(isJWTError(outcomes[0].error, "ERR_JWS_INVALID")).toBe(true);
      }
    });

    it("reports a signature missing 'alg' in protected header as verified:false", async () => {
      const jws = await signMulti({ x: 1 }, [{ key: keys.hs256 }]);
      const forgedProtected = Buffer.from(JSON.stringify({ typ: "JWT" })).toString("base64url");
      const tampered: JWSGeneralSerialization = {
        ...jws,
        signatures: [{ ...jws.signatures[0]!, protected: forgedProtected }],
      };
      const outcomes = await verifyMultiAll(tampered, () => keys.hs256);
      expect(outcomes[0]?.verified).toBe(false);
      if (outcomes[0] && !outcomes[0].verified) {
        expect(isJWTError(outcomes[0].error, "ERR_JWS_INVALID")).toBe(true);
        expect(outcomes[0].protectedHeader?.typ).toBe("JWT");
      }
    });

    it("reports a protected-header decode failure as verified:false", async () => {
      const jws = await signMulti({ x: 1 }, [{ key: keys.hs256 }]);
      const garbageProtected = Buffer.from("not json").toString("base64url");
      const tampered: JWSGeneralSerialization = {
        ...jws,
        signatures: [{ ...jws.signatures[0]!, protected: garbageProtected }],
      };
      const outcomes = await verifyMultiAll(tampered, () => keys.hs256);
      expect(outcomes[0]?.verified).toBe(false);
      if (outcomes[0] && !outcomes[0].verified) {
        expect(isJWTError(outcomes[0].error, "ERR_JWS_INVALID")).toBe(true);
      }
    });

    it("reports a disjoint-header violation as verified:false", async () => {
      const jws = await signMulti({ x: 1 }, [{ key: keys.hs256 }]);
      // Forge: inject a `typ` header that collides with the protected one.
      const protectedDecoded = JSON.parse(
        Buffer.from(jws.signatures[0]!.protected!, "base64url").toString("utf8"),
      );
      const tampered: JWSGeneralSerialization = {
        ...jws,
        signatures: [{ ...jws.signatures[0]!, header: { typ: protectedDecoded.typ ?? "JWT" } }],
      };
      const outcomes = await verifyMultiAll(tampered, () => keys.hs256);
      expect(outcomes[0]?.verified).toBe(false);
      if (outcomes[0] && !outcomes[0].verified) {
        expect(isJWTError(outcomes[0].error, "ERR_JWS_HEADER_PARAMS_NOT_DISJOINT")).toBe(true);
      }
    });

    it("reports typ mismatch as verified:false", async () => {
      const jws = await signMulti({ x: 1 }, [{ key: keys.hs256 }]);
      const outcomes = await verifyMultiAll(jws, () => keys.hs256, { typ: "dpop+jwt" });
      expect(outcomes[0]?.verified).toBe(false);
      if (outcomes[0] && !outcomes[0].verified) {
        expect(isJWTError(outcomes[0].error, "ERR_JWS_INVALID")).toBe(true);
        expect(outcomes[0].error.message).toContain("typ");
      }
    });

    it("reports crit-header violation as verified:false", async () => {
      const jws = await signMulti({ x: 1 }, [
        { key: keys.hs256, protectedHeader: { crit: ["unknown-ext"], "unknown-ext": "value" } },
      ]);
      // No `recognizedHeaders`, so "unknown-ext" is not processed → violation.
      const outcomes = await verifyMultiAll(jws, () => keys.hs256);
      expect(outcomes[0]?.verified).toBe(false);
      if (outcomes[0] && !outcomes[0].verified) {
        expect(outcomes[0].protectedHeader?.crit).toEqual(["unknown-ext"]);
      }
    });

    it("normalises non-Error throws from the key resolver (preserves cause)", async () => {
      const jws = await signMulti({ x: 1 }, [{ key: keys.hs256 }]);
      const outcomes = await verifyMultiAll(jws, () => {
        throw "plain-string-error"; // eslint-disable-line no-throw-literal
      });
      expect(outcomes[0]?.verified).toBe(false);
      if (outcomes[0] && !outcomes[0].verified) {
        expect(isJWTError(outcomes[0].error, "ERR_JWK_KEY_NOT_FOUND")).toBe(true);
        // The string falls through to the fallback message path in _asJWTError,
        // and the original value is preserved as the error's `cause`.
        expect(outcomes[0].error.cause).toBe("plain-string-error");
      }
    });
  });

  describe("verifyMulti branching coverage", () => {
    it("rejects a signature missing the 'signature' field", async () => {
      const jws = await signMulti({ x: 1 }, [{ key: keys.hs256 }]);
      const tampered: JWSGeneralSerialization = {
        ...jws,
        signatures: [{ ...jws.signatures[0]!, signature: undefined as unknown as string }],
      };
      await expect(verifyMulti(tampered, keys.hs256)).rejects.toSatisfy((e) =>
        isJWTError(e, "ERR_JWS_INVALID"),
      );
    });

    it("rejects a protected header missing 'alg'", async () => {
      const jws = await signMulti({ x: 1 }, [{ key: keys.hs256 }]);
      const forgedProtected = Buffer.from(JSON.stringify({ typ: "JWT" })).toString("base64url");
      const tampered: JWSGeneralSerialization = {
        ...jws,
        signatures: [{ ...jws.signatures[0]!, protected: forgedProtected }],
      };
      await expect(verifyMulti(tampered, keys.hs256)).rejects.toSatisfy((e) =>
        isJWTError(e, "ERR_JWS_INVALID"),
      );
    });

    it("surfaces decode failure from the protected header", async () => {
      const jws = await signMulti({ x: 1 }, [{ key: keys.hs256 }]);
      const garbageProtected = Buffer.from("not json").toString("base64url");
      const tampered: JWSGeneralSerialization = {
        ...jws,
        signatures: [{ ...jws.signatures[0]!, protected: garbageProtected }],
      };
      await expect(verifyMulti(tampered, keys.hs256)).rejects.toSatisfy((e) =>
        isJWTError(e, "ERR_JWS_INVALID"),
      );
    });
  });

  describe("generalToFlattenedJWS", () => {
    it("converts single-signature General to Flattened", async () => {
      const general = await signMulti({ x: 1 }, [{ key: keys.hs256 }]);
      const flattened = generalToFlattenedJWS(general);
      expect("signatures" in flattened).toBe(false);
      expect(flattened.payload).toBe(general.payload);
      expect(flattened.protected).toBe(general.signatures[0]?.protected);
      expect(flattened.signature).toBe(general.signatures[0]?.signature);
    });

    it("throws on multi-signature input", async () => {
      const general = await signMulti({ x: 1 }, [{ key: keys.hs256 }, { key: keys.hs384 }]);
      try {
        generalToFlattenedJWS(general);
        expect.fail("should have thrown");
      } catch (err) {
        expect(isJWTError(err, "ERR_JWS_INVALID_SERIALIZATION")).toBe(true);
      }
    });

    it("round-trips via Flattened back into verifyMulti", async () => {
      const general = await signMulti({ x: 1 }, [{ key: keys.hs256 }]);
      const flattened = generalToFlattenedJWS(general);
      const { payload } = await verifyMulti(flattened, keys.hs256);
      expect((payload as Record<string, unknown>).x).toBe(1);
    });
  });

  describe("interop with jose", () => {
    it("unjwt signMulti → jose.generalVerify (single HMAC signer)", async () => {
      const jws = await signMulti({ sub: "u1" }, [{ key: keys.hs256 }]);
      const joseKey = await jose.importJWK(keys.hs256, "HS256");
      const { payload } = await jose.generalVerify(jws as unknown as jose.GeneralJWSInput, joseKey);
      expect(JSON.parse(textDecoder.decode(payload))).toEqual({ sub: "u1" });
    });

    it("unjwt signMulti → jose.generalVerify (RS256 + ES256 + Ed25519 signers)", async () => {
      const jws = await signMulti({ sub: "u1" }, [
        { key: keys.rs256.privateKey },
        { key: keys.es256.privateKey },
        { key: keys.ed25519.privateKey },
      ]);
      const rsPub = await jose.importJWK(keys.rs256.publicKey, "RS256");
      const esPub = await jose.importJWK(keys.es256.publicKey, "ES256");
      const edPub = await jose.importJWK(keys.ed25519.publicKey, "Ed25519");

      const a = await jose.generalVerify(jws as unknown as jose.GeneralJWSInput, rsPub);
      expect(JSON.parse(textDecoder.decode(a.payload))).toEqual({ sub: "u1" });
      const b = await jose.generalVerify(jws as unknown as jose.GeneralJWSInput, esPub);
      expect(JSON.parse(textDecoder.decode(b.payload))).toEqual({ sub: "u1" });
      const c = await jose.generalVerify(jws as unknown as jose.GeneralJWSInput, edPub);
      expect(JSON.parse(textDecoder.decode(c.payload))).toEqual({ sub: "u1" });
    });

    it("jose.GeneralSign → unjwt verifyMulti (RS256 + HS256 signers)", async () => {
      const rsPriv = await jose.importJWK(keys.rs256.privateKey, "RS256");
      const hmac = await jose.importJWK(keys.hs256, "HS256");
      const payloadBytes = textEncoder.encode(JSON.stringify({ sub: "u1" }));

      const builder = new jose.GeneralSign(payloadBytes);
      builder.addSignature(rsPriv).setProtectedHeader({ alg: "RS256" });
      builder.addSignature(hmac).setProtectedHeader({ alg: "HS256" });
      const jws = (await builder.sign()) as unknown as JWSGeneralSerialization;

      const { payload: pa } = await verifyMulti(jws, keys.rs256.publicKey);
      expect(pa).toEqual({ sub: "u1" });
      const { payload: pb } = await verifyMulti(jws, keys.hs256);
      expect(pb).toEqual({ sub: "u1" });
    });

    it("unjwt signMulti + generalToFlattenedJWS → jose.flattenedVerify", async () => {
      const general = await signMulti({ sub: "u1" }, [{ key: keys.hs256 }]);
      const flattened = generalToFlattenedJWS(general);
      const joseKey = await jose.importJWK(keys.hs256, "HS256");
      const { payload } = await jose.flattenedVerify(
        flattened as unknown as jose.FlattenedJWSInput,
        joseKey,
      );
      expect(JSON.parse(textDecoder.decode(payload))).toEqual({ sub: "u1" });
    });

    it("jose.FlattenedSign → unjwt verifyMulti", async () => {
      const joseKey = await jose.importJWK(keys.hs256, "HS256");
      const payloadBytes = textEncoder.encode(JSON.stringify({ sub: "u1" }));
      const jws = (await new jose.FlattenedSign(payloadBytes)
        .setProtectedHeader({ alg: "HS256" })
        .sign(joseKey)) as unknown as JWSFlattenedSerialization;

      const { payload } = await verifyMulti(jws, keys.hs256);
      expect(payload).toEqual({ sub: "u1" });
    });
  });
});
