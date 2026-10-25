import * as jose from "jose";
import { describe, it, expect, expectTypeOf, beforeAll } from "vitest";
import { textEncoder, textDecoder } from "unsecure";
import {
  signMulti,
  verifyMulti,
  verifyMultiAll,
  generalToFlattenedJWS,
  isJWTError,
  isUnsecureError,
} from "../src/core/jws/index.ts";
import { generateJWK, generateKey, importKey } from "../src/core/jwk/index.ts";
import { base64UrlStringify, base64UrlParse } from "../src/utils/base64.ts";
import type {
  JWK,
  JWK_oct,
  JWK_Pair,
  JWKSet,
  JWSGeneralSerialization,
  JWSFlattenedSerialization,
  JWKLookupFunction,
  JWSMultiVerifyOutcome,
  JWSMultiVerifyResult,
  JWSMultiVerifyAllOptions,
  JWTClaims,
} from "../src/core/types/index.ts";
import type { JOSEPayloadMode, PayloadOf } from "../src/core/jws/index.ts";

/**
 * Asserts a multi-verify outcome is `verified: false` and returns it narrowed to
 * the failure variant, so failure-branch assertions read without a type-narrowing
 * conditional (which `vitest/no-conditional-expect` flags).
 */
function expectUnverified(
  outcome: JWSMultiVerifyOutcome | undefined,
): Extract<JWSMultiVerifyOutcome, { verified: false }> {
  expect(outcome?.verified).toBe(false);
  return outcome as Extract<JWSMultiVerifyOutcome, { verified: false }>;
}

describe.concurrent("JWS Multi-signature (General JSON Serialization)", () => {
  const keys = {} as {
    rs256: JWK_Pair<"RS256">;
    ps256: JWK_Pair<"PS256">;
    es256: JWK_Pair<"ES256">;
    ed25519: JWK_Pair<"Ed25519">;
    hs256: JWK_oct<"HS256">;
    hs384: JWK_oct<"HS384">;
  };

  beforeAll(async () => {
    const [rs256, ps256, es256, ed25519, hs256, hs384] = await Promise.all([
      generateJWK("RS256", { modulusLength: 2048 }),
      generateJWK("PS256", { modulusLength: 2048 }),
      generateJWK("ES256"),
      generateJWK("Ed25519"),
      generateJWK("HS256"),
      generateJWK("HS384"),
    ]);
    keys.rs256 = rs256;
    keys.ps256 = ps256;
    keys.es256 = es256;
    keys.ed25519 = ed25519;
    keys.hs256 = hs256;
    keys.hs384 = hs384;
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
      expect("signature" in jws).toBe(false);
      expect("protected" in jws).toBe(false);
    });

    it("applies JWT claim auto-generation to the shared payload (iat, exp)", async () => {
      const jws = await signMulti({ sub: "u1" }, [{ key: keys.hs256 }], {
        expiresIn: "1h",
      });
      const { payload } = await verifyMulti(jws, keys.hs256);
      expect(payload.iat).toBeTypeOf("number");
      expect(payload.exp).toBeTypeOf("number");
      expect(payload.exp! - payload.iat!).toBe(3600);
    });

    it("propagates kid from JWK to per-signer protected header", async () => {
      const jws = await signMulti({ x: 1 }, [{ key: keys.hs256 }]);
      const protectedHeader = JSON.parse(
        Buffer.from(jws.signatures[0].protected!, "base64url").toString("utf8"),
      );
      expect(protectedHeader.kid).toBe(keys.hs256.kid);
    });

    it("preserves per-signer protectedHeader additions", async () => {
      const jws = await signMulti({ x: 1 }, [
        { key: keys.rs256.privateKey, protectedHeader: { typ: "vc+jwt" } },
        { key: keys.hs256 },
      ]);
      const h0 = JSON.parse(Buffer.from(jws.signatures[0].protected!, "base64url").toString());
      const h1 = JSON.parse(Buffer.from(jws.signatures[1].protected!, "base64url").toString());
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
      await expect(
        // @ts-expect-error intentionally passing an alg-less JWK to exercise runtime guard
        signMulti({ x: 1 }, [{ key: noAlg }]),
      ).rejects.toSatisfy((e) => isJWTError(e, "ERR_JWS_SIGNER_ALG_INFERENCE"));
    });

    it('throws on "none" alg', async () => {
      await expect(
        signMulti({ x: 1 }, [
          // @ts-expect-error "none" is rejected by JWSSignJWK at the type level; runtime re-checks
          { key: { ...keys.hs256, alg: "none" } },
        ]),
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
        signMulti({ x: 1 }, [
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
      const { payload } = await verifyMulti(jws, keys.hs256, { payload: "string" });
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
      expect(payload.sub).toBe("u1");
      expect(signerIndex).toBe(0);
    });

    it("verifies using the second signer's key", async () => {
      const jws = await signMulti({ sub: "u1" }, [
        { key: keys.rs256.privateKey },
        { key: keys.hs256 },
      ]);
      const { payload, signerIndex } = await verifyMulti(jws, keys.hs256);
      expect(payload.sub).toBe("u1");
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
        signature: general.signatures[0].signature,
      };
      const { payload } = await verifyMulti(flattened, keys.hs256);
      expect((payload as Record<string, unknown>).x).toBe(1);
    });

    it("accepts a JWKSet and finds the matching key", async () => {
      const jws = await signMulti({ sub: "u1" }, [
        { key: keys.rs256.privateKey },
        { key: keys.hs256 },
      ]);
      const otherHmac = await generateJWK("HS256");
      const set: JWKSet = { keys: [otherHmac, keys.hs256] };
      const { payload, signerIndex } = await verifyMulti(jws, set);
      expect(payload.sub).toBe("u1");
      expect(signerIndex).toBe(1);
    });

    it("reports the same failure as verify, with every tried candidate as the cause", async () => {
      const [a, b] = await Promise.all([
        generateJWK("RS256", { modulusLength: 2048 }),
        generateJWK("RS256", { modulusLength: 2048 }),
      ]);
      const jws = await signMulti({ sub: "u1" }, [{ key: { ...a.privateKey, kid: undefined } }]);
      const set = {
        keys: [
          { kty: "RSA", alg: "RS256", n: "!!", e: "AQAB" },
          { ...b.publicKey, kid: undefined },
        ],
      } as unknown as JWKSet;
      const error = await verifyMulti(jws, set).catch((e) => e);
      expect(isJWTError(error, "ERR_JWS_SIGNATURE_INVALID")).toBe(true);
      expect(error.message).toBe("JWS signature verification failed.");
      const causes = error.cause as Array<{ code: string }>;
      expect(causes.map((c) => c.code)).toEqual(["ERR_JWK_INVALID", "ERR_JWS_SIGNATURE_INVALID"]);
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
      expect(payload.sub).toBe("u1");
    });

    it("validates JWT claims on the payload", async () => {
      const jws = await signMulti({ sub: "u1", exp: Math.floor(Date.now() / 1000) - 10 }, [
        { key: keys.hs256 },
      ]);
      await expect(verifyMulti(jws, keys.hs256)).rejects.toSatisfy((e) =>
        isJWTError(e, "ERR_JWT_EXPIRED"),
      );
    });

    it("rejects a non-JSON-object payload under the default mode", async () => {
      const jws = await signMulti("plain text", [{ key: keys.hs256 }]);
      const error = await verifyMulti(jws, keys.hs256).catch((e) => e);
      expect(isJWTError(error, "ERR_JWS_INVALID")).toBe(true);
      expect(error.message).toBe("Invalid JWS: Payload is not a JSON object.");
    });

    it('returns a JSON-shaped string verbatim under payload: "string"', async () => {
      const jws = await signMulti('{"sub":"admin"}', [{ key: keys.hs256 }]);
      const { payload } = await verifyMulti(jws, keys.hs256, { payload: "string" });
      expect(payload).toBe('{"sub":"admin"}');
    });

    it('rejects validateClaims: true outside payload: "json"', async () => {
      const jws = await signMulti({ x: 1 }, [{ key: keys.hs256 }]);
      const error = await verifyMulti(jws, keys.hs256, {
        payload: "string",
        validateClaims: true,
      }).catch((e) => e);
      expect(isJWTError(error, "ERR_INVALID_OPTION")).toBe(true);
    });

    it("rejects a string key", async () => {
      const jws = await signMulti({ x: 1 }, [{ key: keys.hs256 }]);
      const error = await verifyMulti(jws, "a-very-long-shared-secret-value" as never, {
        algorithms: ["HS256"],
      }).catch((e) => e);
      expect(isJWTError(error, "ERR_JWK_INVALID")).toBe(true);
    });

    it("rejects a string signer key on signMulti", async () => {
      const error = await signMulti({ x: 1 }, [
        { key: "a-very-long-shared-secret-value" as never, alg: "HS256" },
      ]).catch((e) => e);
      expect(isJWTError(error, "ERR_JWK_INVALID")).toBe(true);
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

      it("throws ERR_JWS_NO_MATCHING_SIGNER when the key cannot serve the signature's alg", async () => {
        const jws = await signMulti({ x: 1 }, [{ key: keys.hs256 }]);
        const unrelated: JWK_oct<"HS384"> = { ...keys.hs384, kid: "unrelated" };
        await expect(verifyMulti(jws, unrelated, { strictSignerMatch: true })).rejects.toSatisfy(
          (e) => isJWTError(e, "ERR_JWS_NO_MATCHING_SIGNER"),
        );
      });

      it("attempts a single JWK whose kid differs from the signature's kid", async () => {
        const jws = await signMulti({ x: 1 }, [{ key: keys.hs256 }]);
        const rotated: JWK_oct<"HS256"> = { ...keys.hs256, kid: "rotated" };
        const { payload, signerIndex } = await verifyMulti(jws, rotated, {
          strictSignerMatch: true,
        });
        expect(payload.x).toBe(1);
        expect(signerIndex).toBe(0);
      });

      // `kid` is a selection hint: key material without a `kid` of its own is
      // unknown, not mismatched, and is matched on algorithm compatibility.
      it("attempts a CryptoKey against a signature whose header carries a kid", async () => {
        const jws = await signMulti({ sub: "u1" }, [
          { key: keys.rs256.privateKey },
          { key: keys.es256.privateKey },
        ]);
        const header = JSON.parse(base64UrlParse(jws.signatures[1].protected!));
        expect(header.kid).toBe(keys.es256.privateKey.kid);
        const cryptoKey = await importKey(keys.es256.publicKey);
        const { payload, signerIndex } = await verifyMulti(jws, cryptoKey, {
          strictSignerMatch: true,
          algorithms: ["RS256", "ES256"],
        });
        expect(payload.sub).toBe("u1");
        expect(signerIndex).toBe(1);
      });

      it("attempts raw HMAC bytes against a signature whose header carries a kid", async () => {
        const jws = await signMulti({ sub: "u1" }, [{ key: keys.hs256 }]);
        const raw = base64UrlParse(keys.hs256.k, { returnAs: "uint8array" });
        const { signerIndex } = await verifyMulti(jws, raw, {
          strictSignerMatch: true,
          algorithms: ["HS256"],
        });
        expect(signerIndex).toBe(0);
      });

      it("skips a signature whose alg the CryptoKey cannot serve", async () => {
        const jws = await signMulti({ sub: "u1" }, [{ key: keys.rs256.privateKey }]);
        const cryptoKey = await importKey(keys.es256.publicKey);
        await expect(
          verifyMulti(jws, cryptoKey, { strictSignerMatch: true, algorithms: ["RS256", "ES256"] }),
        ).rejects.toSatisfy((e) => isJWTError(e, "ERR_JWS_NO_MATCHING_SIGNER"));
      });

      it("skips a JWK Set whose kid-matching entry cannot serve the signature's alg", async () => {
        const jws = await signMulti({ sub: "u1" }, [{ key: keys.hs256 }]);
        const { alg: _alg, ...es256 } = keys.es256.publicKey;
        const set: JWKSet = { keys: [{ ...es256, kid: keys.hs256.kid }] };
        await expect(
          verifyMulti(jws, set, { strictSignerMatch: true, algorithms: ["HS256"] }),
        ).rejects.toSatisfy((e) => isJWTError(e, "ERR_JWS_NO_MATCHING_SIGNER"));
      });

      it("reports ERR_JWK_KEY_NOT_FOUND when no JWK Set entry carries the signature's kid", async () => {
        const jws = await signMulti({ sub: "u1" }, [{ key: keys.es256.privateKey }]);
        const set: JWKSet = { keys: [{ ...keys.es256.publicKey, kid: "other" }] };
        await expect(verifyMulti(jws, set, { strictSignerMatch: true })).rejects.toSatisfy((e) =>
          isJWTError(e, "ERR_JWK_KEY_NOT_FOUND"),
        );
      });

      it("does not select a kid-less JWK Set entry for a signature whose header carries a kid", async () => {
        const jws = await signMulti({ sub: "u1" }, [{ key: keys.es256.privateKey }]);
        const { kid: _kid, ...kidless } = keys.es256.publicKey;
        await expect(
          verifyMulti(jws, { keys: [kidless] }, { strictSignerMatch: true }),
        ).rejects.toSatisfy((e) => isJWTError(e, "ERR_JWK_KEY_NOT_FOUND"));
      });

      it("verifies against a looked-up JWK Set that also holds a null entry", async () => {
        const jws = await signMulti({ sub: "u1" }, [{ key: keys.es256.privateKey }]);
        const set = { keys: [null, keys.es256.publicKey] } as unknown as JWKSet;
        const { payload, signerIndex } = await verifyMulti(jws, () => set, {
          strictSignerMatch: true,
        });
        expect(payload.sub).toBe("u1");
        expect(signerIndex).toBe(0);
      });
    });

    describe("error paths", () => {
      it("rejects null input", async () => {
        await expect(
          verifyMulti(null as unknown as JWSGeneralSerialization, keys.hs256),
        ).rejects.toSatisfy((e) => isJWTError(e, "ERR_JWS_INVALID_SERIALIZATION"));
      });

      it("rejects an array as a non-object serialization in verifyMulti and verifyMultiAll", async () => {
        const input = [] as unknown as JWSGeneralSerialization;
        for (const error of [
          await verifyMulti(input, keys.hs256).catch((e) => e),
          await verifyMultiAll(input, () => keys.hs256).catch((e) => e),
        ]) {
          expect(isJWTError(error, "ERR_JWS_INVALID_SERIALIZATION")).toBe(true);
          expect(error.message).toBe("Invalid JWS JSON Serialization: expected an object.");
        }
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

  describe("keyAttempts", () => {
    const exhausted =
      'Key attempt budget of 16 ("limits.keyAttempts") exhausted, narrow the keys with a "kid".';

    it("verifies sixteen kid-matched signatures under the default budget", async () => {
      const pairs = await Promise.all(
        Array.from({ length: 16 }, (_, i) => generateJWK("ES256", { kid: `k${i}` })),
      );
      const jws = await signMulti(
        { sub: "u1" },
        pairs.map((pair) => ({ key: pair.privateKey })),
      );
      const set: JWKSet = { keys: pairs.map((pair) => pair.publicKey) };

      const outcomes = await verifyMultiAll(jws, () => set);
      expect(outcomes.map((o) => o.verified)).toEqual(Array.from({ length: 16 }, () => true));
    });

    it("ends the call once candidate fan-out passes the budget", async () => {
      const [holder, decoy] = await Promise.all([
        generateJWK("ES256", { kid: false }),
        generateJWK("ES256", { kid: false }),
      ]);
      const jws = await signMulti(
        { sub: "u1" },
        Array.from({ length: 9 }, () => ({ key: holder.privateKey })),
      );
      const set: JWKSet = { keys: [decoy.publicKey, holder.publicKey] };

      await expect(verifyMultiAll(jws, () => set)).rejects.toSatisfy((error) =>
        isJWTError(error, "ERR_JWK_KEY_NOT_FOUND"),
      );
      await expect(verifyMultiAll(jws, () => set)).rejects.toThrow(exhausted);

      const outcomes = await verifyMultiAll(jws, () => set, { limits: { keyAttempts: 18 } });
      expect(outcomes.map((o) => o.verified)).toEqual(Array.from({ length: 9 }, () => true));
    });

    it("looks up no signature after the budget runs out", async () => {
      const pairs = await Promise.all(
        Array.from({ length: 4 }, (_, i) => generateJWK("ES256", { kid: `k${i}` })),
      );
      const jws = await signMulti(
        { sub: "u1" },
        pairs.map((pair) => ({ key: pair.privateKey })),
      );
      const looked: (string | undefined)[] = [];
      const lookup: JWKLookupFunction = (header) => {
        looked.push(header.kid);
        return pairs[3].publicKey;
      };

      await expect(verifyMulti(jws, lookup, { limits: { keyAttempts: 2 } })).rejects.toThrow(
        'Key attempt budget of 2 ("limits.keyAttempts") exhausted, narrow the keys with a "kid".',
      );
      expect(looked).toEqual(["k0", "k1", "k2"]);
      await expect(verifyMultiAll(jws, lookup, { limits: { keyAttempts: 2 } })).rejects.toThrow(
        "limits.keyAttempts",
      );
    });
  });

  describe("verifyMultiAll", () => {
    it("reports a string key as a per-signature failure, not a throw", async () => {
      const jws = await signMulti({ sub: "u1" }, [{ key: keys.hs256 }]);
      const outcomes = await verifyMultiAll(jws, () => "secret-from-lookup", {
        algorithms: ["HS256"],
      });
      const failure = expectUnverified(outcomes[0]);
      expect(isJWTError(failure.error, "ERR_JWK_INVALID")).toBe(true);
    });

    it("carries the payload mode into every outcome", async () => {
      const jws = await signMulti('{"sub":"admin"}', [{ key: keys.hs256 }]);
      const outcomes = await verifyMultiAll(jws, () => keys.hs256, { payload: "string" });
      expect(outcomes[0]?.verified).toBe(true);
      expect(outcomes.filter((o) => o.verified)[0]?.payload).toBe('{"sub":"admin"}');
    });

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
        expect(o.payload.sub).toBe("u1");
        expect(o.protectedHeader.alg).toBeTypeOf("string");
      }
    });

    it("collects mixed valid/invalid outcomes when one key is wrong", async () => {
      const jws = await signMulti({ sub: "u1" }, [
        { key: keys.rs256.privateKey },
        { key: keys.hs256 },
      ]);

      // Return the *wrong* HMAC key for signature[1] to force a crypto failure.
      const wrongHmac = await generateJWK("HS256");
      const outcomes = await verifyMultiAll(jws, (header) => {
        if (header.kid === keys.rs256.publicKey.kid) return keys.rs256.publicKey;
        return wrongHmac;
      });

      expect(outcomes).toHaveLength(2);
      expect(outcomes[0]?.verified).toBe(true);
      const outcome = expectUnverified(outcomes[1]);
      expect(isJWTError(outcome.error, "ERR_JWS_SIGNATURE_INVALID")).toBe(true);
      expect(outcome.protectedHeader?.alg).toBe("HS256");
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
      const outcome = expectUnverified(outcomes[1]);
      expect(isJWTError(outcome.error, "ERR_JWK_KEY_NOT_FOUND")).toBe(true);
    });

    it("captures disallowed alg per-signer via options.algorithms", async () => {
      const jws = await signMulti({ x: 1 }, [{ key: keys.rs256.privateKey }, { key: keys.hs256 }]);
      const resolver: JWKLookupFunction = (header) => {
        if (header.kid === keys.rs256.publicKey.kid) return keys.rs256.publicKey;
        return keys.hs256;
      };

      const outcomes = await verifyMultiAll(jws, resolver, { algorithms: ["RS256"] });

      expect(outcomes[0]?.verified).toBe(true);
      const outcome = expectUnverified(outcomes[1]);
      expect(isJWTError(outcome.error, "ERR_JWS_ALG_NOT_ALLOWED")).toBe(true);
    });

    it("captures expired JWT claims on verified signatures as verified:false", async () => {
      const jws = await signMulti({ sub: "u1", exp: Math.floor(Date.now() / 1000) - 10 }, [
        { key: keys.hs256 },
      ]);

      const outcomes = await verifyMultiAll(jws, () => keys.hs256);

      expect(outcomes).toHaveLength(1);
      const outcome = expectUnverified(outcomes[0]);
      expect(isJWTError(outcome.error, "ERR_JWT_EXPIRED")).toBe(true);
      // Protected header is surfaced even on claim-validation failure.
      expect(outcome.protectedHeader?.alg).toBe("HS256");
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
        signature: general.signatures[0].signature,
      };
      const outcomes = await verifyMultiAll(flattened, () => keys.hs256);
      expect(outcomes).toHaveLength(1);
      expect(outcomes[0]?.verified).toBe(true);
    });

    it("reports a malformed signature as verified:false without crashing", async () => {
      const jws = await signMulti({ x: 1 }, [{ key: keys.hs256 }]);
      const tampered: JWSGeneralSerialization = {
        ...jws,
        signatures: [{ ...jws.signatures[0], signature: undefined as unknown as string }],
      };
      const outcomes = await verifyMultiAll(tampered, () => keys.hs256);
      const outcome = expectUnverified(outcomes[0]);
      expect(isJWTError(outcome.error, "ERR_JWS_INVALID")).toBe(true);
    });

    it("reports a signature missing 'alg' in protected header as verified:false", async () => {
      const jws = await signMulti({ x: 1 }, [{ key: keys.hs256 }]);
      const forgedProtected = Buffer.from(JSON.stringify({ typ: "JWT" })).toString("base64url");
      const tampered: JWSGeneralSerialization = {
        ...jws,
        signatures: [{ ...jws.signatures[0], protected: forgedProtected }],
      };
      const outcomes = await verifyMultiAll(tampered, () => keys.hs256);
      const outcome = expectUnverified(outcomes[0]);
      expect(isJWTError(outcome.error, "ERR_JWS_INVALID")).toBe(true);
      expect(outcome.protectedHeader?.typ).toBe("JWT");
    });

    it("reports a protected-header decode failure as verified:false", async () => {
      const jws = await signMulti({ x: 1 }, [{ key: keys.hs256 }]);
      const garbageProtected = Buffer.from("not json").toString("base64url");
      const tampered: JWSGeneralSerialization = {
        ...jws,
        signatures: [{ ...jws.signatures[0], protected: garbageProtected }],
      };
      const outcomes = await verifyMultiAll(tampered, () => keys.hs256);
      const outcome = expectUnverified(outcomes[0]);
      expect(isJWTError(outcome.error, "ERR_JWS_INVALID")).toBe(true);
    });

    it("reports a disjoint-header violation as verified:false", async () => {
      const jws = await signMulti({ x: 1 }, [{ key: keys.hs256 }]);
      // Forge: inject a `typ` header that collides with the protected one.
      const protectedDecoded = JSON.parse(
        Buffer.from(jws.signatures[0].protected!, "base64url").toString("utf8"),
      );
      const tampered: JWSGeneralSerialization = {
        ...jws,
        signatures: [{ ...jws.signatures[0], header: { typ: protectedDecoded.typ ?? "JWT" } }],
      };
      const outcomes = await verifyMultiAll(tampered, () => keys.hs256);
      const outcome = expectUnverified(outcomes[0]);
      expect(isJWTError(outcome.error, "ERR_JWS_HEADER_PARAMS_NOT_DISJOINT")).toBe(true);
    });

    it("reports typ mismatch as verified:false", async () => {
      const jws = await signMulti({ x: 1 }, [{ key: keys.hs256 }]);
      const outcomes = await verifyMultiAll(jws, () => keys.hs256, { typ: "dpop+jwt" });
      const outcome = expectUnverified(outcomes[0]);
      expect(isJWTError(outcome.error, "ERR_JWS_INVALID")).toBe(true);
      expect(outcome.error.message).toContain("typ");
    });

    it("reports crit-header violation as verified:false", async () => {
      const jws = await signMulti({ x: 1 }, [
        { key: keys.hs256, protectedHeader: { "crit": ["unknown-ext"], "unknown-ext": "value" } },
      ]);
      // No `recognizedHeaders`, so "unknown-ext" is not processed → violation.
      const outcomes = await verifyMultiAll(jws, () => keys.hs256);
      const outcome = expectUnverified(outcomes[0]);
      expect(outcome.protectedHeader?.crit).toEqual(["unknown-ext"]);
    });

    it("normalises non-Error throws from the key resolver (preserves cause)", async () => {
      const jws = await signMulti({ x: 1 }, [{ key: keys.hs256 }]);
      const outcomes = await verifyMultiAll(jws, () => {
        throw "plain-string-error"; // eslint-disable-line no-throw-literal
      });
      const outcome = expectUnverified(outcomes[0]);
      expect(isJWTError(outcome.error, "ERR_JWK_KEY_NOT_FOUND")).toBe(true);
      // The thrown value is reported under the library's message, and kept as `cause`.
      expect(outcome.error.cause).toBe("plain-string-error");
    });
  });

  describe("verifyMulti branching coverage", () => {
    it("rejects a signature missing the 'signature' field", async () => {
      const jws = await signMulti({ x: 1 }, [{ key: keys.hs256 }]);
      const tampered: JWSGeneralSerialization = {
        ...jws,
        signatures: [{ ...jws.signatures[0], signature: undefined as unknown as string }],
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
        signatures: [{ ...jws.signatures[0], protected: forgedProtected }],
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
        signatures: [{ ...jws.signatures[0], protected: garbageProtected }],
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
      expect(() => generalToFlattenedJWS(general)).toThrow(
        expect.objectContaining({ name: "JWTError", code: "ERR_JWS_INVALID_SERIALIZATION" }),
      );
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
      const { payload } = await jose.generalVerify(jws, joseKey);
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

      const a = await jose.generalVerify(jws, rsPub);
      expect(JSON.parse(textDecoder.decode(a.payload))).toEqual({ sub: "u1" });
      const b = await jose.generalVerify(jws, esPub);
      expect(JSON.parse(textDecoder.decode(b.payload))).toEqual({ sub: "u1" });
      const c = await jose.generalVerify(jws, edPub);
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
      const { payload } = await jose.flattenedVerify(flattened, joseKey);
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

  describe("codec failures wrap into JWTError", () => {
    it("verifyMulti — malformed signature is ERR_JWS_INVALID with an UnsecureError cause", async () => {
      const jws = await signMulti({ sub: "u1" }, [{ key: keys.hs256 }]);
      const tampered: JWSGeneralSerialization = {
        ...jws,
        signatures: [{ ...jws.signatures[0], signature: `${jws.signatures[0].signature}=` }],
      };
      const error = await verifyMulti(tampered, keys.hs256).catch((e) => e);
      expect(isJWTError(error, "ERR_JWS_INVALID")).toBe(true);
      expect(error.message).toBe("Invalid JWS: Signature could not be decoded.");
      expect(isUnsecureError(error.cause, "MALFORMED")).toBe(true);
    });

    it("verifyMultiAll — malformed signature is a failed outcome, not a throw", async () => {
      const jws = await signMulti({ sub: "u1" }, [{ key: keys.hs256 }]);
      const tampered: JWSGeneralSerialization = {
        ...jws,
        signatures: [{ ...jws.signatures[0], signature: `${jws.signatures[0].signature}=` }],
      };
      const [outcome] = await verifyMultiAll(tampered, () => keys.hs256);
      const { error } = expectUnverified(outcome);
      expect(isJWTError(error, "ERR_JWS_INVALID")).toBe(true);
      expect(error.message).toBe("Invalid JWS: Signature could not be decoded.");
      expect(isUnsecureError(error.cause, "MALFORMED")).toBe(true);
    });

    it("verifyMulti — malformed Flattened signature is ERR_JWS_INVALID with a cause", async () => {
      const jws = await signMulti({ sub: "u1" }, [{ key: keys.hs256 }]);
      const flattened = generalToFlattenedJWS(jws);
      const error = await verifyMulti(
        { ...flattened, signature: `${flattened.signature}=` },
        keys.hs256,
      ).catch((e) => e);
      expect(isJWTError(error, "ERR_JWS_INVALID")).toBe(true);
      expect(isUnsecureError(error.cause, "MALFORMED")).toBe(true);
    });
  });
});

describe.concurrent("JWS multi-signature hardening", () => {
  const keys = {} as { hs256: JWK_oct<"HS256">; hs384: JWK_oct<"HS384">; es256: JWK_Pair<"ES256"> };

  beforeAll(async () => {
    const [hs256, hs384, es256] = await Promise.all([
      generateJWK("HS256"),
      generateJWK("HS384"),
      generateJWK("ES256"),
    ]);
    keys.hs256 = hs256;
    keys.hs384 = hs384;
    keys.es256 = es256;
  });

  describe("protected header shape", () => {
    it.each(["null", "[]", "123", '"str"'])("verifyMulti rejects %s", async (json) => {
      const jws: JWSGeneralSerialization = {
        payload: base64UrlStringify("{}"),
        signatures: [{ protected: encodeHeader(json), signature: "AAAA" }],
      };
      const error = await verifyMulti(jws, keys.hs256).catch((e) => e);
      expect(isJWTError(error, "ERR_JWS_INVALID")).toBe(true);
      expect(error.message).toBe("Invalid JWS: Protected header must be a JSON object.");
    });

    it("verifyMultiAll records a malformed header as a failed outcome", async () => {
      const jws: JWSGeneralSerialization = {
        payload: base64UrlStringify("{}"),
        signatures: [{ protected: encodeHeader("null"), signature: "AAAA" }],
      };
      const [outcome] = await verifyMultiAll(jws, () => keys.hs256);
      expect(expectUnverified(outcome).error.message).toBe(
        "Invalid JWS: Protected header must be a JSON object.",
      );
    });
  });

  describe("algorithm gate", () => {
    it.each([
      ["none", '"none" is not a valid signing algorithm'],
      ["HS1024", 'Algorithm not supported: "HS1024"'],
    ])("verifyMulti rejects alg %s", async (alg, message) => {
      const jws: JWSGeneralSerialization = {
        payload: base64UrlStringify("{}"),
        signatures: [{ protected: encodeHeader(JSON.stringify({ alg })), signature: "AAAA" }],
      };
      const error = await verifyMulti(jws, keys.hs256).catch((e) => e);
      expect(isJWTError(error, "ERR_JWS_ALG_NOT_ALLOWED")).toBe(true);
      expect(error.message).toBe(message);
    });

    it("verifyMultiAll reports an unsupported alg per signature", async () => {
      const jws: JWSGeneralSerialization = {
        payload: base64UrlStringify("{}"),
        signatures: [
          { protected: encodeHeader(JSON.stringify({ alg: "none" })), signature: "AAAA" },
        ],
      };
      const [outcome] = await verifyMultiAll(jws, () => keys.hs256);
      expect(expectUnverified(outcome).error.code).toBe("ERR_JWS_ALG_NOT_ALLOWED");
    });
  });

  describe("per-signature isolation", () => {
    it("a prepended junk signer does not abort a later valid signature", async () => {
      const jws = await signMulti({ sub: "u1" }, [{ key: keys.hs256 }]);
      const junk = {
        protected: jws.signatures[0].protected,
        header: { alg: "HS256" } as Record<string, unknown>,
        signature: "AAAA",
      };
      const tampered: JWSGeneralSerialization = {
        payload: jws.payload,
        signatures: [junk, jws.signatures[0]],
      };
      const { signerIndex } = await verifyMulti(tampered, keys.hs256);
      expect(signerIndex).toBe(1);

      const outcomes = await verifyMultiAll(tampered, () => keys.hs256);
      expect(expectUnverified(outcomes[0]).error.code).toBe("ERR_JWS_HEADER_PARAMS_NOT_DISJOINT");
      expect(outcomes[1]?.verified).toBe(true);
    });

    it("a malformed signature segment does not abort a later valid signature", async () => {
      const jws = await signMulti({ sub: "u1" }, [{ key: keys.hs256 }]);
      const tampered: JWSGeneralSerialization = {
        payload: jws.payload,
        signatures: [
          { ...jws.signatures[0], signature: `${jws.signatures[0].signature}=` },
          jws.signatures[0],
        ],
      };
      const { signerIndex } = await verifyMulti(tampered, keys.hs256);
      expect(signerIndex).toBe(1);

      const outcomes = await verifyMultiAll(tampered, () => keys.hs256);
      expect(expectUnverified(outcomes[0]).error.code).toBe("ERR_JWS_INVALID");
      expect(outcomes[1]?.verified).toBe(true);
    });
  });

  describe('"crit" must be integrity protected', () => {
    it("verifyMulti rejects crit in an unprotected header", async () => {
      const jws = await signMulti({ sub: "u1" }, [{ key: keys.hs256 }]);
      const tampered: JWSGeneralSerialization = {
        payload: jws.payload,
        signatures: [{ ...jws.signatures[0], header: { crit: ["app"], app: "web" } }],
      };
      const error = await verifyMulti(tampered, keys.hs256).catch((e) => e);
      expect(isJWTError(error, "ERR_JWS_INVALID")).toBe(true);
      expect(error.message).toBe('Invalid JWS: "crit" must be integrity protected.');
    });

    it("verifyMultiAll records crit in an unprotected header as a failed outcome", async () => {
      const jws = await signMulti({ sub: "u1" }, [{ key: keys.hs256 }]);
      const tampered: JWSGeneralSerialization = {
        payload: jws.payload,
        signatures: [{ ...jws.signatures[0], header: { crit: ["app"], app: "web" } }],
      };
      const [outcome] = await verifyMultiAll(tampered, () => keys.hs256);
      expect(expectUnverified(outcome).error.code).toBe("ERR_JWS_INVALID");
    });
  });

  describe("ambiguous serialization", () => {
    it.each(["signature", "protected"])("rejects signatures[] alongside %s", async (field) => {
      const jws = await signMulti({ sub: "u1" }, [{ key: keys.hs256 }]);
      const ambiguous = { ...jws, [field]: jws.signatures[0][field as "signature"] };
      const error = await verifyMulti(ambiguous, keys.hs256).catch((e) => e);
      expect(isJWTError(error, "ERR_JWS_INVALID_SERIALIZATION")).toBe(true);
    });
  });

  describe("CryptoKey signers", () => {
    it("infers the alg from a CryptoKey signer", async () => {
      const key = await generateKey("HS256");
      const jws = await signMulti({ sub: "u1" }, [{ key }]);
      const header = JSON.parse(base64UrlParse(jws.signatures[0].protected!));
      expect(header.alg).toBe("HS256");
      expect(header.kid).toBeUndefined();
      const { payload } = await verifyMulti(jws, key);
      expect(payload.sub).toBe("u1");
    });

    it("honours an explicit signer alg and a header-provided kid", async () => {
      const key = await generateKey("HS256");
      const jws = await signMulti({ sub: "u1" }, [
        { key, alg: "HS256", protectedHeader: { kid: "from-header" } },
      ]);
      const header = JSON.parse(base64UrlParse(jws.signatures[0].protected!));
      expect(header.kid).toBe("from-header");
      await expect(verifyMulti(jws, key)).resolves.toBeDefined();
    });

    it("still reports inference failure for an alg-less JWK signer", async () => {
      const { alg: _alg, ...algLess } = keys.hs256;
      await expect(signMulti({ sub: "u1" }, [{ key: algLess }])).rejects.toSatisfy((e) =>
        isJWTError(e, "ERR_JWS_SIGNER_ALG_INFERENCE"),
      );
    });

    it("infers no alg from an HMAC SHA-1 CryptoKey signer", async () => {
      const key = await crypto.subtle.generateKey({ name: "HMAC", hash: "SHA-1" }, false, [
        "sign",
        "verify",
      ]);
      await expect(signMulti({ sub: "u1" }, [{ key }])).rejects.toSatisfy((e) =>
        isJWTError(e, "ERR_JWS_SIGNER_ALG_INFERENCE"),
      );
    });
  });

  describe("RFC 7797 b64", () => {
    it('signMulti adds "b64" to each signer crit when b64 is false', async () => {
      const jws = await signMulti("raw-payload", [
        { key: keys.hs256, protectedHeader: { b64: false } },
        { key: keys.hs384, protectedHeader: { crit: ["app"], app: "web", b64: false } },
      ]);
      const first = JSON.parse(base64UrlParse(jws.signatures[0].protected!));
      const second = JSON.parse(base64UrlParse(jws.signatures[1].protected!));
      expect(first.crit).toEqual(["b64"]);
      expect(second.crit).toEqual(["app", "b64"]);
      await expect(
        verifyMulti(jws, keys.hs256, { payload: "string", recognizedHeaders: ["app"] }),
      ).resolves.toBeDefined();
    });

    it('verifyMulti rejects b64: false that is not listed in "crit"', async () => {
      const jws: JWSGeneralSerialization = {
        payload: "raw-payload",
        signatures: [
          {
            protected: encodeHeader(JSON.stringify({ alg: "HS256", b64: false })),
            signature: "AAAA",
          },
        ],
      };
      const error = await verifyMulti(jws, keys.hs256).catch((e) => e);
      expect(isJWTError(error, "ERR_JWS_INVALID")).toBe(true);
      expect(error.message).toBe('Invalid JWS: "b64" must be listed in "crit".');
    });

    it.each([["false"], [0], [null], [1]])(
      "verifyMulti rejects a non-boolean b64 (%j)",
      async (b64) => {
        const jws: JWSGeneralSerialization = {
          payload: "raw-payload",
          signatures: [
            {
              protected: encodeHeader(JSON.stringify({ alg: "HS256", b64 })),
              signature: "AAAA",
            },
          ],
        };
        const error = await verifyMulti(jws, keys.hs256).catch((e) => e);
        expect(isJWTError(error, "ERR_JWS_INVALID")).toBe(true);
        expect(error.message).toBe('Invalid JWS: "b64" must be a boolean.');
      },
    );

    it("condemns only the signature whose unprotected header carries b64", async () => {
      const jws = await signMulti({ sub: "u1" }, [{ key: keys.hs256 }, { key: keys.hs256 }]);
      const tampered: JWSGeneralSerialization = {
        payload: jws.payload,
        signatures: [{ ...jws.signatures[0], header: { b64: true } }, jws.signatures[1]],
      };

      const { signerIndex } = await verifyMulti(tampered, keys.hs256);
      expect(signerIndex).toBe(1);

      const [first, second] = await verifyMultiAll(tampered, () => keys.hs256);
      const failed = expectUnverified(first);
      expect(failed.error.code).toBe("ERR_JWS_INVALID");
      expect(failed.error.message).toBe('Invalid JWS: "b64" must be in the protected header.');
      expect(second?.verified).toBe(true);
    });

    it("verifyMulti rejects b64 in the unprotected header of its only signature", async () => {
      const jws = await signMulti({ sub: "u1" }, [{ key: keys.hs256 }]);
      const flattened: JWSFlattenedSerialization = {
        payload: jws.payload,
        protected: jws.signatures[0].protected!,
        header: { b64: false },
        signature: jws.signatures[0].signature,
      };
      const error = await verifyMulti(flattened, keys.hs256).catch((e) => e);
      expect(isJWTError(error, "ERR_JWS_INVALID")).toBe(true);
      expect(error.message).toContain('"b64"');
    });
  });

  describe('"typ" is read from the protected header only', () => {
    it("reports a protected header without typ as carrying none", async () => {
      const jws = await signMulti("raw-payload", [{ key: keys.hs256 }]);
      const error = await verifyMulti(jws, keys.hs256, {
        typ: "at+jwt",
        payload: "string",
      }).catch((e) => e);
      expect(isJWTError(error, "ERR_JWS_INVALID")).toBe(true);
      expect(error.message).toBe(
        'Invalid JWS: the protected header on signature[0] carries no "typ", expected "at+jwt".',
      );
    });

    it("ignores a typ that only the unprotected header carries", async () => {
      const jws = await signMulti("raw-payload", [
        { key: keys.hs256, unprotectedHeader: { typ: "at+jwt" } },
      ]);
      const [outcome] = await verifyMultiAll(jws, () => keys.hs256, {
        typ: "at+jwt",
        payload: "string",
      });
      expect(expectUnverified(outcome).error.message).toContain('carries no "typ"');
    });
  });
});

describe.concurrent("signMulti producer header gates", () => {
  let key: JWK_oct<"HS256">;

  beforeAll(async () => {
    key = await generateJWK("HS256");
  });

  it('types an object payload as "JWT" without a "cty"', async () => {
    const { protectedHeader } = await verifyMulti(await signMulti({ sub: "u1" }, [{ key }]), key);
    expect(protectedHeader.typ).toBe("JWT");
    expect(protectedHeader).not.toHaveProperty("cty");
  });

  it('keeps a "cty" set in protectedHeader', async () => {
    const jws = await signMulti({ sub: "u1" }, [
      { key, protectedHeader: { cty: "application/json" } },
    ]);
    const { protectedHeader } = await verifyMulti(jws, key);
    expect(protectedHeader).toMatchObject({ typ: "JWT", cty: "application/json" });
  });

  it("refuses a crit that is not a non-empty array of strings", async () => {
    const error = await signMulti("payload", [
      { key, protectedHeader: { crit: [] as never } },
    ]).catch((e) => e);
    expect(isJWTError(error, "ERR_INVALID_OPTION")).toBe(true);
  });

  it("refuses a crit listing a registered header parameter", async () => {
    const error = await signMulti("payload", [
      { key, protectedHeader: { crit: ["kid"], kid: "k1" } },
    ]).catch((e) => e);
    expect(isJWTError(error, "ERR_INVALID_OPTION")).toBe(true);
  });

  it("refuses a crit naming a parameter the signer header does not carry", async () => {
    const error = await signMulti("payload", [{ key, protectedHeader: { crit: ["app"] } }]).catch(
      (e) => e,
    );
    expect(isJWTError(error, "ERR_INVALID_OPTION")).toBe(true);
    expect(error.message).toContain("app");
  });

  it("refuses a protected header that cannot be serialized", async () => {
    const error = await signMulti("payload", [{ key, protectedHeader: { n: 1n } }]).catch((e) => e);
    expect(isJWTError(error, "ERR_INVALID_OPTION")).toBe(true);
    expect(error.message).toContain("protected header");
  });
});

describe.concurrent("signMulti header tiers", () => {
  let key: JWK_oct<"HS256">;

  beforeAll(async () => {
    key = await generateJWK("HS256");
  });

  it("refuses crit in a per-signature unprotected header", async () => {
    const error = await signMulti("payload", [
      { key, unprotectedHeader: { crit: ["app"], app: "web" } },
    ]).catch((e) => e);
    expect(isJWTError(error, "ERR_INVALID_OPTION")).toBe(true);
    expect(error.message).toContain('"crit"');
  });

  it("refuses b64 in a per-signature unprotected header", async () => {
    const error = await signMulti("payload", [{ key, unprotectedHeader: { b64: false } }]).catch(
      (e) => e,
    );
    expect(isJWTError(error, "ERR_INVALID_OPTION")).toBe(true);
    expect(error.message).toBe(
      'JWS "b64" must be in the protected header, not the unprotected header.',
    );
  });

  it.each([["false"], [0], [null], [1]])(
    "refuses a non-boolean b64 (%j) in a signer protected header",
    async (b64) => {
      const error = await signMulti("payload", [
        { key, protectedHeader: { b64: false } },
        { key, protectedHeader: { b64 } as never },
      ]).catch((e) => e);
      expect(isJWTError(error, "ERR_INVALID_OPTION")).toBe(true);
      expect(error.message).toBe('"b64" must be a boolean.');
    },
  );

  it.each([
    ["null", null],
    ["a string", "signer"],
    ["an array", []],
  ])("refuses a signer entry that is %s", async (_label, signer) => {
    const error = await signMulti("payload", [signer as never]).catch((e) => e);
    expect(isJWTError(error, "ERR_INVALID_OPTION")).toBe(true);
    expect(error.message).toBe('"signers[0]" must be an object.');
  });

  it.each(["protectedHeader", "unprotectedHeader"])(
    "refuses a signer %s that is not an object",
    async (member) => {
      const error = await signMulti("payload", [{ key }, { key, [member]: "abc" }]).catch((e) => e);
      expect(isJWTError(error, "ERR_INVALID_OPTION")).toBe(true);
      expect(error.message).toBe(`"signers[1].${member}" must be an object.`);
    },
  );

  it('refuses "b64" in crit when the signer header carries no b64 member', async () => {
    const error = await signMulti("payload", [{ key, protectedHeader: { crit: ["b64"] } }]).catch(
      (e) => e,
    );
    expect(isJWTError(error, "ERR_INVALID_OPTION")).toBe(true);
    expect(error.message).toContain("b64");
  });

  it('keeps b64: true in the header when "b64" is listed in crit', async () => {
    const jws = await signMulti("payload", [
      { key, protectedHeader: { crit: ["b64"], b64: true } },
    ]);
    const header = JSON.parse(base64UrlParse(jws.signatures[0].protected!));
    expect(header).toMatchObject({ crit: ["b64"], b64: true });
    await expect(verifyMulti(jws, key, { payload: "string" })).resolves.toBeDefined();
  });
});

describe.concurrent("JWS JSON serialization entries", () => {
  let key: JWK_oct<"HS256">;

  beforeAll(async () => {
    key = await generateJWK("HS256");
  });

  const notObjects: [string, unknown][] = [
    ["null", null],
    ["a number", 42],
    ["a string", "signature"],
    ["an array", []],
  ];

  it.each(notObjects)(
    "verifyMulti treats %s in signatures as that entry's failure",
    async (_label, entry) => {
      const jws = await signMulti({ sub: "u1" }, [{ key }]);
      const mixed = {
        payload: jws.payload,
        signatures: [entry, jws.signatures[0]],
      } as JWSGeneralSerialization;
      const { signerIndex } = await verifyMulti(mixed, key);
      expect(signerIndex).toBe(1);

      const lone = { payload: jws.payload, signatures: [entry] } as JWSGeneralSerialization;
      const error = await verifyMulti(lone, key).catch((e) => e);
      expect(isJWTError(error, "ERR_JWS_INVALID")).toBe(true);
    },
  );

  it.each(notObjects)(
    "verifyMultiAll reports %s in signatures as a failed outcome and verifies the next",
    async (_label, entry) => {
      const jws = await signMulti({ sub: "u1" }, [{ key }]);
      const mixed = {
        payload: jws.payload,
        signatures: [entry, jws.signatures[0]],
      } as JWSGeneralSerialization;
      const outcomes = await verifyMultiAll(mixed, () => key);
      expect(expectUnverified(outcomes[0]).error.code).toBe("ERR_JWS_INVALID");
      expect(outcomes[1]?.verified).toBe(true);
    },
  );

  it.each([...notObjects.filter(([label]) => label !== "an array"), ["an array", [1]]])(
    "a signature whose header is %s fails without aborting the next one",
    async (_label, header) => {
      const jws = await signMulti({ sub: "u1" }, [{ key }]);
      const mixed = {
        payload: jws.payload,
        signatures: [{ ...jws.signatures[0], header }, jws.signatures[0]],
      } as JWSGeneralSerialization;
      const { signerIndex } = await verifyMulti(mixed, key);
      expect(signerIndex).toBe(1);

      const outcomes = await verifyMultiAll(mixed, () => key);
      expect(expectUnverified(outcomes[0]).error.code).toBe("ERR_JWS_INVALID");
      expect(outcomes[1]?.verified).toBe(true);
    },
  );

  it("a signature whose protected member is not a string fails without aborting the next one", async () => {
    const jws = await signMulti({ sub: "u1" }, [{ key }]);
    const mixed = {
      payload: jws.payload,
      signatures: [{ ...jws.signatures[0], protected: 0 }, jws.signatures[0]],
    } as unknown as JWSGeneralSerialization;
    const { signerIndex } = await verifyMulti(mixed, key);
    expect(signerIndex).toBe(1);

    const outcomes = await verifyMultiAll(mixed, () => key);
    expect(expectUnverified(outcomes[0]).error.code).toBe("ERR_JWS_INVALID");
  });

  it.each(notObjects)(
    "rejects a Flattened JWS whose header is %s as ERR_JWS_INVALID",
    async (_label, header) => {
      const flat = generalToFlattenedJWS(await signMulti({ sub: "u1" }, [{ key }]));
      const tampered = { ...flat, header } as JWSFlattenedSerialization;
      const error = await verifyMulti(tampered, key).catch((e) => e);
      expect(isJWTError(error, "ERR_JWS_INVALID")).toBe(true);

      const [outcome] = await verifyMultiAll(tampered, () => key);
      expect(expectUnverified(outcome).error.code).toBe("ERR_JWS_INVALID");
    },
  );
});

describe.concurrent("JWS alg in the per-signature unprotected header", () => {
  const bytes = textEncoder.encode("payload bytes");
  let es: JWK_Pair<"ES256">;
  let hs: JWK_oct<"HS256">;

  beforeAll(async () => {
    [es, hs] = await Promise.all([generateJWK("ES256"), generateJWK("HS256")]);
  });

  async function generalWithUnprotectedAlg(): Promise<JWSGeneralSerialization> {
    const sig = new jose.GeneralSign(bytes);
    sig
      .addSignature(es.privateKey)
      .setProtectedHeader({ kid: "es" })
      .setUnprotectedHeader({ alg: "ES256" });
    return (await sig.sign()) as JWSGeneralSerialization;
  }

  async function flattenedWithoutProtected(): Promise<JWSFlattenedSerialization> {
    const sig = new jose.FlattenedSign(bytes).setUnprotectedHeader({ alg: "ES256" });
    return (await sig.sign(es.privateKey)) as JWSFlattenedSerialization;
  }

  it("verifyMulti accepts alg carried only in the unprotected header", async () => {
    const result = await verifyMulti(await generalWithUnprotectedAlg(), es.publicKey, {
      payload: "bytes",
    });
    expect(result.payload).toEqual(bytes);
    expect(result.signerHeader).toEqual({ alg: "ES256" });
    expect(result.protectedHeader).toEqual({ kid: "es" });
  });

  it("verifyMulti accepts a Flattened JWS with no protected member", async () => {
    const result = await verifyMulti(await flattenedWithoutProtected(), es.publicKey, {
      payload: "bytes",
    });
    expect(result.payload).toEqual(bytes);
    expect(result.protectedHeader).toEqual({});
    expect(result.signerHeader).toEqual({ alg: "ES256" });
  });

  it("verifyMultiAll reports alg carried only in the unprotected header as verified", async () => {
    const [outcome] = await verifyMultiAll(await generalWithUnprotectedAlg(), () => es.publicKey, {
      payload: "bytes",
    });
    expect(outcome?.verified).toBe(true);
    expect(outcome?.protectedHeader).toEqual({ kid: "es" });
  });

  it("applies the algorithms allowlist to an unprotected alg", async () => {
    const jws = await generalWithUnprotectedAlg();
    const error = await verifyMulti(jws, es.publicKey, { algorithms: ["ES384"] }).catch((e) => e);
    expect(isJWTError(error, "ERR_JWS_ALG_NOT_ALLOWED")).toBe(true);

    const [outcome] = await verifyMultiAll(jws, () => es.publicKey, { algorithms: ["ES384"] });
    expect(expectUnverified(outcome).error.code).toBe("ERR_JWS_ALG_NOT_ALLOWED");
  });

  it("applies the key's own algorithm to an unprotected alg", async () => {
    const error = await verifyMulti(await flattenedWithoutProtected(), hs).catch((e) => e);
    expect(isJWTError(error, "ERR_JWS_ALG_NOT_ALLOWED")).toBe(true);
  });

  it('rejects an unprotected alg of "none"', async () => {
    const jws = {
      payload: base64UrlStringify(bytes),
      header: { alg: "none" },
      signature: "",
    } as unknown as JWSFlattenedSerialization;
    const error = await verifyMulti(jws, hs, { algorithms: ["none" as never] }).catch((e) => e);
    expect(isJWTError(error, "ERR_JWS_ALG_NOT_ALLOWED")).toBe(true);
  });

  it("rejects a signature carrying no alg in either header", async () => {
    const jws = {
      payload: base64UrlStringify(bytes),
      header: { kid: "es" },
      signature: "AAAA",
    } as JWSFlattenedSerialization;
    const error = await verifyMulti(jws, es.publicKey).catch((e) => e);
    expect(isJWTError(error, "ERR_JWS_INVALID")).toBe(true);
    expect(error.message).toContain('"alg"');
  });
});

describe.concurrent('JWS JSON serialization "crit" members', () => {
  let key: JWK_oct<"HS256">;

  beforeAll(async () => {
    key = await generateJWK("HS256");
  });

  it('rejects crit:["b64"] when the protected header carries no b64 member', async () => {
    const protectedHeader = base64UrlStringify(JSON.stringify({ alg: "HS256", crit: ["b64"] }));
    const payload = base64UrlStringify("payload");
    const hmacKey = await crypto.subtle.importKey(
      "raw",
      base64UrlParse(key.k, { returnAs: "uint8array" }),
      { name: "HMAC", hash: "SHA-256" },
      false,
      ["sign"],
    );
    const mac = await crypto.subtle.sign(
      "HMAC",
      hmacKey,
      textEncoder.encode(`${protectedHeader}.${payload}`),
    );
    const jws: JWSFlattenedSerialization = {
      payload,
      protected: protectedHeader,
      signature: base64UrlStringify(new Uint8Array(mac)),
    };

    const error = await verifyMulti(jws, key, { payload: "string" }).catch((e) => e);
    expect(isJWTError(error, "ERR_JWS_INVALID")).toBe(true);
    expect(error.message).toBe(
      'Critical header parameter "b64" is missing from the protected header.',
    );

    const [outcome] = await verifyMultiAll(jws, () => key, { payload: "string" });
    expect(expectUnverified(outcome).error.code).toBe("ERR_JWS_INVALID");
  });
});

describe.concurrent("JWS JSON verification option gates", () => {
  let key: JWK_oct<"HS256">;
  let jws: JWSGeneralSerialization;

  beforeAll(async () => {
    key = await generateJWK("HS256");
    jws = await signMulti({ sub: "u" }, [{ key, protectedHeader: { typ: "at+jwt" } }]);
  });

  it("refuses an unencoded payload whose bytes are not UTF-8", async () => {
    const error = await signMulti(new Uint8Array([0x61, 0xff, 0x62]), [
      { key, protectedHeader: { b64: false } },
    ]).catch((e) => e);
    expect(isJWTError(error, "ERR_JWS_INVALID")).toBe(true);
    expect(error.message).toBe("Invalid JWS: Payload is not valid UTF-8.");
  });

  it.each([
    ["an empty typ", { typ: "" }],
    ["a typ that is not a string", { typ: 1 }],
    ["an algorithms allowlist that is not an array", { algorithms: "HS256-disabled" }],
    ["an empty audience", { audience: "" }],
  ])("verifyMulti refuses %s", async (_label, options) => {
    const error = await verifyMulti(jws, key, options as never).catch((e) => e);
    expect(isJWTError(error, "ERR_INVALID_OPTION")).toBe(true);
  });

  it("verifyMultiAll throws an option error rather than reporting it per signature", async () => {
    await expect(verifyMultiAll(jws, () => key, { typ: "" })).rejects.toSatisfy((error) =>
      isJWTError(error, "ERR_INVALID_OPTION"),
    );
    await expect(verifyMultiAll(jws, () => key, { subject: "" })).rejects.toSatisfy((error) =>
      isJWTError(error, "ERR_INVALID_OPTION"),
    );
  });
});

describe("types", () => {
  type MyClaims = { sub: string; role: "admin" | "user" };
  type Bytes = Uint8Array<ArrayBuffer>;
  const key = new Uint8Array(32);

  it("types the verifyMulti payload after its mode", () => {
    expectTypeOf((jws: JWSGeneralSerialization) =>
      verifyMulti(jws, key),
    ).returns.resolves.toEqualTypeOf<JWSMultiVerifyResult<JWTClaims>>();
    expectTypeOf((jws: JWSGeneralSerialization) =>
      verifyMulti<MyClaims>(jws, key),
    ).returns.resolves.toEqualTypeOf<JWSMultiVerifyResult<MyClaims>>();
    expectTypeOf((jws: JWSFlattenedSerialization) =>
      verifyMulti(jws, key, { payload: "json" }),
    ).returns.resolves.toEqualTypeOf<JWSMultiVerifyResult<JWTClaims>>();
    expectTypeOf((jws: JWSGeneralSerialization) =>
      verifyMulti(jws, key, { payload: "string" }),
    ).returns.resolves.toEqualTypeOf<JWSMultiVerifyResult<string>>();
    expectTypeOf((jws: JWSGeneralSerialization) =>
      verifyMulti(jws, key, { payload: "bytes" }),
    ).returns.resolves.toEqualTypeOf<JWSMultiVerifyResult<Bytes>>();
    expectTypeOf((jws: JWSGeneralSerialization, payload: JOSEPayloadMode) =>
      verifyMulti(jws, key, { payload }),
    ).returns.resolves.toEqualTypeOf<JWSMultiVerifyResult<JWTClaims | string | Bytes>>();
  });

  it("types every verifyMultiAll outcome payload after its mode", () => {
    const resolver: JWKLookupFunction = () => key;
    expectTypeOf((jws: JWSGeneralSerialization) =>
      verifyMultiAll(jws, resolver),
    ).returns.resolves.toEqualTypeOf<JWSMultiVerifyOutcome<JWTClaims>[]>();
    expectTypeOf((jws: JWSGeneralSerialization) =>
      verifyMultiAll<MyClaims>(jws, resolver),
    ).returns.resolves.toEqualTypeOf<JWSMultiVerifyOutcome<MyClaims>[]>();
    expectTypeOf((jws: JWSGeneralSerialization) =>
      verifyMultiAll(jws, resolver, { payload: "string" }),
    ).returns.resolves.toEqualTypeOf<JWSMultiVerifyOutcome<string>[]>();
    expectTypeOf((jws: JWSGeneralSerialization) =>
      verifyMultiAll(jws, resolver, { payload: "bytes" }),
    ).returns.resolves.toEqualTypeOf<JWSMultiVerifyOutcome<Bytes>[]>();
    expectTypeOf((jws: JWSGeneralSerialization, options: JWSMultiVerifyAllOptions) =>
      verifyMultiAll(jws, resolver, options),
    ).returns.resolves.toEqualTypeOf<JWSMultiVerifyOutcome<JWTClaims | string | Bytes>[]>();
    expectTypeOf<
      Extract<JWSMultiVerifyOutcome<PayloadOf<"string">>, { verified: true }>["payload"]
    >().toEqualTypeOf<string>();
  });

  it("rejects an unknown payload mode and a claims type outside the json mode", () => {
    const resolver: JWKLookupFunction = () => key;
    // @ts-expect-error not a payload mode
    expectTypeOf((jws: JWSGeneralSerialization) => verifyMulti(jws, key, { payload: "nonsense" }));
    // @ts-expect-error not a payload mode
    expectTypeOf((jws: JWSGeneralSerialization) => verifyMultiAll(jws, resolver, { payload: "x" }));
    expectTypeOf((jws: JWSGeneralSerialization) =>
      // @ts-expect-error a claims type implies payload: "json"
      verifyMultiAll<MyClaims>(jws, resolver, { payload: "bytes" }),
    );
  });
});

function encodeHeader(json: string): string {
  return base64UrlStringify(json);
}
