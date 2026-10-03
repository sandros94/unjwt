import { describe, it, expect, beforeAll } from "vitest";

import {
  sign,
  signMulti,
  verify,
  verifyMulti,
  verifyMultiAll,
  DEFAULT_JOSE_LIMITS,
  isJWTError,
} from "../src/core/jws";
import { encrypt, decrypt, encryptMulti, decryptMulti } from "../src/core/jwe";
import { generateJWK } from "../src/core/jwk";
import { DEFAULT_PBES2_ITERATIONS } from "../src/core/_internal";
import { base64UrlParse, base64UrlStringify } from "../src/core/utils/base64";
import { textEncoder } from "unsecure/utils";
import type {
  JWK_EC_Private,
  JWK_EC_Public,
  JWK_oct,
  JWKSet,
  JWSGeneralSerialization,
  JWEGeneralSerialization,
  JWKLookupFunction,
} from "../src/core/types";

/** An `oct` JWK whose `k` is a PBES2 password — a recipient key for `encryptMulti`. */
function passwordJWK(password: string): JWK_oct<"PBES2-HS256+A128KW"> {
  return {
    kty: "oct",
    alg: "PBES2-HS256+A128KW",
    k: base64UrlStringify(textEncoder.encode(password)),
  };
}

describe("limits", () => {
  let signer: JWK_EC_Private<"ES256">;
  let publicKey: JWK_EC_Public<"ES256">;
  let decoys: JWK_EC_Public<"ES256">[];
  let octKeys: JWK_oct<"A256KW">[];

  beforeAll(async () => {
    const pair = await generateJWK("ES256");
    // A `kid`-less signer keeps every set entry a candidate: the filter narrows
    // by `kid` as soon as the header carries one.
    const { kid: _signerKid, ...privateKey } = pair.privateKey;
    const { kid: _publicKid, ...pub } = pair.publicKey;
    signer = privateKey as JWK_EC_Private<"ES256">;
    publicKey = pub as JWK_EC_Public<"ES256">;

    decoys = await Promise.all(
      Array.from({ length: 12 }, async () => {
        const { publicKey: decoy } = await generateJWK("ES256");
        const { kid: _decoyKid, ...rest } = decoy;
        return rest as JWK_EC_Public<"ES256">;
      }),
    );

    octKeys = await Promise.all(
      Array.from({ length: 4 }, async () => {
        const key = await generateJWK("A256KW");
        const { kid: _octKid, ...rest } = key;
        return rest as JWK_oct<"A256KW">;
      }),
    );
  });

  describe("defaults", () => {
    it("names one set of numbers", () => {
      expect(DEFAULT_JOSE_LIMITS).toEqual({
        signatures: 16,
        recipients: 16,
        keyCandidates: 8,
        pbes2Iterations: 2_400_000,
      });
    });

    it("covers four recipients minted at the default PBES2 cost", () => {
      expect(DEFAULT_JOSE_LIMITS.pbes2Iterations).toBe(4 * DEFAULT_PBES2_ITERATIONS);
    });
  });

  describe("keyCandidates (JWS verify)", () => {
    it("tries a set filling the limit exactly", async () => {
      const jws = await sign({ sub: "u1" }, signer);
      const set: JWKSet = {
        keys: [...decoys.slice(0, DEFAULT_JOSE_LIMITS.keyCandidates - 1), publicKey],
      };
      const { payload } = await verify<{ sub: string }>(jws, set);
      expect(payload.sub).toBe("u1");
    });

    it("rejects one candidate over the limit before importing a key", async () => {
      const jws = await sign({ sub: "u1" }, signer);
      const set: JWKSet = {
        keys: [...decoys.slice(0, DEFAULT_JOSE_LIMITS.keyCandidates), publicKey],
      };
      await expect(verify(jws, set)).rejects.toSatisfy((error) =>
        isJWTError(error, "ERR_JWK_KEY_NOT_FOUND"),
      );
      await expect(verify(jws, set)).rejects.toThrow(
        '9 candidate keys exceed the limit of 8; narrow the JWK Set with a "kid".',
      );
    });

    it("honours a caller-set limit", async () => {
      const jws = await sign({ sub: "u1" }, signer);
      const set: JWKSet = { keys: [decoys[0]!, publicKey] };
      await expect(verify(jws, set, { limits: { keyCandidates: 1 } })).rejects.toThrow(
        '2 candidate keys exceed the limit of 1; narrow the JWK Set with a "kid".',
      );
      const { payload } = await verify<{ sub: string }>(jws, set, {
        limits: { keyCandidates: 2 },
      });
      expect(payload.sub).toBe("u1");
    });

    it("applies to verifyMulti", async () => {
      const jws = await signMulti({ sub: "u1" }, [{ key: signer }]);
      const set: JWKSet = { keys: [decoys[0]!, publicKey] };
      await expect(verifyMulti(jws, set, { limits: { keyCandidates: 1 } })).rejects.toThrow(
        '2 candidate keys exceed the limit of 1; narrow the JWK Set with a "kid".',
      );
      const { payload } = await verifyMulti<{ sub: string }>(jws, set, {
        limits: { keyCandidates: 2 },
      });
      expect(payload.sub).toBe("u1");
    });
  });

  describe("keyCandidates (JWE decrypt)", () => {
    it("rejects one candidate over the limit before importing a key", async () => {
      const jwe = await encrypt({ sub: "u1" }, octKeys[2]!, { enc: "A256GCM" });
      const set: JWKSet = { keys: [octKeys[0]!, octKeys[1]!, octKeys[2]!] };
      await expect(
        decrypt(jwe, set, { allowSymmetricJWKSet: true, limits: { keyCandidates: 2 } }),
      ).rejects.toSatisfy((error) => isJWTError(error, "ERR_JWK_KEY_NOT_FOUND"));
      const { payload } = await decrypt<{ sub: string }>(jwe, set, {
        allowSymmetricJWKSet: true,
        limits: { keyCandidates: 3 },
      });
      expect(payload.sub).toBe("u1");
    });

    it("applies to decryptMulti", async () => {
      const jwe = await encryptMulti({ sub: "u1" }, [{ key: octKeys[2]! }], { enc: "A256GCM" });
      const set: JWKSet = { keys: [octKeys[0]!, octKeys[1]!, octKeys[2]!] };
      await expect(
        decryptMulti(jwe, set, { allowSymmetricJWKSet: true, limits: { keyCandidates: 2 } }),
      ).rejects.toSatisfy((error) => isJWTError(error, "ERR_JWK_KEY_NOT_FOUND"));
      const { payload } = await decryptMulti<{ sub: string }>(jwe, set, {
        allowSymmetricJWKSet: true,
        limits: { keyCandidates: 3 },
      });
      expect(payload.sub).toBe("u1");
    });
  });

  describe("signatures", () => {
    let single: JWSGeneralSerialization;

    const repeat = (count: number): JWSGeneralSerialization => ({
      payload: single.payload,
      signatures: Array.from({ length: count }, () => single.signatures[0]!),
    });

    beforeAll(async () => {
      single = await signMulti({ sub: "u1" }, [{ key: signer }]);
    });

    it("verifies a token carrying exactly the limit", async () => {
      const { payload } = await verifyMulti<{ sub: string }>(
        repeat(DEFAULT_JOSE_LIMITS.signatures),
        publicKey,
      );
      expect(payload.sub).toBe("u1");
    });

    it("rejects one signature over the limit", async () => {
      await expect(
        verifyMulti(repeat(DEFAULT_JOSE_LIMITS.signatures + 1), publicKey),
      ).rejects.toSatisfy((error) => isJWTError(error, "ERR_JWS_INVALID"));
      await expect(
        verifyMulti(repeat(DEFAULT_JOSE_LIMITS.signatures + 1), publicKey),
      ).rejects.toThrow("Invalid JWS: 17 signatures exceed the limit of 16.");
    });

    it("honours a caller-set limit", async () => {
      await expect(
        verifyMulti(repeat(3), publicKey, { limits: { signatures: 2 } }),
      ).rejects.toThrow("Invalid JWS: 3 signatures exceed the limit of 2.");
      const { payload } = await verifyMulti<{ sub: string }>(repeat(2), publicKey, {
        limits: { signatures: 2 },
      });
      expect(payload.sub).toBe("u1");
    });

    it("is a thrown verdict on the token in verifyMultiAll, not an outcome", async () => {
      const resolver: JWKLookupFunction = () => publicKey;
      const outcomes = await verifyMultiAll(repeat(2), resolver, { limits: { signatures: 2 } });
      expect(outcomes).toHaveLength(2);
      expect(outcomes.every((outcome) => outcome.verified)).toBe(true);

      await expect(
        verifyMultiAll(repeat(3), resolver, { limits: { signatures: 2 } }),
      ).rejects.toSatisfy((error) => isJWTError(error, "ERR_JWS_INVALID"));
    });
  });

  describe("recipients", () => {
    let single: JWEGeneralSerialization;

    const repeat = (count: number): JWEGeneralSerialization => ({
      ...single,
      recipients: Array.from({ length: count }, () => single.recipients[0]!),
    });

    beforeAll(async () => {
      single = await encryptMulti({ sub: "u1" }, [{ key: octKeys[0]! }], { enc: "A256GCM" });
    });

    it("decrypts a token carrying exactly the limit", async () => {
      const { payload } = await decryptMulti<{ sub: string }>(
        repeat(DEFAULT_JOSE_LIMITS.recipients),
        octKeys[0]!,
      );
      expect(payload.sub).toBe("u1");
    });

    it("rejects one recipient over the limit", async () => {
      await expect(
        decryptMulti(repeat(DEFAULT_JOSE_LIMITS.recipients + 1), octKeys[0]!),
      ).rejects.toSatisfy((error) => isJWTError(error, "ERR_JWE_INVALID"));
      await expect(
        decryptMulti(repeat(DEFAULT_JOSE_LIMITS.recipients + 1), octKeys[0]!),
      ).rejects.toThrow("Invalid JWE: 17 recipients exceed the limit of 16.");
    });

    it("honours a caller-set limit", async () => {
      await expect(
        decryptMulti(repeat(3), octKeys[0]!, { limits: { recipients: 2 } }),
      ).rejects.toThrow("Invalid JWE: 3 recipients exceed the limit of 2.");
      const { payload } = await decryptMulti<{ sub: string }>(repeat(2), octKeys[0]!, {
        limits: { recipients: 2 },
      });
      expect(payload.sub).toBe("u1");
    });
  });

  describe("pbes2Iterations", () => {
    it("spends the budget of a compact token on its single attempt", async () => {
      const jwe = await encrypt({ sub: "u1" }, "correct horse battery staple", {
        alg: "PBES2-HS256+A128KW",
        enc: "A256GCM",
        p2c: 2000,
      });

      const { payload } = await decrypt<{ sub: string }>(jwe, "correct horse battery staple", {
        limits: { pbes2Iterations: 2000 },
      });
      expect(payload.sub).toBe("u1");

      await expect(
        decrypt(jwe, "correct horse battery staple", { limits: { pbes2Iterations: 1999 } }),
      ).rejects.toSatisfy((error) => isJWTError(error, "ERR_JWE_INVALID"));
      await expect(
        decrypt(jwe, "correct horse battery staple", { limits: { pbes2Iterations: 1999 } }),
      ).rejects.toThrow("PBES2 iteration budget of 1999 exhausted.");
    });

    it("sums every recipient attempt of one call", async () => {
      const holder = passwordJWK("the real one");
      const jwe = await encryptMulti({ sub: "u1" }, [
        { key: passwordJWK("decoy one"), p2c: 2000 },
        { key: passwordJWK("decoy two"), p2c: 2000 },
        { key: holder, p2c: 2000 },
      ]);

      const { payload, recipientIndex } = await decryptMulti<{ sub: string }>(jwe, holder, {
        limits: { pbes2Iterations: 6000 },
      });
      expect(payload.sub).toBe("u1");
      expect(recipientIndex).toBe(2);

      await expect(
        decryptMulti(jwe, holder, { limits: { pbes2Iterations: 5999 } }),
      ).rejects.toThrow("PBES2 iteration budget of 5999 exhausted.");
    });

    it("opens the second of two recipients minted at the defaults", async () => {
      const holder = passwordJWK("the real one");
      const jwe = await encryptMulti({ sub: "u1" }, [
        { key: passwordJWK("decoy one") },
        { key: holder },
      ]);

      expect((jwe.recipients[1]!.header as { p2c: number }).p2c).toBe(DEFAULT_PBES2_ITERATIONS);

      const { payload, recipientIndex } = await decryptMulti<{ sub: string }>(jwe, holder);
      expect(payload.sub).toBe("u1");
      expect(recipientIndex).toBe(1);
    });

    it("reports a compact p2c above the ceiling as the ceiling, not as the budget", async () => {
      const jwe = await encrypt({ sub: "u1" }, "correct horse battery staple", {
        alg: "PBES2-HS256+A128KW",
        enc: "A256GCM",
        p2c: 2000,
      });
      const [protectedEncoded, ...rest] = jwe.split(".");
      const header = JSON.parse(base64UrlParse(protectedEncoded!)) as Record<string, unknown>;
      const forged = [
        base64UrlStringify(JSON.stringify({ ...header, p2c: 3_000_000 })),
        ...rest,
      ].join(".");

      await expect(decrypt(forged, "correct horse battery staple")).rejects.toThrow(
        `PBES2 "p2c" above the maximum of ${DEFAULT_PBES2_ITERATIONS} iterations (got 3000000).`,
      );
      await expect(
        decrypt(jwe, "correct horse battery staple", {
          maxIterations: 1500,
          limits: { pbes2Iterations: 1500 },
        }),
      ).rejects.toThrow('PBES2 "p2c" above the maximum of 1500 iterations (got 2000).');
    });

    it("charges nothing for a recipient whose p2c is above the ceiling", async () => {
      const holder = passwordJWK("the real one");
      const jwe = await encryptMulti({ sub: "u1" }, [
        { key: passwordJWK("decoy one"), p2c: 2000 },
        { key: holder },
      ]);
      (jwe.recipients[0]!.header as { p2c: number }).p2c = 2_000_000;

      const { payload, recipientIndex } = await decryptMulti<{ sub: string }>(jwe, holder);
      expect(payload.sub).toBe("u1");
      expect(recipientIndex).toBe(1);
    });

    it("leaves a decoy's iterations unspent when it exceeds the whole budget", async () => {
      const holder = passwordJWK("the real one");
      const jwe = await encryptMulti({ sub: "u1" }, [
        { key: passwordJWK("decoy one"), p2c: 3000 },
        { key: holder, p2c: 2000 },
      ]);

      const { payload, recipientIndex } = await decryptMulti<{ sub: string }>(jwe, holder, {
        limits: { pbes2Iterations: 2000 },
      });
      expect(payload.sub).toBe("u1");
      expect(recipientIndex).toBe(1);
    });
  });

  describe("option validation", () => {
    it("rejects a non-positive, fractional or non-numeric limit", async () => {
      const jws = await sign({ sub: "u1" }, signer);

      await expect(verify(jws, publicKey, { limits: { keyCandidates: 0 } })).rejects.toSatisfy(
        (error) => isJWTError(error, "ERR_INVALID_OPTION"),
      );
      await expect(verify(jws, publicKey, { limits: { keyCandidates: 0 } })).rejects.toThrow(
        '"limits.keyCandidates" must be a positive integer.',
      );
      await expect(verify(jws, publicKey, { limits: { keyCandidates: 1.5 } })).rejects.toSatisfy(
        (error) => isJWTError(error, "ERR_INVALID_OPTION"),
      );
      await expect(
        verify(jws, publicKey, { limits: { keyCandidates: "8" as unknown as number } }),
      ).rejects.toSatisfy((error) => isJWTError(error, "ERR_INVALID_OPTION"));
    });

    it("rejects a malformed limit before any signature is tried", async () => {
      const jws = await signMulti({ sub: "u1" }, [{ key: signer }]);
      await expect(verifyMulti(jws, publicKey, { limits: { signatures: -1 } })).rejects.toSatisfy(
        (error) => isJWTError(error, "ERR_INVALID_OPTION"),
      );
      await expect(
        verifyMultiAll(jws, () => publicKey, { limits: { signatures: Number.NaN } }),
      ).rejects.toSatisfy((error) => isJWTError(error, "ERR_INVALID_OPTION"));
    });

    it("rejects a malformed JWE limit", async () => {
      const jwe = await encryptMulti({ sub: "u1" }, [{ key: octKeys[0]! }], { enc: "A256GCM" });
      await expect(decryptMulti(jwe, octKeys[0]!, { limits: { recipients: 0 } })).rejects.toThrow(
        '"limits.recipients" must be a positive integer.',
      );
      await expect(
        decryptMulti(jwe, octKeys[0]!, { limits: { pbes2Iterations: 0 } }),
      ).rejects.toThrow('"limits.pbes2Iterations" must be a positive integer.');
    });
  });
});
