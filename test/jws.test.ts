import { describe, it, expect, beforeAll } from "vitest";
import { sign, verify } from "../src//jws";
import { generateKey } from "../src//jwk";
import { base64UrlEncode, textEncoder, base64UrlDecode } from "../src//utils";
import type { JWSProtectedHeader, JWTClaims } from "../src//types";

describe("JWS Utilities", () => {
  const payloadObj = {
    sub: "1234567890",
    name: "John Doe",
    iat: 1_516_239_022,
  };
  const payloadBytes = textEncoder.encode("Payload as bytes");
  const payloadString = "Payload as string";

  describe("sign", () => {
    it("should sign with HS256 (Object payload)", async () => {
      const key = await generateKey("HS256");
      const jws = await sign(payloadObj, key, { alg: "HS256" });
      expect(jws.split(".").length).toBe(3);
      const [headerEncoded] = jws.split(".");
      const header = JSON.parse(
        new TextDecoder().decode(base64UrlDecode(headerEncoded, false)),
      );
      expect(header.alg).toBe("HS256");
      expect(header.typ).toBe("JWT"); // Default for object
    });

    it("should sign with HS256 (Uint8Array payload)", async () => {
      const key = await generateKey("HS256");
      const jws = await sign(payloadBytes, key, { alg: "HS256" });
      expect(jws.split(".").length).toBe(3);
      const [headerEncoded, payloadEncoded] = jws.split(".");
      const header = JSON.parse(
        new TextDecoder().decode(base64UrlDecode(headerEncoded, false)),
      );
      expect(header.alg).toBe("HS256");
      expect(header.typ).toBeUndefined(); // No default typ for bytes
      expect(base64UrlDecode(payloadEncoded, false)).toEqual(payloadBytes);
    });

    it("should sign with HS256 (String payload)", async () => {
      const key = await generateKey("HS256");
      const jws = await sign(payloadString, key, { alg: "HS256" });
      expect(jws.split(".").length).toBe(3);
      const [headerEncoded, payloadEncoded] = jws.split(".");
      const header = JSON.parse(
        new TextDecoder().decode(base64UrlDecode(headerEncoded, false)),
      );
      expect(header.alg).toBe("HS256");
      expect(header.typ).toBeUndefined(); // No default typ for string
      expect(base64UrlDecode(payloadEncoded, true)).toEqual(payloadString);
    });

    it("should sign with RS256", async () => {
      const { privateKey } = await generateKey("RS256", {
        modulusLength: 2048,
      });
      const jws = await sign(payloadObj, privateKey, { alg: "RS256" });
      expect(jws.split(".").length).toBe(3);
      const [headerEncoded] = jws.split(".");
      const header = JSON.parse(
        new TextDecoder().decode(base64UrlDecode(headerEncoded, false)),
      );
      expect(header.alg).toBe("RS256");
    });

    it("should sign with ES256", async () => {
      const { privateKey } = await generateKey("ES256");
      const jws = await sign(payloadObj, privateKey, { alg: "ES256" });
      expect(jws.split(".").length).toBe(3);
      const [headerEncoded] = jws.split(".");
      const header = JSON.parse(
        new TextDecoder().decode(base64UrlDecode(headerEncoded, false)),
      );
      expect(header.alg).toBe("ES256");
    });

    it("should sign with PS256", async () => {
      const { privateKey } = await generateKey("PS256", {
        modulusLength: 2048,
      });
      const jws = await sign(payloadObj, privateKey, { alg: "PS256" });
      expect(jws.split(".").length).toBe(3);
      const [headerEncoded] = jws.split(".");
      const header = JSON.parse(
        new TextDecoder().decode(base64UrlDecode(headerEncoded, false)),
      );
      expect(header.alg).toBe("PS256");
    });

    it("should handle b64: false option", async () => {
      const key = await generateKey("HS256");
      const jws = await sign(payloadString, key, {
        alg: "HS256",
        protectedHeader: { b64: false },
      });
      const parts = jws.split(".");
      expect(parts.length).toBe(3);
      const [headerEncoded, payloadRaw] = parts;
      const header = JSON.parse(
        new TextDecoder().decode(base64UrlDecode(headerEncoded, false)),
      );
      expect(header.alg).toBe("HS256");
      expect(header.b64).toBe(false);
      expect(payloadRaw).toBe(payloadString); // Payload is not base64 encoded
    });

    it("should include custom protected headers", async () => {
      const key = await generateKey("HS256");
      const jws = await sign(payloadObj, key, {
        alg: "HS256",
        protectedHeader: { kid: "test-key-1", typ: "custom" },
      });
      const [headerEncoded] = jws.split(".");
      const header = JSON.parse(
        new TextDecoder().decode(base64UrlDecode(headerEncoded, false)),
      );
      expect(header.alg).toBe("HS256");
      expect(header.kid).toBe("test-key-1");
      expect(header.typ).toBe("custom"); // Overrides default
    });

    it("should throw if alg is missing", async () => {
      const key = await generateKey("HS256");
      await expect(sign(payloadObj, key, {} as any)).rejects.toThrow(
        'JWS "alg" (Algorithm) must be provided',
      );
    });

    it("should throw for invalid payload type", async () => {
      const key = await generateKey("HS256");
      await expect(sign(12_345 as any, key, { alg: "HS256" })).rejects.toThrow(
        TypeError,
      );
    });
  });

  describe("verify", () => {
    let hs256Key: CryptoKey;
    let rs256KeyPair: CryptoKeyPair;
    let es256KeyPair: CryptoKeyPair;
    let ps256KeyPair: CryptoKeyPair;

    beforeAll(async () => {
      hs256Key = await generateKey("HS256");
      rs256KeyPair = await generateKey("RS256", { modulusLength: 2048 });
      es256KeyPair = await generateKey("ES256");
      ps256KeyPair = await generateKey("PS256", { modulusLength: 2048 });
    });

    it("should verify HS256 (Object payload)", async () => {
      const jws = await sign(payloadObj, hs256Key, { alg: "HS256" });
      const { payload, protectedHeader } = await verify<JWTClaims>(
        jws,
        hs256Key,
      );
      expect(payload).toEqual(payloadObj);
      expect(protectedHeader.alg).toBe("HS256");
      expect(protectedHeader.typ).toBe("JWT");
    });

    it("should verify HS256 (Uint8Array payload)", async () => {
      const jws = await sign(payloadBytes, hs256Key, { alg: "HS256" });
      const { payload, protectedHeader } = await verify<Uint8Array>(
        jws,
        hs256Key,
      );
      expect(payload).toBeInstanceOf(Uint8Array);
      expect(payload).toEqual(payloadBytes);
      expect(protectedHeader.alg).toBe("HS256");
      expect(protectedHeader.typ).toBeUndefined();
    });

    it("should verify HS256 (String payload)", async () => {
      const jws = await sign(payloadString, hs256Key, { alg: "HS256" });
      // String payload that isn't JSON gets decoded back to string by default if b64:true
      const { payload, protectedHeader } = await verify<string>(jws, hs256Key);
      expect(typeof payload).toBe("string");
      expect(payload).toEqual(payloadString);
      expect(protectedHeader.alg).toBe("HS256");
    });

    it("should verify RS256", async () => {
      const jws = await sign(payloadObj, rs256KeyPair.privateKey, {
        alg: "RS256",
      });
      const { payload, protectedHeader } = await verify<JWTClaims>(
        jws,
        rs256KeyPair.publicKey,
      );
      expect(payload).toEqual(payloadObj);
      expect(protectedHeader.alg).toBe("RS256");
    });

    it("should verify ES256", async () => {
      const jws = await sign(payloadObj, es256KeyPair.privateKey, {
        alg: "ES256",
      });
      const { payload, protectedHeader } = await verify<JWTClaims>(
        jws,
        es256KeyPair.publicKey,
      );
      expect(payload).toEqual(payloadObj);
      expect(protectedHeader.alg).toBe("ES256");
    });

    it("should verify PS256", async () => {
      const jws = await sign(payloadObj, ps256KeyPair.privateKey, {
        alg: "PS256",
      });
      const { payload, protectedHeader } = await verify<JWTClaims>(
        jws,
        ps256KeyPair.publicKey,
      );
      expect(payload).toEqual(payloadObj);
      expect(protectedHeader.alg).toBe("PS256");
    });

    it("should verify with b64: false", async () => {
      const jws = await sign(payloadString, hs256Key, {
        alg: "HS256",
        protectedHeader: { b64: false },
      });
      const { payload, protectedHeader } = await verify<Uint8Array>(
        jws,
        hs256Key,
      ); // b64:false returns Uint8Array
      expect(payload).toBeInstanceOf(Uint8Array);
      expect(new TextDecoder().decode(payload)).toBe(payloadString);
      expect(protectedHeader.alg).toBe("HS256");
      expect(protectedHeader.b64).toBe(false);
    });

    it("should verify with sync key lookup function", async () => {
      const jws = await sign(payloadObj, hs256Key, {
        alg: "HS256",
        protectedHeader: { kid: "key1" },
      });
      const keyLookup = (header: JWSProtectedHeader) => {
        if (header.kid === "key1" && header.alg === "HS256") {
          return hs256Key;
        }
        throw new Error("Key not found");
      };
      const { payload } = await verify(jws, keyLookup);
      expect(payload).toEqual(payloadObj);
    });

    it("should verify with async key lookup function", async () => {
      const jws = await sign(payloadObj, hs256Key, {
        alg: "HS256",
        protectedHeader: { kid: "key2" },
      });
      const keyLookup = async (header: JWSProtectedHeader) => {
        await new Promise((resolve) => setTimeout(resolve, 10)); // Simulate async
        if (header.kid === "key2" && header.alg === "HS256") {
          return hs256Key;
        }
        throw new Error("Key not found");
      };
      const { payload } = await verify(jws, keyLookup);
      expect(payload).toEqual(payloadObj);
    });

    it("should verify with algorithms option (success)", async () => {
      const jws = await sign(payloadObj, hs256Key, { alg: "HS256" });
      await expect(
        verify(jws, hs256Key, { algorithms: ["HS256", "ES256"] }),
      ).resolves.toBeDefined();
    });

    it("should throw if algorithm not allowed", async () => {
      const jws = await sign(payloadObj, hs256Key, { alg: "HS256" });
      await expect(
        verify(jws, hs256Key, { algorithms: ["ES256", "RS256"] }),
      ).rejects.toThrow("Algorithm not allowed: HS256");
    });

    it("should handle critical headers (success)", async () => {
      const jws = await sign(payloadString, hs256Key, {
        alg: "HS256",
        protectedHeader: { crit: ["exp"], exp: 12_345 },
      });
      // We "understand" 'exp' because it's in the options.critical array
      await expect(
        verify(jws, hs256Key, { critical: ["exp"] }),
      ).resolves.toBeDefined();
    });

    it("should throw if crit present but no critical options provided", async () => {
      const jws = await sign(payloadString, hs256Key, {
        alg: "HS256",
        protectedHeader: { crit: ["exp"], exp: 12_345 },
      });
      // No critical option passed to verify
      await expect(verify(jws, hs256Key)).rejects.toThrow(
        "Unprocessed critical header parameters: exp",
      );
    });

    it("should throw for invalid JWS format", async () => {
      await expect(verify("a.b", hs256Key)).rejects.toThrow(
        "Invalid JWS: Must contain three parts",
      );
    });

    it("should throw for invalid header base64", async () => {
      await expect(verify("a?.b.c", hs256Key)).rejects.toThrow(
        /Protected header is not valid Base64URL/,
      );
    });

    it("should throw for invalid header JSON", async () => {
      const invalidHeader = base64UrlEncode(textEncoder.encode("not json"));
      await expect(
        verify(`${invalidHeader}.payload.sig`, hs256Key),
      ).rejects.toThrow(/Protected header is not valid Base64URL or JSON/);
    });

    it("should throw for header missing alg", async () => {
      const headerWithoutAlg = base64UrlEncode(
        textEncoder.encode(JSON.stringify({ typ: "JWT" })),
      );
      await expect(
        verify(`${headerWithoutAlg}.payload.sig`, hs256Key),
      ).rejects.toThrow(
        /Protected header must be an object with an "alg" property/,
      );
    });

    it("should throw for invalid signature base64", async () => {
      const jws = await sign(payloadObj, hs256Key, { alg: "HS256" });
      const parts = jws.split(".");
      await expect(
        verify(`${parts[0]}.${parts[1]}.sig?`, hs256Key),
      ).rejects.toThrow(/Signature is not valid Base64URL/);
    });

    it("should throw for signature mismatch", async () => {
      const jws = await sign(payloadObj, hs256Key, { alg: "HS256" });
      const otherKey = await generateKey("HS256");
      await expect(verify(jws, otherKey)).rejects.toThrow(
        "JWS signature verification failed",
      );
    });

    it("should throw if key lookup function fails", async () => {
      const jws = await sign(payloadObj, hs256Key, {
        alg: "HS256",
        protectedHeader: { kid: "key3" },
      });
      const keyLookup = (_header: JWSProtectedHeader) => {
        throw new Error("Key lookup failed");
      };
      await expect(verify(jws, keyLookup)).rejects.toThrow("Key lookup failed");
    });

    it("should throw if payload decoding fails (e.g., invalid base64)", async () => {
      const header = base64UrlEncode(
        textEncoder.encode(JSON.stringify({ alg: "HS256" })),
      );
      const sig = base64UrlEncode(new Uint8Array(32)); // Dummy sig
      await expect(
        verify(`${header}.invalid?payload.${sig}`, hs256Key),
      ).rejects.toThrow("JWS signature verification failed.");
    });
  });
});
