import { describe, it, expect, beforeAll } from "vitest";
import { sign, verify } from "../src/jws";
import { generateKey, exportKey, importKey } from "../src/jwk";
import { base64UrlEncode, base64UrlDecode, textEncoder } from "../src/utils";
import type { JWK } from "../src/types";

// --- Test Data ---
const payloadString = "Hello, JWS!";
const payloadObject = { sub: "123", name: "test", iat: 1_678_886_400 };
const payloadBytes = textEncoder.encode(payloadString);
const payloadBuffer = payloadBytes.buffer as ArrayBuffer;

// --- Keys (Generated once for efficiency) ---
let hs256Key: CryptoKey;
let hs256Jwk: JWK;
let rs256KeyPair: CryptoKeyPair;
let rs256PublicJwk: JWK;
let rs256PrivateJwk: JWK;
let ps256KeyPair: CryptoKeyPair;
let ps256PublicJwk: JWK;
let ps256PrivateJwk: JWK;

beforeAll(async () => {
  // HS256
  hs256Key = await generateKey("HS256");
  hs256Jwk = await exportKey(hs256Key);

  // RS256
  rs256KeyPair = await generateKey("RS256");
  rs256PublicJwk = await exportKey(rs256KeyPair.publicKey);
  rs256PrivateJwk = await exportKey(rs256KeyPair.privateKey);

  // PS256
  ps256KeyPair = await generateKey("PS256");
  ps256PublicJwk = await exportKey(ps256KeyPair.publicKey);
  ps256PrivateJwk = await exportKey(ps256KeyPair.privateKey);
});

// --- Helper to Decode JWS for Inspection ---
const decodeJws = (jws: string) => {
  const parts = jws.split(".");
  if (parts.length !== 3) throw new Error("Invalid JWS format");
  const [header, payload, signature] = parts;
  return {
    header: JSON.parse(base64UrlDecode(header)),
    payload: base64UrlDecode(payload), // Decode as string for easy comparison
    signatureBytes: base64UrlDecode(signature, false),
    headerRaw: header,
    payloadRaw: payload,
    signatureRaw: signature,
  };
};

describe("JWS Utilities", () => {
  describe("sign", () => {
    it("should sign with HS256 CryptoKey", async () => {
      const jws = await sign(payloadString, hs256Key);
      const decoded = decodeJws(jws);
      expect(decoded.header.alg).toBe("HS256");
      expect(decoded.payload).toBe(payloadString);
      expect(decoded.signatureBytes.length).toBeGreaterThan(0);
    });

    it("should sign with HS256 JWK", async () => {
      const jws = await sign(JSON.stringify(payloadObject), hs256Jwk); // Use object payload
      const decoded = decodeJws(jws);
      expect(decoded.header.alg).toBe("HS256");
      expect(JSON.parse(decoded.payload)).toEqual(payloadObject);
    });

    it("should sign with RS256 CryptoKey (private)", async () => {
      const jws = await sign(payloadBytes, rs256KeyPair.privateKey); // Use Uint8Array
      const decoded = decodeJws(jws);
      expect(decoded.header.alg).toBe("RS256");
      expect(base64UrlDecode(decoded.payloadRaw, false)).toEqual(payloadBytes);
    });

    it("should sign with RS256 JWK (private)", async () => {
      const jws = await sign(payloadBuffer, rs256PrivateJwk); // Use ArrayBuffer
      const decoded = decodeJws(jws);
      expect(decoded.header.alg).toBe("RS256");
      expect(base64UrlDecode(decoded.payloadRaw, false).buffer).toEqual(payloadBuffer);
    });

    it("should sign with PS256 CryptoKey (private)", async () => {
      const jws = await sign(payloadString, ps256KeyPair.privateKey);
      const decoded = decodeJws(jws);
      expect(decoded.header.alg).toBe("PS256");
      expect(decoded.payload).toBe(payloadString);
    });

    it("should sign with PS256 JWK (private)", async () => {
      const jws = await sign(payloadString, ps256PrivateJwk);
      const decoded = decodeJws(jws);
      expect(decoded.header.alg).toBe("PS256");
      expect(decoded.payload).toBe(payloadString);
    });

    it("should use alg from protectedHeader if provided", async () => {
      const jws = await sign(payloadString, hs256Key, {
        protectedHeader: { alg: "HS256", typ: "JWT" },
      });
      const decoded = decodeJws(jws);
      expect(decoded.header.alg).toBe("HS256");
      expect(decoded.header.typ).toBe("JWT");
    });

    it("should infer alg from CryptoKey if not in JWK or options", async () => {
      // Create a JWK without 'alg'
      const hs256JwkNoAlg = { ...hs256Jwk };
      delete hs256JwkNoAlg.alg;
      const importedKey = await importKey(hs256JwkNoAlg, { alg: "HS256" }); // Need alg for import

      // Sign using the CryptoKey, alg should be inferred
      const jws = await sign(payloadString, importedKey);
      const decoded = decodeJws(jws);
      expect(decoded.header.alg).toBe("HS256"); // Inferred correctly
    });

    it("should throw if alg cannot be determined", async () => {
      const hs256JwkNoAlg = { ...hs256Jwk };
      delete hs256JwkNoAlg.alg;
      // Attempting to sign with a JWK that lacks 'alg' and no options.protectedHeader.alg
      await expect(sign(payloadString, hs256JwkNoAlg)).rejects.toThrow(
        "Algorithm ('alg') missing in JWK and options, cannot infer for 'oct' key type.",
      );
    });

    it("should throw for unsupported algorithm in options", async () => {
      await expect(
        sign(payloadString, hs256Key, {
          protectedHeader: { alg: "UnsupportedAlg" },
        }),
      ).rejects.toThrow(/Algorithm must be specified.*UnsupportedAlg/);
    });

    it("should throw for invalid key type", async () => {
      // @ts-expect-error - Testing invalid type
      await expect(sign(payloadString, "not-a-key")).rejects.toThrow(
        "Invalid key type. Key must be a CryptoKey or JWK.",
      );
      // @ts-expect-error - Testing invalid type
      await expect(sign(payloadString, {})).rejects.toThrow(
        "Invalid key type. Key must be a CryptoKey or JWK.",
      );
      // @ts-expect-error - Testing invalid type
      await expect(sign(payloadString, null)).rejects.toThrow(
        "Invalid key type. Key must be a CryptoKey or JWK.",
      );
    });

    it("should throw if CryptoKey algorithm cannot be mapped", async () => {
      // Generate a key type sign doesn't know how to map (e.g., AES-GCM)
      const aesKey = await generateKey("A128GCM");
      await expect(sign(payloadString, aesKey)).rejects.toThrow(
        /Unsupported key algorithm: AES-GCM/,
      );
    });
  });

  describe("verify", () => {
    let hs256Jws: string;
    let rs256Jws: string;
    let ps256Jws: string;

    beforeAll(async () => {
      hs256Jws = await sign(JSON.stringify(payloadObject), hs256Jwk);
      rs256Jws = await sign(payloadString, rs256PrivateJwk);
      ps256Jws = await sign(payloadBytes, ps256PrivateJwk);
    });

    // --- Successful Verifications ---

    it("should verify HS256 with CryptoKey", async () => {
      const { payload, protectedHeader } = await verify(hs256Jws, hs256Key);
      expect(protectedHeader.alg).toBe("HS256");
      expect(JSON.parse(payload)).toEqual(payloadObject); // Default toString: true
    });

    it("should verify HS256 with JWK", async () => {
      const { payload, protectedHeader } = await verify(hs256Jws, hs256Jwk);
      expect(protectedHeader.alg).toBe("HS256");
      expect(JSON.parse(payload)).toEqual(payloadObject);
    });

    it("should verify RS256 with CryptoKey (public)", async () => {
      const { payload, protectedHeader } = await verify(
        rs256Jws,
        rs256KeyPair.publicKey,
      );
      expect(protectedHeader.alg).toBe("RS256");
      expect(payload).toBe(payloadString);
    });

    it("should verify RS256 with JWK (public)", async () => {
      const { payload, protectedHeader } = await verify(
        rs256Jws,
        rs256PublicJwk,
      );
      expect(protectedHeader.alg).toBe("RS256");
      expect(payload).toBe(payloadString);
    });

    it("should verify PS256 with CryptoKey (public)", async () => {
      const { payload, protectedHeader } = await verify(
        ps256Jws,
        ps256KeyPair.publicKey,
        { toString: false }, // Request Uint8Array
      );
      expect(protectedHeader.alg).toBe("PS256");
      expect(payload).toBeInstanceOf(Uint8Array);
      expect(payload).toEqual(payloadBytes);
    });

    it("should verify PS256 with JWK (public)", async () => {
      const { payload, protectedHeader } = await verify(
        ps256Jws,
        ps256PublicJwk,
        { toString: false },
      );
      expect(protectedHeader.alg).toBe("PS256");
      expect(payload).toEqual(payloadBytes);
    });

    it("should verify using a key retrieval function", async () => {
      const keyResolver = async (header: any) => {
        expect(header.alg).toBe("HS256");
        // Simulate async lookup
        await new Promise((r) => setTimeout(r, 10));
        return hs256Jwk; // Return the correct JWK
      };
      const { payload } = await verify(hs256Jws, keyResolver);
      expect(JSON.parse(payload as string)).toEqual(payloadObject);
    });

    // --- Verification Failures and Errors ---

    it("should throw for invalid JWS format (too few parts)", async () => {
      await expect(verify("a.b", hs256Key)).rejects.toThrow(
        "Invalid JWS format: Must contain three parts separated by dots.",
      );
    });

    it("should throw for invalid JWS format (too many parts)", async () => {
      await expect(verify("a.b.c.d", hs256Key)).rejects.toThrow(
        "Invalid JWS format: Must contain three parts separated by dots.",
      );
    });

    it("should throw for invalid header encoding", async () => {
      const parts = hs256Jws.split(".");
      const invalidJws = `!invalid-base64.${parts[1]}.${parts[2]}`;
      await expect(verify(invalidJws, hs256Key)).rejects.toThrow(
        "Invalid JWS: Failed to decode or parse protected header.",
      );
    });

    it("should throw for unsupported algorithm in header", async () => {
      const jws = await sign(payloadString, hs256Key, {
        protectedHeader: { alg: "HS256" },
      });
      const parts = jws.split(".");
      // Manually create a header with an unsupported alg
      const badHeader = base64UrlEncode(JSON.stringify({ alg: "Unsupported" }));
      const invalidJws = `${badHeader}.${parts[1]}.${parts[2]}`;
      await expect(verify(invalidJws, hs256Key)).rejects.toThrow(
        "Unsupported or missing algorithm in JWS header: Unsupported",
      );
    });

    it("should throw for missing algorithm in header", async () => {
      const jws = await sign(payloadString, hs256Key, {
        protectedHeader: { alg: "HS256" },
      });
      const parts = jws.split(".");
      // Manually create a header without alg
      const badHeader = base64UrlEncode(JSON.stringify({ typ: "JWT" }));
      const invalidJws = `${badHeader}.${parts[1]}.${parts[2]}`;
      await expect(verify(invalidJws, hs256Key)).rejects.toThrow(
        "Unsupported or missing algorithm in JWS header: undefined",
      );
    });

    it("should throw if signature verification fails (wrong key)", async () => {
      const wrongHs256Key = await generateKey("HS256");
      await expect(verify(hs256Jws, wrongHs256Key)).rejects.toThrow(
        "JWS signature verification failed.",
      );
      await expect(verify(rs256Jws, ps256KeyPair.publicKey)).rejects.toThrow(
        // RS key for PS JWS
        "Unable to use this key to verify",
      );
    });

    it("should throw if signature verification fails (tampered payload)", async () => {
      const parts = hs256Jws.split(".");
      const tamperedPayload = base64UrlEncode(
        JSON.stringify({ ...payloadObject, hacked: true }),
      );
      const tamperedJws = `${parts[0]}.${tamperedPayload}.${parts[2]}`;
      await expect(verify(tamperedJws, hs256Key)).rejects.toThrow(
        "JWS signature verification failed.",
      );
    });

    it("should throw if signature verification fails (tampered signature)", async () => {
      const parts = hs256Jws.split(".");
      const tamperedSig = parts[2]?.slice(0, -1) + "A"; // Change last char
      const tamperedJws = `${parts[0]}.${parts[1]}.${tamperedSig}`;
      await expect(verify(tamperedJws, hs256Key)).rejects.toThrow(
        "JWS signature verification failed.",
      );
    });

    it("should throw for invalid key type provided to verify", async () => {
      // @ts-expect-error - Testing invalid type
      await expect(verify(hs256Jws, "not-a-key")).rejects.toThrow(
        "Invalid key type provided or returned by key retrieval function.",
      );
      // @ts-expect-error - Testing invalid type
      await expect(verify(hs256Jws, {})).rejects.toThrow(
        "Invalid key type provided or returned by key retrieval function.",
      );
    });

    it("should throw if JWK alg mismatches header alg", async () => {
      const hs512Jwk = await exportKey(await generateKey("HS512")); // Key with HS512 alg
      await expect(verify(hs256Jws, hs512Jwk)).rejects.toThrow(
        // Verify HS256 JWS with HS512 key/JWK
        "JWS header algorithm 'HS256' does not match JWK algorithm 'HS512'.",
      );
    });

    it("should throw if key retrieval function returns invalid type", async () => {
      const keyResolver = async () => {
        return "not-a-key"; // Function returns wrong type
      };
      // @ts-expect-error - Testing invalid return type
      await expect(verify(hs256Jws, keyResolver)).rejects.toThrow(
        "Invalid key type provided or returned by key retrieval function.",
      );
    });
  });
});
