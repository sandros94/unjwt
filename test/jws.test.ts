import * as jose from "jose";
import { describe, it, expect, beforeAll } from "vitest";
import { sign, verify } from "../src/jws";
import { generateKey, exportKey } from "../src/jwk";
import {
  base64UrlEncode,
  base64UrlDecode,
  textEncoder,
  textDecoder,
} from "../src/utils";
import type { JWSProtectedHeader, JWTClaims, JWK, JWKSet } from "../src/types";

describe.concurrent("JWS Utilities", () => {
  const payloadObj = {
    sub: "1234567890",
    name: "John Doe",
    iat: 1_516_239_022,
  };
  const payloadBytes = textEncoder.encode("Payload as bytes");
  const payloadString = "Payload as string";

  describe("sign", () => {
    it("should sing while inferring alg from JWK", async () => {
      const t = "Hello, World!";
      const jwk: JWK = {
        key_ops: ["sign", "verify"],
        ext: true,
        kty: "oct",
        k: "OZ3BsJChEniZwQhiyZdML26Ovchsjqal9sAQR7DsBfc4xBFlcxqYzlOO77MNd0CnPKdznatgsELJjW02BqaqVw",
        alg: "HS256",
      };

      const jws = await sign(t, jwk);
      const { payload } = await verify(jws, jwk);
      expect(payload).toBe(t);

      const { payload: josePayload } = await jose.compactVerify(jws, jwk);
      expect(textDecoder.decode(josePayload)).toBe(t);
    });

    it("should sign with HS256 (Object payload)", async () => {
      const key = await generateKey("HS256");
      const jws = await sign(payloadObj, key, { alg: "HS256" });
      expect(jws.split(".").length).toBe(3);
      const [headerEncoded] = jws.split(".");
      const header = JSON.parse(base64UrlDecode(headerEncoded));
      expect(header.alg).toBe("HS256");
      expect(header.typ).toBe("JWT"); // Default for object

      const { payload: josePayload } = await jose.compactVerify(jws, key);
      expect(JSON.parse(textDecoder.decode(josePayload))).toEqual(payloadObj);
    });

    it("should sign with HS256 (Uint8Array payload)", async () => {
      const key = await generateKey("HS256");
      const jws = await sign(payloadBytes, key, { alg: "HS256" });
      expect(jws.split(".").length).toBe(3);
      const [headerEncoded, payloadEncoded] = jws.split(".");
      const header = JSON.parse(base64UrlDecode(headerEncoded));
      expect(header.alg).toBe("HS256");
      expect(header.typ).toBeUndefined(); // No default typ for bytes
      expect(base64UrlDecode(payloadEncoded, false)).toEqual(payloadBytes);

      const { payload: josePayload } = await jose.compactVerify(jws, key);
      expect(josePayload).toEqual(payloadBytes);
    });

    it("should sign with HS256 (String payload)", async () => {
      const key = await generateKey("HS256");
      const jws = await sign(payloadString, key, { alg: "HS256" });
      expect(jws.split(".").length).toBe(3);
      const [headerEncoded, payloadEncoded] = jws.split(".");
      const header = JSON.parse(base64UrlDecode(headerEncoded));
      expect(header.alg).toBe("HS256");
      expect(header.typ).toBeUndefined(); // No default typ for string
      expect(base64UrlDecode(payloadEncoded, true)).toEqual(payloadString);

      const { payload: josePayload } = await jose.compactVerify(jws, key);
      expect(textDecoder.decode(josePayload)).toEqual(payloadString);
    });

    it("should sign with RS256", async () => {
      const { privateKey, publicKey } = await generateKey("RS256", {
        modulusLength: 2048,
      });
      const jws = await sign(payloadObj, privateKey, { alg: "RS256" });
      expect(jws.split(".").length).toBe(3);
      const [headerEncoded] = jws.split(".");
      const header = JSON.parse(base64UrlDecode(headerEncoded));
      expect(header.alg).toBe("RS256");

      const { payload: josePayload } = await jose.compactVerify(jws, publicKey);
      expect(JSON.parse(textDecoder.decode(josePayload))).toEqual(payloadObj);
    });

    it("should sign with ES256", async () => {
      const { privateKey, publicKey } = await generateKey("ES256");
      const jws = await sign(payloadObj, privateKey, { alg: "ES256" });
      expect(jws.split(".").length).toBe(3);
      const [headerEncoded] = jws.split(".");
      const header = JSON.parse(base64UrlDecode(headerEncoded));
      expect(header.alg).toBe("ES256");

      const { payload: josePayload } = await jose.compactVerify(jws, publicKey);
      expect(JSON.parse(textDecoder.decode(josePayload))).toEqual(payloadObj);
    });

    it("should sign with PS256", async () => {
      const { privateKey, publicKey } = await generateKey("PS256", {
        modulusLength: 2048,
      });
      const jws = await sign(payloadObj, privateKey, { alg: "PS256" });
      expect(jws.split(".").length).toBe(3);
      const [headerEncoded] = jws.split(".");
      const header = JSON.parse(base64UrlDecode(headerEncoded));
      expect(header.alg).toBe("PS256");

      const { payload: josePayload } = await jose.compactVerify(jws, publicKey);
      expect(JSON.parse(textDecoder.decode(josePayload))).toEqual(payloadObj);
    });

    it("should sign with Ed25519", async () => {
      const { privateKey, publicKey } = await generateKey("Ed25519");
      const jws = await sign(payloadObj, privateKey, { alg: "Ed25519" });
      expect(jws.split(".").length).toBe(3);
      const [headerEncoded] = jws.split(".");
      const header = JSON.parse(base64UrlDecode(headerEncoded));
      expect(header.alg).toBe("Ed25519");

      const { payload: josePayload } = await jose.compactVerify(jws, publicKey);
      expect(JSON.parse(textDecoder.decode(josePayload))).toEqual(payloadObj);
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
      const header = JSON.parse(base64UrlDecode(headerEncoded));
      expect(header.alg).toBe("HS256");
      expect(header.b64).toBe(false);
      expect(payloadRaw).toBe(payloadString); // Payload is not base64 encoded

      // jose library doesn't support `b64: false`
    });

    it("should include custom protected headers", async () => {
      const key = await generateKey("HS256");
      const jws = await sign(payloadObj, key, {
        alg: "HS256",
        protectedHeader: { kid: "test-key-1", typ: "custom" },
      });
      const [headerEncoded] = jws.split(".");
      const header = JSON.parse(base64UrlDecode(headerEncoded));
      expect(header.alg).toBe("HS256");
      expect(header.kid).toBe("test-key-1");
      expect(header.typ).toBe("custom"); // Overrides default

      const { protectedHeader: joseHeader } = await jose.compactVerify(
        jws,
        key,
      );
      expect(joseHeader.kid).toBe("test-key-1");
      expect(joseHeader.typ).toBe("custom");
    });

    it("should include computed `exp`", async () => {
      const key = await generateKey("HS256", { toJWK: true });
      const jws = await sign({ ...payloadObj, iat: undefined }, key, {
        expiresIn: "1m", // 1 minute expiration
      });
      const [_headerEncoded, payloadEncoded] = jws.split(".");
      const payload = JSON.parse(base64UrlDecode(payloadEncoded));
      expect(payload.iat).toBeDefined();
      expect(payload.exp).toBeDefined();

      const { payload: josePayload } = await jose.jwtVerify(jws, key);
      expect(josePayload.iat).toBeDefined();
      expect(josePayload.exp).toBeDefined();
    });

    it("should include computed `exp` and throw because it is expired", async () => {
      // setting `currentDate` 2 minutes in the past for testing purposes
      const date = new Date();
      const creationDate = new Date(date.getTime() - 60 * 2 * 1000);
      const key = await generateKey("HS256", { toJWK: true });
      const jws = await sign(
        {
          ...payloadObj,
          exp: undefined,
          iat: undefined,
        },
        key,
        {
          currentDate: creationDate,
          expiresIn: 60, // 1 minute expiration
        },
      );
      const [_headerEncoded, payloadEncoded] = jws.split(".");
      const payload = JSON.parse(base64UrlDecode(payloadEncoded));
      expect(payload.exp).toEqual(
        Math.round(creationDate.getTime() / 1000) + 60,
      ); // expired 1 minute ago

      await expect(
        jose.jwtVerify(jws, key, {
          currentDate: date,
        }),
      ).rejects.toThrow('"exp" claim timestamp check failed');

      await expect(
        verify(jws, key, {
          currentDate: date,
        }),
      ).rejects.toThrow(
        `JWT "exp" (Expiration Time) Claim validation failed: Token has expired (exp: ${new Date(
          payload.exp * 1000,
        ).toISOString()})`,
      );
    });

    it("should not include computed `exp`", async () => {
      const key = await generateKey("HS256", { toJWK: true });
      const jws = await sign(payloadString, key, {
        expiresIn: 60, // 1 minute expiration
      });
      const [headerEncoded, payload] = jws.split(".");
      const header = JSON.parse(base64UrlDecode(headerEncoded));
      expect(header.alg).toBe("HS256");
      expect(base64UrlDecode(payload)).toEqual(payloadString);

      const { payload: josePayload } = await jose.compactVerify(jws, key);
      expect(textDecoder.decode(josePayload)).toEqual(payloadString);
    });

    it("should throw if alg is missing", async () => {
      const key = await generateKey("HS256");
      await expect(sign(payloadObj, key, {} as any)).rejects.toThrow(
        'JWS "alg" (Algorithm) must be provided',
      );
    });

    it("should throw on Uint8Array key too small", async () => {
      await expect(
        sign(payloadObj, textEncoder.encode("small-key"), {
          alg: "HS256",
        }),
      ).rejects.toThrow("HS256 requires key length to be 32 bytes or larger");
    });

    it("should throw on RS CryptoKey too small", async () => {
      const invalidRSKey = await generateKey("RS256", {
        modulusLength: 1024,
      });

      await expect(
        sign(payloadObj, invalidRSKey.privateKey, {
          alg: "RS256",
        }),
      ).rejects.toThrow(
        "RS256 requires key modulusLength to be 2048 bits or larger",
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
    let jwkSet: JWKSet;

    // Keys for jose
    let joseJwkSet: (
      protectedHeader?: jose.JWSHeaderParameters,
      token?: jose.FlattenedJWSInput,
    ) => Promise<jose.CryptoKey | Uint8Array>;

    const basicJwtPayload: JWTClaims = {
      iss: "test-issuer",
      sub: "test-subject",
      aud: "test-audience",
      exp: Math.floor(Date.now() / 1000) + 3600, // Expires in 1 hour
      nbf: Math.floor(Date.now() / 1000) - 3600, // Valid since 1 hour ago
      iat: Math.floor(Date.now() / 1000) - 1800, // Issued 30 minutes ago
      jti: "jwt-id-123",
    };

    beforeAll(async () => {
      const [hs256, rs256Pair, es256Pair, ps256Pair] = await Promise.all([
        generateKey("HS256"),
        generateKey("RS256", { modulusLength: 2048 }),
        generateKey("ES256"),
        generateKey("PS256", { modulusLength: 2048 }),
      ]);
      hs256Key = hs256;
      rs256KeyPair = rs256Pair;
      es256KeyPair = es256Pair;
      ps256KeyPair = ps256Pair;

      jwkSet = {
        keys: await Promise.all([
          exportKey(hs256Key, { kid: "key2" }),
          exportKey(rs256KeyPair.publicKey, { kid: "key1" }),
          exportKey(es256KeyPair.publicKey, { kid: "key66" }),
          exportKey(ps256KeyPair.publicKey, { kid: "key69" }),
        ]),
      };

      joseJwkSet = jose.createLocalJWKSet(jwkSet);
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

      const { payload: josePayload } = await jose.compactVerify(jws, hs256Key);
      expect(JSON.parse(textDecoder.decode(josePayload))).toEqual(payloadObj);
    });

    it("should verify HS256 (Uint8Array payload)", async () => {
      const jws = await sign(payloadBytes, hs256Key, { alg: "HS256" });
      const { payload, protectedHeader } = await verify<
        Uint8Array<ArrayBuffer>
      >(jws, hs256Key, {
        forceUint8Array: true,
      });
      expect(payload).toBeInstanceOf(Uint8Array);
      expect(payload).toEqual(payloadBytes);
      expect(protectedHeader.alg).toBe("HS256");
      expect(protectedHeader.typ).toBeUndefined();

      const { payload: josePayload } = await jose.compactVerify(jws, hs256Key);
      expect(josePayload).toEqual(payloadBytes);
    });

    it("should verify HS256 (String payload)", async () => {
      const jws = await sign(payloadString, hs256Key, { alg: "HS256" });
      const { payload, protectedHeader } = await verify<string>(jws, hs256Key);
      expect(payload).toBeTypeOf("string");
      expect(payload).toEqual(payloadString);
      expect(protectedHeader.alg).toBe("HS256");

      const { payload: josePayload } = await jose.compactVerify(jws, hs256Key);
      expect(textDecoder.decode(josePayload)).toEqual(payloadString);
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

      const { payload: josePayload } = await jose.compactVerify(
        jws,
        rs256KeyPair.publicKey,
      );
      expect(JSON.parse(textDecoder.decode(josePayload))).toEqual(payloadObj);
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

      const { payload: josePayload } = await jose.compactVerify(
        jws,
        es256KeyPair.publicKey,
      );
      expect(JSON.parse(textDecoder.decode(josePayload))).toEqual(payloadObj);
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

      const { payload: josePayload } = await jose.compactVerify(
        jws,
        ps256KeyPair.publicKey,
      );
      expect(JSON.parse(textDecoder.decode(josePayload))).toEqual(payloadObj);
    });

    it("should verify with b64: false", async () => {
      const jws = await sign(payloadString, hs256Key, {
        alg: "HS256",
        protectedHeader: { b64: false },
      });
      // When b64 is false, and forceUint8Array is not true,
      // and typ is not JWT, the payload is treated as a raw string.
      // If typ were JWT, it would attempt to JSON.parse it.
      // If forceUint8Array were true, it would be Uint8Array.
      const { payload, protectedHeader } = await verify<string>(jws, hs256Key);
      expect(protectedHeader.b64).toBe(false);
      expect(protectedHeader.alg).toBe("HS256");
      expect(typeof payload).toBe("string");
      expect(payload).toBe(payloadString);

      // jose library doesn't support `b64: false`
    });

    it("should verify with b64: false and forceUint8Array", async () => {
      const jws = await sign(payloadString, hs256Key, {
        alg: "HS256",
        protectedHeader: { b64: false },
      });
      const { payload, protectedHeader } = await verify<
        Uint8Array<ArrayBuffer>
      >(jws, hs256Key, {
        forceUint8Array: true,
      });
      expect(protectedHeader.b64).toBe(false);
      expect(payload).toBeInstanceOf(Uint8Array);
      expect(textDecoder.decode(payload)).toBe(payloadString);

      // jose library doesn't support `b64: false`
    });

    it("should verify with keyset", async () => {
      const jws = await sign(payloadObj, hs256Key, {
        alg: "HS256",
        protectedHeader: { kid: "key2" },
      });

      const { payload } = await verify(jws, jwkSet);
      expect(payload).toEqual(payloadObj);
    });

    it("should verify with JWK known in the keyset", async () => {
      const rsPrKey = await exportKey(rs256KeyPair.privateKey, { kid: "key1" });
      const jws = await sign(payloadObj, rsPrKey);

      const { protectedHeader, payload } = await verify(jws, jwkSet);
      expect(protectedHeader.kid).toBe("key1");
      expect(payload).toEqual(payloadObj);

      const { payload: josePayload } = await jose.compactVerify(
        jws,
        joseJwkSet,
      );
      expect(JSON.parse(textDecoder.decode(josePayload))).toEqual(payloadObj);
    });

    it("should verify with sync key lookup function", async () => {
      const jws = await sign(payloadObj, hs256Key, {
        alg: "HS256",
        protectedHeader: { kid: "key1" }, // Using "key1" kid for test purposes
      });

      const keyLookup = (header: JWSProtectedHeader) => {
        if (header.kid === "key1" && header.alg === "HS256") {
          return hs256Key;
        }
        throw new Error("Key not found");
      };

      const { payload } = await verify(jws, keyLookup);
      expect(payload).toEqual(payloadObj);

      const { payload: josePayload } = await jose.compactVerify(jws, hs256Key);
      expect(JSON.parse(textDecoder.decode(josePayload))).toEqual(payloadObj);
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

      const { payload: josePayload } = await jose.compactVerify(jws, hs256Key);
      expect(JSON.parse(textDecoder.decode(josePayload))).toEqual(payloadObj);
    });

    it("should verify with async key set lookup function", async () => {
      const jws = await sign(payloadObj, hs256Key, {
        alg: "HS256",
        protectedHeader: { kid: "key2" },
      });

      const keyLookup = async () => {
        await new Promise((resolve) => setTimeout(resolve, 10)); // Simulate async
        return jwkSet;
      };

      const { payload } = await verify(jws, keyLookup);
      expect(payload).toEqual(payloadObj);
    });

    it("should verify with algorithms option (success)", async () => {
      const jws = await sign(payloadObj, hs256Key, { alg: "HS256" });
      await expect(
        verify(jws, hs256Key, { algorithms: ["HS256", "ES256"] }),
      ).resolves.toBeDefined();

      await expect(
        jose.compactVerify(jws, hs256Key, {
          algorithms: ["HS256", "ES256"],
        }),
      ).resolves.toBeDefined();
    });

    describe("Critical Header ('crit') Validation", () => {
      it("should succeed if 'crit' headers are known and processed (e.g. b64)", async () => {
        // 'b64' is implicitly understood.
        const jws = await sign(payloadString, hs256Key, {
          alg: "HS256",
          protectedHeader: { crit: ["b64"], b64: true },
        });
        await expect(verify(jws, hs256Key)).resolves.toBeDefined();
      });

      it("should succeed if 'crit' headers are known and present (e.g. alg)", async () => {
        // 'alg' is implicitly understood and always present.
        const jws = await sign(payloadString, hs256Key, {
          alg: "HS256",
          protectedHeader: { crit: ["alg"] }, // alg is already there
        });
        await expect(verify(jws, hs256Key)).resolves.toBeDefined();
      });

      it("should throw if 'crit' lists an unknown header parameter", async () => {
        const jws = await sign(payloadString, hs256Key, {
          alg: "HS256",
          protectedHeader: { crit: ["unknownHeader"], unknownHeader: "value" },
        });
        await expect(verify(jws, hs256Key)).rejects.toThrow(
          "Missing critical header parameters: unknownHeader",
        );

        await expect(jose.compactVerify(jws, hs256Key)).rejects.toThrow(
          'Extension Header Parameter "unknownHeader" is not recognized',
        );
      });

      it("should throw if a header listed in 'crit' is not present", async () => {
        // We'll use 'kid' as an example of a known header that might be critical
        // but isn't provided in this specific JWS.
        const jwsNoKid = await sign(payloadString, hs256Key, {
          alg: "HS256",
          // 'kid' is listed as critical, but not included in the protected header
          protectedHeader: { crit: ["kid"] },
        });
        await expect(verify(jwsNoKid, hs256Key)).rejects.toThrow(
          "Missing critical header parameters: kid",
        );

        // Verify with jose - it also fails because 'kid' is critical but absent.
        await expect(
          jose.compactVerify(jwsNoKid, hs256Key as any, {
            crit: { kid: true },
          }),
        ).rejects.toThrow('Extension Header Parameter "kid" is missing');
      });

      it("should succeed if 'crit' is present and all params are known, even if options.critical is not set", async () => {
        const jws = await sign(payloadString, hs256Key, {
          alg: "HS256",
          protectedHeader: { crit: ["b64"], b64: false }, // b64 is known
        });
        await expect(verify(jws, hs256Key)).resolves.toBeDefined();

        await expect(jose.compactVerify(jws, hs256Key)).resolves.toBeDefined();
      });
    });

    describe("JWT Claim Validations", () => {
      it("should validate 'typ' header parameter (success)", async () => {
        const jws = await sign(basicJwtPayload, hs256Key, {
          alg: "HS256",
          protectedHeader: { typ: "JWT" },
        });
        await expect(
          verify(jws, hs256Key, { typ: "JWT" }),
        ).resolves.toBeDefined();

        await expect(
          jose.jwtVerify(jws, hs256Key, { typ: "JWT" }),
        ).resolves.toBeDefined();
      });

      it("should validate 'typ' header parameter (failure)", async () => {
        const jws = await sign(basicJwtPayload, hs256Key, {
          alg: "HS256",
          protectedHeader: { typ: "application/custom" },
        });
        await expect(verify(jws, hs256Key, { typ: "JWT" })).rejects.toThrow(
          'Invalid JWS: "typ" (Type) Header Parameter mismatch. Expected "JWT", got "application/custom".',
        );

        await expect(
          jose.jwtVerify(jws, hs256Key, { typ: "JWT" }),
        ).rejects.toThrow('unexpected "typ" JWT header value');
      });

      it("should succeed if options.typ is undefined, regardless of header.typ", async () => {
        const jwsWithTyp = await sign(basicJwtPayload, hs256Key, {
          alg: "HS256",
          protectedHeader: { typ: "JWT" },
        });
        await expect(verify(jwsWithTyp, hs256Key, {})).resolves.toBeDefined();
        await expect(
          jose.jwtVerify(jwsWithTyp, hs256Key, {}),
        ).resolves.toBeDefined();

        const jwsWithoutTyp = await sign(basicJwtPayload, hs256Key, {
          alg: "HS256",
        }); // typ will be JWT by default for object payload
        await expect(
          verify(jwsWithoutTyp, hs256Key, {}),
        ).resolves.toBeDefined();
        await expect(
          jose.jwtVerify(jwsWithoutTyp, hs256Key, {}),
        ).resolves.toBeDefined();
      });

      it("should validate requiredClaims (success)", async () => {
        const jws = await sign(basicJwtPayload, hs256Key, { alg: "HS256" });
        await expect(
          verify(jws, hs256Key, { requiredClaims: ["iss", "sub", "jti"] }),
        ).resolves.toBeDefined();

        await expect(
          jose.jwtVerify(jws, hs256Key, {
            requiredClaims: ["iss", "sub", "jti"],
          }),
        ).resolves.toBeDefined();
      });

      it("should validate requiredClaims (failure)", async () => {
        const jws = await sign(basicJwtPayload, hs256Key, { alg: "HS256" });
        await expect(
          verify(jws, hs256Key, {
            requiredClaims: ["iss", "nonExistentClaim"],
          }),
        ).rejects.toThrow("Missing required JWT Claims: nonExistentClaim");

        await expect(
          jose.jwtVerify(jws, hs256Key, {
            requiredClaims: ["iss", "nonExistentClaim"],
          }),
        ).rejects.toThrow('missing required "nonExistentClaim" claim');
      });

      it("should validate issuer (success - string)", async () => {
        const jws = await sign(basicJwtPayload, hs256Key, { alg: "HS256" });
        await expect(
          verify(jws, hs256Key, { issuer: "test-issuer" }),
        ).resolves.toBeDefined();

        await expect(
          jose.jwtVerify(jws, hs256Key, { issuer: "test-issuer" }),
        ).resolves.toBeDefined();
      });

      it("should validate issuer (success - array)", async () => {
        const jws = await sign(basicJwtPayload, hs256Key, { alg: "HS256" });
        await expect(
          verify(jws, hs256Key, { issuer: ["another-issuer", "test-issuer"] }),
        ).resolves.toBeDefined();

        await expect(
          jose.jwtVerify(jws, hs256Key, {
            issuer: ["another-issuer", "test-issuer"],
          }),
        ).resolves.toBeDefined();
      });

      it("should validate issuer (failure - mismatch)", async () => {
        const jws = await sign(basicJwtPayload, hs256Key, { alg: "HS256" });
        await expect(
          verify(jws, hs256Key, { issuer: "wrong-issuer" }),
        ).rejects.toThrow(
          'Invalid JWT "iss" (Issuer) Claim: Expected wrong-issuer, got test-issuer',
        );

        await expect(
          jose.jwtVerify(jws, hs256Key, { issuer: "wrong-issuer" }),
        ).rejects.toThrow('unexpected "iss" claim value');
      });

      it("should validate issuer (failure - claim missing)", async () => {
        const payloadWithoutIss = { ...basicJwtPayload };
        delete payloadWithoutIss.iss;
        const jws = await sign(payloadWithoutIss, hs256Key, { alg: "HS256" });
        await expect(
          verify(jws, hs256Key, { issuer: "test-issuer" }),
        ).rejects.toThrow("Missing required JWT Claims: iss");

        await expect(
          jose.jwtVerify(jws, hs256Key, { issuer: "test-issuer" }),
        ).rejects.toThrow('missing required "iss" claim');
      });

      it("should validate subject (success)", async () => {
        const jws = await sign(basicJwtPayload, hs256Key, { alg: "HS256" });
        await expect(
          verify(jws, hs256Key, { subject: "test-subject" }),
        ).resolves.toBeDefined();
      });

      it("should validate subject (failure - mismatch)", async () => {
        const jws = await sign(basicJwtPayload, hs256Key, { alg: "HS256" });
        await expect(
          jose.jwtVerify(jws, hs256Key, { subject: "wrong-subject" }),
        ).rejects.toThrow('unexpected "sub" claim value');
      });

      it("should validate subject (failure - claim missing)", async () => {
        const payloadWithoutSub = { ...basicJwtPayload };
        delete payloadWithoutSub.sub;
        const jws = await sign(payloadWithoutSub, hs256Key, { alg: "HS256" });
        await expect(
          jose.jwtVerify(jws, hs256Key, { subject: "test-subject" }),
        ).rejects.toThrow('missing required "sub" claim');
      });

      it("should validate audience (success - string option, string claim)", async () => {
        const jws = await sign(basicJwtPayload, hs256Key, { alg: "HS256" });
        await expect(
          jose.jwtVerify(jws, hs256Key, {
            audience: "test-audience",
          }),
        ).resolves.toBeDefined();
      });

      it("should validate audience (success - array option, string claim)", async () => {
        const jws = await sign(basicJwtPayload, hs256Key, { alg: "HS256" });
        await expect(
          jose.jwtVerify(jws, hs256Key, {
            audience: ["test-audience", "another-audience"],
          }),
        ).resolves.toBeDefined();
      });

      it("should validate audience (success - string option, array claim)", async () => {
        const payloadWithAudArray = {
          ...basicJwtPayload,
          aud: ["aud1", "test-audience", "aud2"],
        };
        const jws = await sign(payloadWithAudArray, hs256Key, {
          alg: "HS256",
        });
        await expect(
          verify(jws, hs256Key, { audience: "test-audience" }),
        ).resolves.toBeDefined();
      });

      it("should validate audience (success - array option, array claim)", async () => {
        const payloadWithAudArray = {
          ...basicJwtPayload,
          aud: ["aud1", "target-aud", "aud2"],
        };
        const jws = await sign(payloadWithAudArray, hs256Key, {
          alg: "HS256",
        });
        await expect(
          verify(jws, hs256Key, {
            audience: ["other-aud", "target-aud"],
          }),
        ).resolves.toBeDefined();
      });

      it("should validate audience (failure - mismatch)", async () => {
        const jws = await sign(basicJwtPayload, hs256Key, { alg: "HS256" });
        await expect(
          verify(jws, hs256Key, { audience: "wrong-audience" }),
        ).rejects.toThrow(
          'Invalid JWT "aud" (Audience) Claim: Expected wrong-audience, got test-audience',
        );
      });

      it("should validate audience (failure - claim missing)", async () => {
        const payloadWithoutAud = { ...basicJwtPayload };
        delete payloadWithoutAud.aud;
        const jws = await sign(payloadWithoutAud, hs256Key, { alg: "HS256" });
        await expect(
          verify(jws, hs256Key, { audience: "test-audience" }),
        ).rejects.toThrow("Missing required JWT Claims: aud");
      });

      it("should validate nbf (success)", async () => {
        const payload = {
          ...basicJwtPayload,
          nbf: Math.floor(Date.now() / 1000) - 100,
        };
        const jws = await sign(payload, hs256Key, { alg: "HS256" });
        await expect(verify(jws, hs256Key)).resolves.toBeDefined();
      });

      it("should validate nbf (failure - token not yet valid)", async () => {
        const futureNbf = Math.floor(Date.now() / 1000) + 3600;
        const payload = { ...basicJwtPayload, nbf: futureNbf };
        const jws = await sign(payload, hs256Key, { alg: "HS256" });

        await expect(jose.jwtVerify(jws, hs256Key)).rejects.toThrow(
          '"nbf" claim timestamp check failed',
        );

        await expect(verify(jws, hs256Key)).rejects.toThrow(
          `JWT "nbf" (Not Before) Claim validation failed: Token is not yet valid (nbf: ${new Date(
            futureNbf * 1000,
          ).toISOString()})`,
        );
      });

      it("should validate nbf with clockTolerance (success)", async () => {
        const futureNbf = Math.floor(Date.now() / 1000) + 5; // 5 seconds in future
        const payload = { ...basicJwtPayload, nbf: futureNbf };
        const jws = await sign(payload, hs256Key, { alg: "HS256" });
        await expect(
          verify(jws, hs256Key, { clockTolerance: 10 }), // 10s tolerance
        ).resolves.toBeDefined();
      });

      it("should validate exp (success)", async () => {
        const payload = {
          ...basicJwtPayload,
          exp: Math.floor(Date.now() / 1000) + 100,
        };
        const jws = await sign(payload, hs256Key, { alg: "HS256" });
        await expect(verify(jws, hs256Key)).resolves.toBeDefined();
      });

      it("should validate exp (failure - token expired)", async () => {
        const pastExp = Math.floor(Date.now() / 1000) - 3600;
        const payload = { ...basicJwtPayload, exp: pastExp };
        const jws = await sign(payload, hs256Key, { alg: "HS256" });

        await expect(jose.jwtVerify(jws, hs256Key)).rejects.toThrow(
          '"exp" claim timestamp check failed',
        );

        await expect(verify(jws, hs256Key)).rejects.toThrow(
          `JWT "exp" (Expiration Time) Claim validation failed: Token has expired (exp: ${new Date(
            pastExp * 1000,
          ).toISOString()})`,
        );
      });

      it("should validate exp with clockTolerance (success)", async () => {
        const pastExp = Math.floor(Date.now() / 1000) - 5; // Expired 5 seconds ago
        const payload = { ...basicJwtPayload, exp: pastExp };
        const jws = await sign(payload, hs256Key, { alg: "HS256" });
        await expect(
          verify(jws, hs256Key, { clockTolerance: 10 }), // 10s tolerance
        ).resolves.toBeDefined();
      });

      it("should validate maxTokenAge (success)", async () => {
        const iat = Math.floor(Date.now() / 1000) - 60; // Issued 60s ago
        const payload = { ...basicJwtPayload, iat };
        const jws = await sign(payload, hs256Key, { alg: "HS256" });
        await expect(
          jose.jwtVerify(jws, hs256Key, { maxTokenAge: 120 }), // Max age 120s
        ).resolves.toBeDefined();
      });

      it("should validate maxTokenAge (failure - token too old)", async () => {
        const iat = Math.floor(Date.now() / 1000) - 300; // Issued 300s ago
        const payload = { ...basicJwtPayload, iat };
        const jws = await sign(payload, hs256Key, { alg: "HS256" });

        await expect(
          jose.jwtVerify(jws, hs256Key, { maxTokenAge: 120 }),
        ).rejects.toThrow(
          '"iat" claim timestamp check failed (too far in the past)',
        );
      });

      it("should validate maxTokenAge (failure - iat in future)", async () => {
        const futureIat = Math.floor(Date.now() / 1000) + 3600;
        const payload = { ...basicJwtPayload, iat: futureIat };
        const jws = await sign(payload, hs256Key, { alg: "HS256" });
        await expect(
          jose.jwtVerify(jws, hs256Key, { maxTokenAge: 120 }),
        ).rejects.toThrow(
          '"iat" claim timestamp check failed (it should be in the past)',
        );
      });

      it("should validate maxTokenAge (failure - iat missing)", async () => {
        const payloadWithoutIat = { ...basicJwtPayload };
        delete payloadWithoutIat.iat;
        const jws = await sign(payloadWithoutIat, hs256Key, { alg: "HS256" });
        await expect(
          verify(jws, hs256Key, { maxTokenAge: 60 }),
        ).rejects.toThrow("Missing required JWT Claims: iat");
      });

      it("should validate maxTokenAge with clockTolerance (success for age)", async () => {
        const iat = Math.floor(Date.now() / 1000) - 65; // Issued 65s ago
        const payload = { ...basicJwtPayload, iat };
        const jws = await sign(payload, hs256Key, { alg: "HS256" });
        await expect(
          verify(jws, hs256Key, { maxTokenAge: 60, clockTolerance: 10 }), // Max age 60s, tolerance 10s
        ).resolves.toBeDefined();
      });

      it("should validate maxTokenAge with clockTolerance (success for future iat within tolerance)", async () => {
        const futureIat = Math.floor(Date.now() / 1000) + 5; // Issued 5s in future
        const payload = { ...basicJwtPayload, iat: futureIat };
        const jws = await sign(payload, hs256Key, { alg: "HS256" });
        await expect(
          verify(jws, hs256Key, { maxTokenAge: 60, clockTolerance: 10 }),
        ).resolves.toBeDefined();
      });

      it("should use currentDate for nbf validation", async () => {
        const nbf = Math.floor(Date.now() / 1000) + 100; // nbf in 100 seconds
        const payload = { ...basicJwtPayload, nbf };
        const jws = await sign(payload, hs256Key, { alg: "HS256" });
        const futureDate = new Date(Date.now() + 120 * 1000); // 120 seconds in future
        await expect(
          verify(jws, hs256Key, { currentDate: futureDate }),
        ).resolves.toBeDefined(); // Should be valid at futureDate

        const pastDate = new Date(Date.now() + 50 * 1000); // 50 seconds in future
        await expect(
          verify(jws, hs256Key, { currentDate: pastDate }),
        ).rejects.toThrow("Token is not yet valid");
      });

      it("should use currentDate for exp validation", async () => {
        const exp = Math.floor(Date.now() / 1000) + 100; // expires in 100 seconds
        const payload = { ...basicJwtPayload, exp };
        const jws = await sign(payload, hs256Key, { alg: "HS256" });
        const pastDate = new Date(Date.now() + 50 * 1000); // 50 seconds in future
        await expect(
          verify(jws, hs256Key, { currentDate: pastDate }),
        ).resolves.toBeDefined(); // Should not be expired at pastDate

        const futureDate = new Date(Date.now() + 120 * 1000); // 120 seconds in future
        await expect(
          verify(jws, hs256Key, { currentDate: futureDate }),
        ).rejects.toThrow("Token has expired");
      });

      it("should use currentDate for maxTokenAge validation", async () => {
        const iat = Math.floor(Date.now() / 1000); // issued now
        const payload = { ...basicJwtPayload, iat };
        const jws = await sign(payload, hs256Key, { alg: "HS256" });

        // Token is 60s old relative to currentDate
        const currentDateForward = new Date(Date.now() + 60 * 1000);
        await expect(
          verify(jws, hs256Key, {
            maxTokenAge: 30,
            currentDate: currentDateForward,
          }),
        ).rejects.toThrow("Token is too old");

        await expect(
          verify(jws, hs256Key, {
            maxTokenAge: 90,
            currentDate: currentDateForward,
          }),
        ).resolves.toBeDefined();
      });

      it("it does have an expired claim but validation is skipped", async () => {
        const jws = await sign({ sub: "abc" }, hs256Key, {
          alg: "HS256",
          expiresIn: 60,
          currentDate: new Date(0), // epoch
        });

        const { payload } = await verify<JWTClaims>(jws, hs256Key, {
          currentDate: new Date(61_000), // 61 seconds after epoch
          validateJWT: false,
        });
        expect(payload.exp).toBe(60);
      });
    });

    it("should throw if algorithm not allowed", async () => {
      const jws = await sign(payloadObj, hs256Key, { alg: "HS256" });

      await expect(
        jose.compactVerify(jws, hs256Key, {
          algorithms: ["ES256", "RS256"],
        }),
      ).rejects.toThrow('"alg" (Algorithm) Header Parameter value not allowed');
    });

    it("should handle critical headers (success)", async () => {
      const jws = await sign(payloadString, hs256Key, {
        alg: "HS256",
        protectedHeader: { crit: ["exp"], exp: 12_345 },
      });
      // We "understand" 'exp' because it's in the options.critical array
      await expect(
        verify(jws, hs256Key, { requiredHeaders: ["exp"] }),
      ).resolves.toBeDefined();
    });

    it("should throw if crit present but no critical options provided", async () => {
      const jws = await sign(payloadString, hs256Key, {
        alg: "HS256",
        protectedHeader: { crit: ["exp"], exp: 12_345 },
      });
      // No critical option passed to verify
      await expect(verify(jws, hs256Key)).rejects.toThrow(
        "Missing critical header parameters: exp",
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
      const invalidHeader = base64UrlEncode("not json");
      await expect(
        verify(`${invalidHeader}.payload.sig`, hs256Key),
      ).rejects.toThrow(/Protected header is not valid Base64URL or JSON/);
    });

    it("should throw for header missing alg", async () => {
      const headerWithoutAlg = base64UrlEncode(JSON.stringify({ typ: "JWT" }));
      await expect(
        verify(`${headerWithoutAlg}.payload.sig`, hs256Key),
      ).rejects.toThrow(
        'Protected header must be an object with an "alg" property',
      );
    });

    it("should throw for invalid signature base64", async () => {
      const jws = await sign(payloadObj, hs256Key, { alg: "HS256" });
      const parts = jws.split(".");
      await expect(
        verify(`${parts[0]}.${parts[1]}.sig?`, hs256Key),
      ).rejects.toThrow("Signature is not valid Base64URL");
    });

    it("should throw for signature mismatch", async () => {
      const jws = await sign(payloadObj, hs256Key, { alg: "HS256" });
      const otherKey = await generateKey("HS256");
      await expect(jose.compactVerify(jws, otherKey)).rejects.toThrow(
        "signature verification failed",
      );

      const otherJoseKey = await jose.importJWK(await exportKey(otherKey));
      await expect(jose.compactVerify(jws, otherJoseKey)).rejects.toThrow(
        "signature verification failed",
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
      const header = base64UrlEncode(JSON.stringify({ alg: "HS256" }));
      const sig = base64UrlEncode(new Uint8Array(32)); // Dummy sig
      await expect(
        verify(`${header}.invalid?payload.${sig}`, hs256Key),
      ).rejects.toThrow("JWS signature verification failed.");
    });
  });
});
