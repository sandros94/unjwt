import * as jose from "jose";
import { describe, it, expect, beforeAll } from "vitest";
import { sign, verify, JWTError, isJWTError } from "../src/core/jws";
import { generateKey, generateJWK, exportKey } from "../src/core/jwk";
import { base64UrlEncode, base64UrlDecode, textEncoder, textDecoder } from "../src/core/utils";
import type { JWTClaims, JWK, JWK_Private, JWKSet } from "../src/core/types";

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
      expect(payloadRaw).toBe(payloadString);
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

      const { protectedHeader: joseHeader } = await jose.compactVerify(jws, key);
      expect(joseHeader.kid).toBe("test-key-1");
      expect(joseHeader.typ).toBe("custom");
    });

    // `alg` must come from the top-level `options.alg`; allowing it inside
    // `protectedHeader` would let it be silently overwritten. The compile-time
    // assertion below fails the typecheck run if the StrictOmit guard regresses.
    it("rejects `alg` inside protectedHeader at the type level", async () => {
      const key = await generateKey("HS256");

      const jwsOptions = {
        alg: "HS256",
        protectedHeader: { alg: "HS512" },
      };

      // @ts-expect-error `alg` is forbidden inside protectedHeader.
      const jws = await sign(payloadObj, key, jwsOptions);

      const header = JSON.parse(base64UrlDecode(jws.split(".")[0]));
      expect(header.alg).toBe("HS256");
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

    it("should set `exp` from `expiresAt` (absolute expiry)", async () => {
      const key = await generateKey("HS256", { toJWK: true });
      const expiresAt = new Date("2030-01-01T00:00:00Z");
      const jws = await sign({ ...payloadObj, iat: undefined, exp: undefined }, key, {
        expiresAt,
      });
      const [, payloadEncoded] = jws.split(".");
      const payload = JSON.parse(base64UrlDecode(payloadEncoded));
      expect(payload.exp).toBe(Math.floor(expiresAt.getTime() / 1000));
      expect(payload.iat).toBeDefined();
    });

    it("should throw when both `expiresIn` and `expiresAt` are set", async () => {
      const key = await generateKey("HS256", { toJWK: true });
      await expect(
        sign({ ...payloadObj, iat: undefined, exp: undefined }, key, {
          expiresIn: 60,
          expiresAt: new Date("2030-01-01T00:00:00Z"),
        }),
      ).rejects.toThrow(/mutually exclusive/i);
    });

    it("should throw when `expiresAt` is an invalid Date", async () => {
      const key = await generateKey("HS256", { toJWK: true });
      await expect(
        sign({ ...payloadObj, iat: undefined, exp: undefined }, key, {
          expiresAt: new Date("not-a-date"),
        }),
      ).rejects.toThrow(/valid Date/i);
    });

    it("should set `nbf` from `notBeforeAt`", async () => {
      const key = await generateKey("HS256", { toJWK: true });
      const notBeforeAt = new Date("2030-01-01T00:00:00Z");
      const jws = await sign({ ...payloadObj, iat: undefined, exp: undefined }, key, {
        expiresIn: "1h",
        notBeforeAt,
      });
      const [, payloadEncoded] = jws.split(".");
      const payload = JSON.parse(base64UrlDecode(payloadEncoded));
      expect(payload.nbf).toBe(Math.floor(notBeforeAt.getTime() / 1000));
      expect(payload.iat).toBeDefined();
      expect(payload.exp).toBeDefined();
    });

    it("should not override existing `nbf` claim", async () => {
      const key = await generateKey("HS256", { toJWK: true });
      const jws = await sign({ sub: "x", nbf: 999, iat: undefined, exp: undefined }, key, {
        expiresIn: "1h",
        notBeforeAt: new Date("2030-01-01T00:00:00Z"),
      });
      const [, payloadEncoded] = jws.split(".");
      const payload = JSON.parse(base64UrlDecode(payloadEncoded));
      expect(payload.nbf).toBe(999);
    });

    it("should throw when `notBeforeAt` is an invalid Date", async () => {
      const key = await generateKey("HS256", { toJWK: true });
      await expect(
        sign({ ...payloadObj, iat: undefined, exp: undefined }, key, {
          expiresIn: "1h",
          notBeforeAt: new Date("not-a-date"),
        }),
      ).rejects.toThrow(/valid Date/i);
    });

    it("roundtrips `nbf` — verify rejects before, accepts after", async () => {
      const key = await generateKey("HS256", { toJWK: true });
      const notBeforeAt = new Date("2030-01-01T00:00:00Z");
      const jws = await sign({ sub: "x", iat: undefined, exp: undefined }, key, {
        currentDate: new Date("2029-12-31T00:00:00Z"),
        expiresIn: "7D",
        notBeforeAt,
      });

      await expect(
        verify(jws, key, { currentDate: new Date("2029-12-31T12:00:00Z") }),
      ).rejects.toThrow(/not yet valid/);

      await expect(
        verify(jws, key, { currentDate: new Date("2030-01-02T00:00:00Z") }),
      ).resolves.toBeDefined();
    });

    it("should set `nbf` from `notBeforeIn` duration", async () => {
      const key = await generateKey("HS256", { toJWK: true });
      const jws = await sign({ sub: "x", iat: undefined, exp: undefined }, key, {
        currentDate: new Date(0),
        expiresIn: "1h",
        notBeforeIn: "5m",
      });
      const [, payloadEncoded] = jws.split(".");
      const payload = JSON.parse(base64UrlDecode(payloadEncoded));
      expect(payload.iat).toBe(0);
      expect(payload.nbf).toBe(300);
    });

    it("should accept `notBeforeIn: 0` as `nbf = iat`", async () => {
      const key = await generateKey("HS256", { toJWK: true });
      const jws = await sign({ sub: "x", iat: undefined, exp: undefined }, key, {
        currentDate: new Date(0),
        expiresIn: "1h",
        notBeforeIn: 0,
      });
      const [, payloadEncoded] = jws.split(".");
      const payload = JSON.parse(base64UrlDecode(payloadEncoded));
      expect(payload.iat).toBe(0);
      expect(payload.nbf).toBe(0);
    });

    it("should throw when both `notBeforeIn` and `notBeforeAt` are set", async () => {
      const key = await generateKey("HS256", { toJWK: true });
      await expect(
        sign({ sub: "x", iat: undefined, exp: undefined }, key, {
          expiresIn: "1h",
          notBeforeIn: 60,
          notBeforeAt: new Date("2030-01-01T00:00:00Z"),
        }),
      ).rejects.toThrow(/mutually exclusive/i);
    });

    it("should throw on negative `notBeforeIn`", async () => {
      const key = await generateKey("HS256", { toJWK: true });
      await expect(
        sign({ sub: "x", iat: undefined, exp: undefined }, key, {
          expiresIn: "1h",
          notBeforeIn: -60,
        }),
      ).rejects.toThrow(/zero or a positive/i);
    });

    it("should include computed `exp` and throw because it is expired", async () => {
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
          expiresIn: 60,
        },
      );
      const [_headerEncoded, payloadEncoded] = jws.split(".");
      const payload = JSON.parse(base64UrlDecode(payloadEncoded));
      expect(payload.exp).toEqual(Math.round(creationDate.getTime() / 1000) + 60);

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

    it("should throw JWTError with ERR_JWT_EXPIRED code and cause for expired `exp`", async () => {
      const key = await generateKey("HS256", { toJWK: true });
      const date = new Date();
      const creationDate = new Date(date.getTime() - 60 * 2 * 1000);
      const jws = await sign({ sub: "test-subject", jti: "test-jti-exp" }, key, {
        currentDate: creationDate,
        expiresIn: 60,
      });
      const [, payloadEncoded] = jws.split(".");
      const { exp, iat } = JSON.parse(base64UrlDecode(payloadEncoded));

      const error = await verify(jws, key, { currentDate: date }).catch((e) => e);

      expect(error).toBeInstanceOf(JWTError);
      expect(isJWTError(error, "ERR_JWT_EXPIRED")).toBe(true);
      if (isJWTError(error, "ERR_JWT_EXPIRED")) {
        expect(error.cause).toStrictEqual({ jti: "test-jti-exp", iat, exp });
      }
    });

    it("should throw JWTError with ERR_JWT_EXPIRED code and cause for exceeded maxTokenAge", async () => {
      const key = await generateKey("HS256", { toJWK: true });
      const date = new Date();
      const creationDate = new Date(date.getTime() - 60 * 2 * 1000);
      // `expiresIn` is required so `computeJwtTimeClaims` populates `iat` — without
      // an `iat` the `maxTokenAge` check below has nothing to compare against.
      const jws = await sign({ sub: "test-subject", jti: "test-jti-age" }, key, {
        currentDate: creationDate,
        expiresIn: 3600,
      });
      const [, payloadEncoded] = jws.split(".");
      const { iat } = JSON.parse(base64UrlDecode(payloadEncoded));

      const error = await verify(jws, key, {
        currentDate: date,
        maxTokenAge: 60,
      }).catch((e) => e);

      expect(error).toBeInstanceOf(JWTError);
      expect(isJWTError(error, "ERR_JWT_EXPIRED")).toBe(true);
      if (isJWTError(error, "ERR_JWT_EXPIRED")) {
        expect(error.cause).toMatchObject({ jti: "test-jti-age", iat });
      }
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

    it("should throw for invalid payload type", async () => {
      const key = await generateKey("HS256");
      await expect(sign(12_345 as any, key, { alg: "HS256" })).rejects.toThrow(TypeError);
    });
  });

  describe("verify", () => {
    let hs256Key: CryptoKey;
    let rs256KeyPair: CryptoKeyPair;
    let es256KeyPair: CryptoKeyPair;
    let ps256KeyPair: CryptoKeyPair;
    let jwkSet: JWKSet;

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
      const { payload, protectedHeader } = await verify<JWTClaims>(jws, hs256Key);
      expect(payload).toEqual(payloadObj);
      expect(protectedHeader.alg).toBe("HS256");
      expect(protectedHeader.typ).toBe("JWT");

      const { payload: josePayload } = await jose.compactVerify(jws, hs256Key);
      expect(JSON.parse(textDecoder.decode(josePayload))).toEqual(payloadObj);
    });

    it("should verify HS256 (Uint8Array payload)", async () => {
      const jws = await sign(payloadBytes, hs256Key, { alg: "HS256" });
      const { payload, protectedHeader } = await verify<Uint8Array<ArrayBuffer>>(jws, hs256Key, {
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
      const { payload, protectedHeader } = await verify<JWTClaims>(jws, rs256KeyPair.publicKey);
      expect(payload).toEqual(payloadObj);
      expect(protectedHeader.alg).toBe("RS256");

      const { payload: josePayload } = await jose.compactVerify(jws, rs256KeyPair.publicKey);
      expect(JSON.parse(textDecoder.decode(josePayload))).toEqual(payloadObj);
    });

    it("should verify ES256", async () => {
      const jws = await sign(payloadObj, es256KeyPair.privateKey, {
        alg: "ES256",
      });
      const { payload, protectedHeader } = await verify<JWTClaims>(jws, es256KeyPair.publicKey);
      expect(payload).toEqual(payloadObj);
      expect(protectedHeader.alg).toBe("ES256");

      const { payload: josePayload } = await jose.compactVerify(jws, es256KeyPair.publicKey);
      expect(JSON.parse(textDecoder.decode(josePayload))).toEqual(payloadObj);
    });

    it("should verify PS256", async () => {
      const jws = await sign(payloadObj, ps256KeyPair.privateKey, {
        alg: "PS256",
      });
      const { payload, protectedHeader } = await verify<JWTClaims>(jws, ps256KeyPair.publicKey);
      expect(payload).toEqual(payloadObj);
      expect(protectedHeader.alg).toBe("PS256");

      const { payload: josePayload } = await jose.compactVerify(jws, ps256KeyPair.publicKey);
      expect(JSON.parse(textDecoder.decode(josePayload))).toEqual(payloadObj);
    });

    // jose (the cross-check library) does not support RFC 7797 `b64: false`, so these
    // tests only assert unjwt's own roundtrip behaviour.
    it("should verify with b64: false", async () => {
      const jws = await sign(payloadString, hs256Key, {
        alg: "HS256",
        protectedHeader: { b64: false },
      });
      const { payload, protectedHeader } = await verify<string>(jws, hs256Key);
      expect(protectedHeader.b64).toBe(false);
      expect(protectedHeader.alg).toBe("HS256");
      expect(typeof payload).toBe("string");
      expect(payload).toBe(payloadString);
    });

    it("should verify with b64: false and forceUint8Array", async () => {
      const jws = await sign(payloadString, hs256Key, {
        alg: "HS256",
        protectedHeader: { b64: false },
      });
      const { payload, protectedHeader } = await verify<Uint8Array<ArrayBuffer>>(jws, hs256Key, {
        forceUint8Array: true,
      });
      expect(protectedHeader.b64).toBe(false);
      expect(payload).toBeInstanceOf(Uint8Array);
      expect(textDecoder.decode(payload)).toBe(payloadString);
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
      const rsPrKey = await exportKey<JWK_Private>(rs256KeyPair.privateKey, {
        kid: "key1",
      });
      const jws = await sign(payloadObj, rsPrKey);

      const { protectedHeader, payload } = await verify(jws, jwkSet);
      expect(protectedHeader.kid).toBe("key1");
      expect(payload).toEqual(payloadObj);

      const { payload: josePayload } = await jose.compactVerify(jws, joseJwkSet);
      expect(JSON.parse(textDecoder.decode(josePayload))).toEqual(payloadObj);
    });

    it("should verify with sync key lookup function", async () => {
      const jws = await sign(payloadObj, hs256Key, {
        alg: "HS256",
        protectedHeader: { kid: "key1" }, // Using "key1" kid for test purposes
      });

      const keyLookup = (header: { kid?: string; alg?: string }) => {
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

      const keyLookup = async (header: { kid?: string; alg?: string }) => {
        await Promise.resolve(); // Ensure async resolution
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
        await Promise.resolve(); // Ensure async resolution
        return jwkSet;
      };

      const { payload } = await verify(jws, keyLookup);
      expect(payload).toEqual(payloadObj);
    });

    it("should verify with JWKSet by trying multiple keys when no kid is present", async () => {
      // Two HMAC keys without kid — sign with key2, set has key1 first so retry is exercised
      const [raw1, raw2] = await Promise.all([generateKey("HS256"), generateKey("HS256")]);
      const [jwk1, jwk2] = await Promise.all([exportKey(raw1), exportKey(raw2)]);
      const jws = await sign(payloadObj, raw2, { alg: "HS256" });
      const set: JWKSet = { keys: [jwk1, jwk2] };
      const { payload } = await verify(jws, set);
      expect(payload).toEqual(payloadObj);
    });

    // The loop's "try next" contract only covers cryptographic signature mismatch
    // (which `joseVerify` returns as `false`). Malformed JWKs must surface instead
    // of being silently skipped to the next candidate.
    it("surfaces malformed JWK errors instead of silently skipping to a valid candidate", async () => {
      const rawValid = await generateKey("HS256");
      const validJwk = await exportKey(rawValid);
      // kty=RSA with alg=HS256 is nonsensical — `subtleMapping` rejects the combination.
      const malformedJwk = { kty: "RSA", alg: "HS256" } as unknown as JWK;
      const jws = await sign(payloadObj, rawValid, { alg: "HS256" });

      const set: JWKSet = { keys: [malformedJwk, validJwk] };
      await expect(verify(jws, set)).rejects.toThrow(/Invalid or unsupported JWK "alg"/);
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

      // RFC 7515 §4.1.11 — registered params the library does not process must not be treated as
      // implicitly understood. `jwk`/`jku`/`x5c`/`x5t`/`x5u` require explicit `recognizedHeaders`.
      it.each(["jwk", "jku", "x5c", "x5t", "x5u"])(
        "rejects '%s' in crit without explicit recognizedHeaders",
        async (param) => {
          const jws = await sign(payloadString, hs256Key, {
            alg: "HS256",
            protectedHeader: { crit: [param], [param]: "irrelevant" },
          });
          await expect(verify(jws, hs256Key)).rejects.toThrow(
            `Missing critical header parameters: ${param}`,
          );
          await expect(
            verify(jws, hs256Key, { recognizedHeaders: [param] }),
          ).resolves.toBeDefined();
        },
      );

      it("should throw if a header listed in 'crit' is not present", async () => {
        const jwsNoKid = await sign(payloadString, hs256Key, {
          alg: "HS256",
          protectedHeader: { crit: ["kid"] },
        });
        await expect(verify(jwsNoKid, hs256Key)).rejects.toThrow(
          "Missing critical header parameters: kid",
        );

        await expect(
          jose.compactVerify(jwsNoKid, hs256Key as any, {
            crit: { kid: true },
          }),
        ).rejects.toThrow('Extension Header Parameter "kid" is missing');
      });

      it("should succeed if 'crit' is present and all params are known, even if options.critical is not set", async () => {
        const jws = await sign(payloadString, hs256Key, {
          alg: "HS256",
          protectedHeader: { crit: ["b64"], b64: false },
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
        await expect(verify(jws, hs256Key, { typ: "JWT" })).resolves.toBeDefined();

        await expect(jose.jwtVerify(jws, hs256Key, { typ: "JWT" })).resolves.toBeDefined();
      });

      it("should validate 'typ' header parameter (failure)", async () => {
        const jws = await sign(basicJwtPayload, hs256Key, {
          alg: "HS256",
          protectedHeader: { typ: "application/custom" },
        });
        await expect(verify(jws, hs256Key, { typ: "JWT" })).rejects.toThrow(
          'Invalid JWS: "typ" (Type) Header Parameter mismatch. Expected "JWT", got "application/custom".',
        );

        await expect(jose.jwtVerify(jws, hs256Key, { typ: "JWT" })).rejects.toThrow(
          'unexpected "typ" JWT header value',
        );
      });

      it("should succeed if options.typ is undefined, regardless of header.typ", async () => {
        const jwsWithTyp = await sign(basicJwtPayload, hs256Key, {
          alg: "HS256",
          protectedHeader: { typ: "JWT" },
        });
        await expect(verify(jwsWithTyp, hs256Key, {})).resolves.toBeDefined();
        await expect(jose.jwtVerify(jwsWithTyp, hs256Key, {})).resolves.toBeDefined();

        const jwsWithoutTyp = await sign(basicJwtPayload, hs256Key, {
          alg: "HS256",
        }); // typ will be JWT by default for object payload
        await expect(verify(jwsWithoutTyp, hs256Key, {})).resolves.toBeDefined();
        await expect(jose.jwtVerify(jwsWithoutTyp, hs256Key, {})).resolves.toBeDefined();
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
        await expect(verify(jws, hs256Key, { issuer: "test-issuer" })).resolves.toBeDefined();

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
        await expect(verify(jws, hs256Key, { issuer: "wrong-issuer" })).rejects.toThrow(
          'Invalid JWT "iss" (Issuer) Claim: Expected wrong-issuer, got test-issuer',
        );

        await expect(jose.jwtVerify(jws, hs256Key, { issuer: "wrong-issuer" })).rejects.toThrow(
          'unexpected "iss" claim value',
        );
      });

      it("should validate issuer (failure - claim missing)", async () => {
        const payloadWithoutIss = { ...basicJwtPayload };
        delete payloadWithoutIss.iss;
        const jws = await sign(payloadWithoutIss, hs256Key, { alg: "HS256" });
        await expect(verify(jws, hs256Key, { issuer: "test-issuer" })).rejects.toThrow(
          "Missing required JWT Claims: iss",
        );

        await expect(jose.jwtVerify(jws, hs256Key, { issuer: "test-issuer" })).rejects.toThrow(
          'missing required "iss" claim',
        );
      });

      it("should validate subject (success)", async () => {
        const jws = await sign(basicJwtPayload, hs256Key, { alg: "HS256" });
        await expect(verify(jws, hs256Key, { subject: "test-subject" })).resolves.toBeDefined();
      });

      it("should validate subject (failure - mismatch)", async () => {
        const jws = await sign(basicJwtPayload, hs256Key, { alg: "HS256" });
        await expect(jose.jwtVerify(jws, hs256Key, { subject: "wrong-subject" })).rejects.toThrow(
          'unexpected "sub" claim value',
        );
      });

      it("should validate subject (failure - claim missing)", async () => {
        const payloadWithoutSub = { ...basicJwtPayload };
        delete payloadWithoutSub.sub;
        const jws = await sign(payloadWithoutSub, hs256Key, { alg: "HS256" });
        await expect(jose.jwtVerify(jws, hs256Key, { subject: "test-subject" })).rejects.toThrow(
          'missing required "sub" claim',
        );
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
        await expect(verify(jws, hs256Key, { audience: "test-audience" })).resolves.toBeDefined();
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
        await expect(verify(jws, hs256Key, { audience: "wrong-audience" })).rejects.toThrow(
          'Invalid JWT "aud" (Audience) Claim: Expected wrong-audience, got test-audience',
        );
      });

      it("should validate audience (failure - claim missing)", async () => {
        const payloadWithoutAud = { ...basicJwtPayload };
        delete payloadWithoutAud.aud;
        const jws = await sign(payloadWithoutAud, hs256Key, { alg: "HS256" });
        await expect(verify(jws, hs256Key, { audience: "test-audience" })).rejects.toThrow(
          "Missing required JWT Claims: aud",
        );
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
          jose.jwtVerify(jws, hs256Key, { maxTokenAge: "2m" }), // Max age 120s
        ).resolves.toBeDefined();
      });

      it("should validate maxTokenAge (failure - token too old)", async () => {
        const iat = Math.floor(Date.now() / 1000) - 300; // Issued 300s ago
        const payload = { ...basicJwtPayload, iat };
        const jws = await sign(payload, hs256Key, { alg: "HS256" });

        await expect(jose.jwtVerify(jws, hs256Key, { maxTokenAge: 120 })).rejects.toThrow(
          '"iat" claim timestamp check failed (too far in the past)',
        );
      });

      it("should validate maxTokenAge (failure - iat in future)", async () => {
        const futureIat = Math.floor(Date.now() / 1000) + 3600;
        const payload = { ...basicJwtPayload, iat: futureIat };
        const jws = await sign(payload, hs256Key, { alg: "HS256" });
        await expect(jose.jwtVerify(jws, hs256Key, { maxTokenAge: 120 })).rejects.toThrow(
          '"iat" claim timestamp check failed (it should be in the past)',
        );
      });

      it("should validate maxTokenAge (failure - iat missing)", async () => {
        const payloadWithoutIat = { ...basicJwtPayload };
        delete payloadWithoutIat.iat;
        const jws = await sign(payloadWithoutIat, hs256Key, { alg: "HS256" });
        await expect(verify(jws, hs256Key, { maxTokenAge: 60 })).rejects.toThrow(
          "Missing required JWT Claims: iat",
        );
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
        await expect(verify(jws, hs256Key, { currentDate: futureDate })).resolves.toBeDefined(); // Should be valid at futureDate

        const pastDate = new Date(Date.now() + 50 * 1000); // 50 seconds in future
        await expect(verify(jws, hs256Key, { currentDate: pastDate })).rejects.toThrow(
          "Token is not yet valid",
        );
      });

      it("should use currentDate for exp validation", async () => {
        const exp = Math.floor(Date.now() / 1000) + 100; // expires in 100 seconds
        const payload = { ...basicJwtPayload, exp };
        const jws = await sign(payload, hs256Key, { alg: "HS256" });
        const pastDate = new Date(Date.now() + 50 * 1000); // 50 seconds in future
        await expect(verify(jws, hs256Key, { currentDate: pastDate })).resolves.toBeDefined(); // Should not be expired at pastDate

        const futureDate = new Date(Date.now() + 120 * 1000); // 120 seconds in future
        await expect(verify(jws, hs256Key, { currentDate: futureDate })).rejects.toThrow(
          "Token has expired",
        );
      });

      it("should use currentDate for maxTokenAge validation", async () => {
        const iat = Math.floor(Date.now() / 1000);
        const payload = { ...basicJwtPayload, iat };
        const jws = await sign(payload, hs256Key, { alg: "HS256" });

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
          currentDate: new Date(0),
        });

        const { payload } = await verify<JWTClaims>(jws, hs256Key, {
          currentDate: new Date(61_000),
          validateClaims: false,
        });
        expect(payload.exp).toBe(60);
      });

      it("rejects expired token even when signer omitted the typ header", async () => {
        // Hand-crafted JWS without `typ` — exercises the path where claim validation
        // runs on any JSON-object payload, not only when `typ` is JWT.
        const header = { alg: "HS256" };
        const payload = {
          sub: "abc",
          exp: Math.floor(Date.now() / 1000) - 60,
        };
        const headerEncoded = base64UrlEncode(JSON.stringify(header));
        const payloadEncoded = base64UrlEncode(JSON.stringify(payload));
        const signingInput = textEncoder.encode(`${headerEncoded}.${payloadEncoded}`);
        const rawKey = await crypto.subtle.exportKey("raw", hs256Key as CryptoKey);
        const macKey = await crypto.subtle.importKey(
          "raw",
          rawKey,
          { name: "HMAC", hash: "SHA-256" },
          false,
          ["sign"],
        );
        const signatureBytes = new Uint8Array(
          await crypto.subtle.sign("HMAC", macKey, signingInput),
        );
        const jws = `${headerEncoded}.${payloadEncoded}.${base64UrlEncode(signatureBytes)}`;

        await expect(verify(jws, hs256Key)).rejects.toThrow("Token has expired");
      });

      it("rejects non-numeric exp as ERR_JWT_CLAIM_INVALID", async () => {
        const jws = await sign({ sub: "abc", exp: "never" }, hs256Key, { alg: "HS256" });

        try {
          await verify(jws, hs256Key);
          expect.fail("verify should have thrown");
        } catch (err) {
          expect(isJWTError(err)).toBe(true);
          if (isJWTError(err)) expect(err.code).toBe("ERR_JWT_CLAIM_INVALID");
          expect((err as Error).message).toContain(
            '"exp" (Expiration Time) Claim must be a number',
          );
        }
      });
    });

    it("should throw if algorithm not allowed", async () => {
      const jws = await sign(payloadObj, hs256Key, { alg: "HS256" });

      await expect(verify(jws, hs256Key, { algorithms: ["ES256", "RS256"] })).rejects.toThrow(
        "Algorithm not allowed: HS256",
      );

      await expect(
        jose.compactVerify(jws, hs256Key, {
          algorithms: ["ES256", "RS256"],
        }),
      ).rejects.toThrow('"alg" (Algorithm) Header Parameter value not allowed');
    });

    // Without an explicit `options.algorithms`, verify falls back to inference from
    // the key shape — a forged `alg` that's outside the inferred set must be rejected.
    it("infers the algorithm allowlist from a CryptoKey when options.algorithms is absent", async () => {
      const jws = await sign(payloadObj, hs256Key, { alg: "HS256" });
      await expect(verify(jws, hs256Key)).resolves.toBeDefined();
      const [, payloadPart, sigPart] = jws.split(".");
      const forgedHeader = base64UrlEncode(JSON.stringify({ alg: "HS512", typ: "JWT" }));
      await expect(verify(`${forgedHeader}.${payloadPart}.${sigPart}`, hs256Key)).rejects.toThrow(
        "Algorithm not allowed: HS512",
      );
    });

    // Raw `Uint8Array` keys carry no metadata, so inference cannot pick an alg and
    // verify must demand an explicit `options.algorithms`.
    it("requires explicit options.algorithms when the key shape is ambiguous", async () => {
      const rawKey = await crypto.subtle.exportKey("raw", hs256Key as CryptoKey);
      const jws = await sign(payloadObj, new Uint8Array(rawKey), { alg: "HS256" });
      await expect(verify(jws, new Uint8Array(rawKey))).rejects.toThrow(
        /Cannot infer allowed algorithms/,
      );
      await expect(
        verify(jws, new Uint8Array(rawKey), { algorithms: ["HS256"] }),
      ).resolves.toBeDefined();
    });

    it("should handle critical headers (success)", async () => {
      const jws = await sign(payloadString, hs256Key, {
        alg: "HS256",
        protectedHeader: { crit: ["exp"], exp: 12_345 },
      });
      await expect(verify(jws, hs256Key, { recognizedHeaders: ["exp"] })).resolves.toBeDefined();
    });

    it("should throw if crit present but no critical options provided", async () => {
      const jws = await sign(payloadString, hs256Key, {
        alg: "HS256",
        protectedHeader: { crit: ["exp"], exp: 12_345 },
      });
      await expect(verify(jws, hs256Key)).rejects.toThrow(
        "Missing critical header parameters: exp",
      );
    });

    it("should throw for invalid JWS format", async () => {
      await expect(verify("a.b", hs256Key)).rejects.toThrow(
        "Invalid JWS: Must contain three parts",
      );
    });

    // `verify` pins `expect: "public"` on import, so a private JWK passed in place
    // of the public key is rejected rather than silently accepted.
    it("rejects a private JWK passed to verify()", async () => {
      const { privateKey, publicKey } = await generateJWK("ES256");
      const jws = await sign(payloadObj, privateKey);
      await expect(verify(jws, publicKey)).resolves.toBeDefined();
      await expect(verify(jws, privateKey)).rejects.toThrow(
        expect.objectContaining({ name: "JWTError", code: "ERR_JWK_INVALID" }),
      );
    });

    it("rejects a public JWK passed to sign()", async () => {
      const { publicKey } = await generateJWK("ES256");
      // `sign`'s type union excludes `JWK_Public`; cast past it to exercise the
      // runtime guard that callers using `as any` would otherwise bypass.
      await expect(sign(payloadObj, publicKey as any)).rejects.toThrow(
        expect.objectContaining({ name: "JWTError", code: "ERR_JWK_INVALID" }),
      );
    });

    it("should throw for header missing alg", async () => {
      const headerWithoutAlg = base64UrlEncode(JSON.stringify({ typ: "JWT" }));
      await expect(verify(`${headerWithoutAlg}.payload.sig`, hs256Key)).rejects.toThrow(
        'Protected header must be an object with an "alg" property',
      );
    });

    it("should throw for invalid signature base64", async () => {
      const jws = await sign(payloadObj, hs256Key, { alg: "HS256" });
      const parts = jws.split(".");
      await expect(verify(`${parts[0]}.${parts[1]}.sig?`, hs256Key)).rejects.toThrow();
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
      const keyLookup = (_header: { kid?: string; alg?: string }) => {
        throw new Error("Key lookup failed");
      };
      await expect(verify(jws, keyLookup)).rejects.toThrow("Key lookup failed");
    });

    it("should throw if payload decoding fails (e.g., invalid base64)", async () => {
      const header = base64UrlEncode(JSON.stringify({ alg: "HS256" }));
      const sig = base64UrlEncode(new Uint8Array(32)); // Dummy sig
      await expect(verify(`${header}.invalid?payload.${sig}`, hs256Key)).rejects.toThrow(
        "JWS signature verification failed.",
      );
    });
  });

  describe("JWTError error codes", () => {
    let hs256Key: CryptoKey;
    beforeAll(async () => {
      hs256Key = await generateKey("HS256");
    });

    it("ERR_JWS_INVALID — malformed compact serialization", async () => {
      const error = await verify("only.two", hs256Key).catch((e) => e);
      expect(error).toBeInstanceOf(JWTError);
      expect(isJWTError(error, "ERR_JWS_INVALID")).toBe(true);
    });

    it("ERR_JWS_ALG_NOT_ALLOWED — algorithm rejected by policy", async () => {
      const jws = await sign(payloadObj, hs256Key, { alg: "HS256" });
      const error = await verify(jws, hs256Key, { algorithms: ["RS256"] }).catch((e) => e);
      expect(error).toBeInstanceOf(JWTError);
      expect(isJWTError(error, "ERR_JWS_ALG_NOT_ALLOWED")).toBe(true);
    });

    it("ERR_JWS_SIGNATURE_INVALID — tampered payload", async () => {
      const jws = await sign(payloadObj, hs256Key, { alg: "HS256" });
      const otherKey = await generateKey("HS256");
      const error = await verify(jws, otherKey).catch((e) => e);
      expect(error).toBeInstanceOf(JWTError);
      expect(isJWTError(error, "ERR_JWS_SIGNATURE_INVALID")).toBe(true);
    });

    it("ERR_JWK_INVALID — Uint8Array key too short for algorithm", async () => {
      const error = await sign(payloadObj, textEncoder.encode("short"), { alg: "HS256" }).catch(
        (e) => e,
      );
      expect(error).toBeInstanceOf(JWTError);
      expect(isJWTError(error, "ERR_JWK_INVALID")).toBe(true);
    });

    it("ERR_JWK_KEY_NOT_FOUND — no matching key in JWK Set", async () => {
      const key = await generateKey("HS256", { toJWK: true });
      const jws = await sign(payloadObj, { ...key, kid: "key-1" });
      const jwkSet = { keys: [{ ...key, kid: "other-key" }] };
      const error = await verify(jws, jwkSet).catch((e) => e);
      expect(error).toBeInstanceOf(JWTError);
      expect(isJWTError(error, "ERR_JWK_KEY_NOT_FOUND")).toBe(true);
    });

    it("ERR_JWT_NBF — token not yet valid", async () => {
      const nbf = Math.round(Date.now() / 1000) + 3600;
      const jws = await sign({ nbf }, hs256Key, { alg: "HS256" });
      const error = await verify(jws, hs256Key).catch((e) => e);
      expect(error).toBeInstanceOf(JWTError);
      expect(isJWTError(error, "ERR_JWT_NBF")).toBe(true);
    });

    it("ERR_JWT_CLAIM_MISSING — required claim absent", async () => {
      const jws = await sign({ sub: "test" }, hs256Key, { alg: "HS256" });
      const error = await verify(jws, hs256Key, { requiredClaims: ["jti"] }).catch((e) => e);
      expect(error).toBeInstanceOf(JWTError);
      expect(isJWTError(error, "ERR_JWT_CLAIM_MISSING")).toBe(true);
    });

    it("ERR_JWT_CLAIM_INVALID — issuer mismatch", async () => {
      const jws = await sign({ iss: "https://a.example" }, hs256Key, { alg: "HS256" });
      const error = await verify(jws, hs256Key, { issuer: "https://b.example" }).catch((e) => e);
      expect(error).toBeInstanceOf(JWTError);
      expect(isJWTError(error, "ERR_JWT_CLAIM_INVALID")).toBe(true);
    });

    it("ERR_JWS_ALG_MISSING — sign without inferable alg", async () => {
      // Raw Uint8Array carries no `alg`; the second positional overload requires a TS `alg`
      // option, so we deliberately cast to bypass and exercise the runtime guard.
      const key = textEncoder.encode("raw-hmac-key-bytes");
      const error = await (sign as (p: unknown, k: unknown) => Promise<string>)(
        "payload",
        key,
      ).catch((e) => e);
      expect(error).toBeInstanceOf(JWTError);
      expect(isJWTError(error, "ERR_JWS_ALG_MISSING")).toBe(true);
    });
  });
});
