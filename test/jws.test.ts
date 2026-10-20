import * as jose from "jose";
import { describe, it, expect, expectTypeOf, beforeAll } from "vitest";
import { textEncoder, textDecoder } from "unsecure";
import { base64UrlStringify, base64UrlParse } from "../src/core/utils/base64.ts";

import { sign, verify, JWTError, isJWTError, isUnsecureError } from "../src/core/jws.ts";
import type {
  JOSEPayloadMode,
  JOSEPayloadTypeMap,
  JWSVerifyOptions,
  JWSVerifyResult,
  PayloadOf,
} from "../src/core/jws.ts";
import { generateKey, generateJWK, exportKey } from "../src/core/jwk.ts";
import type {
  JWTClaims,
  JWK,
  JWK_oct,
  JWK_Pair,
  JWK_RSA_Private,
  JWKSet,
  JWSVerifyJWK,
} from "../src/core/types/index.ts";

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
      const jwk = {
        key_ops: ["sign", "verify"],
        ext: true,
        kty: "oct",
        k: "OZ3BsJChEniZwQhiyZdML26Ovchsjqal9sAQR7DsBfc4xBFlcxqYzlOO77MNd0CnPKdznatgsELJjW02BqaqVw",
        alg: "HS256",
      } as const satisfies JWK;

      const jws = await sign(t, jwk);
      const { payload } = await verify(jws, jwk, { payload: "string" });
      expect(payload).toBe(t);

      const { payload: josePayload } = await jose.compactVerify(jws, jwk);
      expect(textDecoder.decode(josePayload)).toBe(t);
    });

    it("should sign with HS256 (Object payload)", async () => {
      const key = await generateKey("HS256");
      const jws = await sign(payloadObj, key, { alg: "HS256" });
      expect(jws.split(".").length).toBe(3);
      const [headerEncoded] = jws.split(".");
      const header = JSON.parse(base64UrlParse(headerEncoded));
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
      const header = JSON.parse(base64UrlParse(headerEncoded));
      expect(header.alg).toBe("HS256");
      expect(header.typ).toBeUndefined(); // No default typ for bytes
      expect(base64UrlParse(payloadEncoded, { returnAs: "uint8array" })).toEqual(payloadBytes);

      const { payload: josePayload } = await jose.compactVerify(jws, key);
      expect(josePayload).toEqual(payloadBytes);
    });

    it("should sign with HS256 (String payload)", async () => {
      const key = await generateKey("HS256");
      const jws = await sign(payloadString, key, { alg: "HS256" });
      expect(jws.split(".").length).toBe(3);
      const [headerEncoded, payloadEncoded] = jws.split(".");
      const header = JSON.parse(base64UrlParse(headerEncoded));
      expect(header.alg).toBe("HS256");
      expect(header.typ).toBeUndefined(); // No default typ for string
      expect(base64UrlParse(payloadEncoded, { returnAs: "string" })).toEqual(payloadString);

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
      const header = JSON.parse(base64UrlParse(headerEncoded));
      expect(header.alg).toBe("RS256");

      const { payload: josePayload } = await jose.compactVerify(jws, publicKey);
      expect(JSON.parse(textDecoder.decode(josePayload))).toEqual(payloadObj);
    });

    it("should sign with ES256", async () => {
      const { privateKey, publicKey } = await generateKey("ES256");
      const jws = await sign(payloadObj, privateKey, { alg: "ES256" });
      expect(jws.split(".").length).toBe(3);
      const [headerEncoded] = jws.split(".");
      const header = JSON.parse(base64UrlParse(headerEncoded));
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
      const header = JSON.parse(base64UrlParse(headerEncoded));
      expect(header.alg).toBe("PS256");

      const { payload: josePayload } = await jose.compactVerify(jws, publicKey);
      expect(JSON.parse(textDecoder.decode(josePayload))).toEqual(payloadObj);
    });

    it("treats EdDSA and Ed25519 as one signature over an Ed25519 key", async () => {
      const fully = await generateJWK("Ed25519");
      const rfc8037 = await generateJWK("EdDSA");

      const viaEdDSA = await sign(payloadObj, fully.privateKey, { alg: "EdDSA" });
      expect(JSON.parse(base64UrlParse(viaEdDSA.split(".")[0])).alg).toBe("EdDSA");
      await expect(verify(viaEdDSA, fully.publicKey)).resolves.toMatchObject({
        payload: payloadObj,
      });
      await expect(
        verify(viaEdDSA, fully.publicKey, { algorithms: ["EdDSA"] }),
      ).resolves.toMatchObject({ payload: payloadObj });

      const viaEd25519 = await sign(payloadObj, rfc8037.privateKey, { alg: "Ed25519" });
      expect(JSON.parse(base64UrlParse(viaEd25519.split(".")[0])).alg).toBe("Ed25519");
      await expect(verify(viaEd25519, rfc8037.publicKey)).resolves.toMatchObject({
        payload: payloadObj,
      });

      await expect(
        verify(viaEdDSA, fully.publicKey, { algorithms: ["Ed25519"] }),
      ).rejects.toSatisfy((e) => isJWTError(e, "ERR_JWS_ALG_NOT_ALLOWED"));
    });

    it("should sign with Ed25519", async () => {
      const { privateKey, publicKey } = await generateKey("Ed25519");
      const jws = await sign(payloadObj, privateKey, { alg: "Ed25519" });
      expect(jws.split(".").length).toBe(3);
      const [headerEncoded] = jws.split(".");
      const header = JSON.parse(base64UrlParse(headerEncoded));
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
      const header = JSON.parse(base64UrlParse(headerEncoded));
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
      const header = JSON.parse(base64UrlParse(headerEncoded));
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

      const header = JSON.parse(base64UrlParse(jws.split(".")[0]));
      expect(header.alg).toBe("HS256");
    });

    it("should include computed `exp`", async () => {
      const key = await generateKey("HS256", { toJWK: true });
      const jws = await sign({ ...payloadObj, iat: undefined }, key, {
        expiresIn: "1m", // 1 minute expiration
      });
      const [_headerEncoded, payloadEncoded] = jws.split(".");
      const payload = JSON.parse(base64UrlParse(payloadEncoded));
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
      const payload = JSON.parse(base64UrlParse(payloadEncoded));
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
      const payload = JSON.parse(base64UrlParse(payloadEncoded));
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
      const payload = JSON.parse(base64UrlParse(payloadEncoded));
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
      const payload = JSON.parse(base64UrlParse(payloadEncoded));
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
      const payload = JSON.parse(base64UrlParse(payloadEncoded));
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
      const payload = JSON.parse(base64UrlParse(payloadEncoded));
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
      const { exp, iat } = JSON.parse(base64UrlParse(payloadEncoded));

      const error = await verify(jws, key, { currentDate: date }).catch((e) => e);

      expect(error).toBeInstanceOf(JWTError);
      expect(isJWTError(error, "ERR_JWT_EXPIRED")).toBe(true);
      expect((error as JWTError).cause).toStrictEqual({ jti: "test-jti-exp", iat, exp });
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
      const { iat } = JSON.parse(base64UrlParse(payloadEncoded));

      const error = await verify(jws, key, {
        currentDate: date,
        maxTokenAge: 60,
      }).catch((e) => e);

      expect(error).toBeInstanceOf(JWTError);
      expect(isJWTError(error, "ERR_JWT_EXPIRED")).toBe(true);
      expect((error as JWTError).cause).toMatchObject({ jti: "test-jti-age", iat });
    });

    it("should not include computed `exp`", async () => {
      const key = await generateKey("HS256", { toJWK: true });
      const jws = await sign(payloadString, key, {
        expiresIn: 60, // 1 minute expiration
      });
      const [headerEncoded, payload] = jws.split(".");
      const header = JSON.parse(base64UrlParse(headerEncoded));
      expect(header.alg).toBe("HS256");
      expect(base64UrlParse(payload)).toEqual(payloadString);

      const { payload: josePayload } = await jose.compactVerify(jws, key);
      expect(textDecoder.decode(josePayload)).toEqual(payloadString);
    });

    it("should throw if alg is missing", async () => {
      const key = await generateKey("HS256");
      await expect(sign(payloadObj, key, {} as never)).rejects.toThrow(
        'JWS "alg" (Algorithm) must be provided',
      );
    });

    it("should throw ERR_INVALID_OPTION for invalid payload type", async () => {
      const key = await generateKey("HS256");
      await expect(sign(12_345 as never, key, { alg: "HS256" })).rejects.toThrow(
        expect.objectContaining({ name: "JWTError", code: "ERR_INVALID_OPTION" }),
      );
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
      const { payload, protectedHeader } = await verify(jws, hs256Key);
      expect(payload).toEqual(payloadObj);
      expect(protectedHeader.alg).toBe("HS256");
      expect(protectedHeader.typ).toBe("JWT");

      const { payload: josePayload } = await jose.compactVerify(jws, hs256Key);
      expect(JSON.parse(textDecoder.decode(josePayload))).toEqual(payloadObj);
    });

    it("should verify HS256 (Uint8Array payload)", async () => {
      const jws = await sign(payloadBytes, hs256Key, { alg: "HS256" });
      const { payload, protectedHeader } = await verify(jws, hs256Key, { payload: "bytes" });
      expect(payload).toBeInstanceOf(Uint8Array);
      expect(payload).toEqual(payloadBytes);
      expect(protectedHeader.alg).toBe("HS256");
      expect(protectedHeader.typ).toBeUndefined();

      const { payload: josePayload } = await jose.compactVerify(jws, hs256Key);
      expect(josePayload).toEqual(payloadBytes);
    });

    it("should verify HS256 (String payload)", async () => {
      const jws = await sign(payloadString, hs256Key, { alg: "HS256" });
      const { payload, protectedHeader } = await verify(jws, hs256Key, { payload: "string" });
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
      const { payload, protectedHeader } = await verify(jws, rs256KeyPair.publicKey);
      expect(payload).toEqual(payloadObj);
      expect(protectedHeader.alg).toBe("RS256");

      const { payload: josePayload } = await jose.compactVerify(jws, rs256KeyPair.publicKey);
      expect(JSON.parse(textDecoder.decode(josePayload))).toEqual(payloadObj);
    });

    it("should verify ES256", async () => {
      const jws = await sign(payloadObj, es256KeyPair.privateKey, {
        alg: "ES256",
      });
      const { payload, protectedHeader } = await verify(jws, es256KeyPair.publicKey);
      expect(payload).toEqual(payloadObj);
      expect(protectedHeader.alg).toBe("ES256");

      const { payload: josePayload } = await jose.compactVerify(jws, es256KeyPair.publicKey);
      expect(JSON.parse(textDecoder.decode(josePayload))).toEqual(payloadObj);
    });

    it("should verify PS256", async () => {
      const jws = await sign(payloadObj, ps256KeyPair.privateKey, {
        alg: "PS256",
      });
      const { payload, protectedHeader } = await verify(jws, ps256KeyPair.publicKey);
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
      const { payload, protectedHeader } = await verify(jws, hs256Key, { payload: "string" });
      expect(protectedHeader.b64).toBe(false);
      expect(protectedHeader.alg).toBe("HS256");
      expect(typeof payload).toBe("string");
      expect(payload).toBe(payloadString);
    });

    it('should verify with b64: false and payload: "bytes"', async () => {
      const jws = await sign(payloadString, hs256Key, {
        alg: "HS256",
        protectedHeader: { b64: false },
      });
      const { payload, protectedHeader } = await verify(jws, hs256Key, { payload: "bytes" });
      expect(protectedHeader.b64).toBe(false);
      expect(payload).toBeInstanceOf(Uint8Array);
      expect(textDecoder.decode(payload)).toBe(payloadString);
    });

    it("should verify with keyset", async () => {
      const jws = await sign(payloadObj, hs256Key, {
        alg: "HS256",
        protectedHeader: { kid: "key2" },
      });

      const { payload } = await verify(jws, jwkSet, { allowSymmetricJWKSet: true });
      expect(payload).toEqual(payloadObj);
    });

    it("should verify with JWK known in the keyset", async () => {
      const rsPrKey = await exportKey<JWK_RSA_Private<"RS256">>(rs256KeyPair.privateKey, {
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

      const { payload } = await verify(jws, keyLookup, { allowSymmetricJWKSet: true });
      expect(payload).toEqual(payloadObj);
    });

    it("should verify with JWKSet by trying multiple keys when no kid is present", async () => {
      // Two HMAC keys without kid — sign with key2, set has key1 first so retry is exercised
      const [raw1, raw2] = await Promise.all([generateKey("HS256"), generateKey("HS256")]);
      const [jwk1, jwk2] = await Promise.all([exportKey(raw1), exportKey(raw2)]);
      const jws = await sign(payloadObj, raw2, { alg: "HS256" });
      const set: JWKSet = { keys: [jwk1, jwk2] };
      const { payload } = await verify(jws, set, { allowSymmetricJWKSet: true });
      expect(payload).toEqual(payloadObj);
    });

    describe("JWK Set candidate policy", () => {
      it("ignores an injected oct key unless the caller admits symmetric material", async () => {
        const { publicKey, privateKey } = await generateJWK("RS256", { modulusLength: 2048 });
        const attackerSecret = await generateJWK("HS256");
        const genuine = await sign(payloadObj, privateKey);
        const forgery = await sign({ ...payloadObj, sub: "admin" }, attackerSecret);

        const poisoned: JWKSet = { keys: [publicKey, attackerSecret] };

        const error = await verify(forgery, poisoned).catch((e) => e);
        expect(isJWTError(error, "ERR_JWS_ALG_NOT_ALLOWED")).toBe(true);

        // The genuine, asymmetric token is unaffected.
        await expect(verify(genuine, poisoned)).resolves.toBeDefined();

        // The set's owner can opt back in for an HMAC rotation set they control.
        const { payload } = await verify(forgery, poisoned, {
          allowSymmetricJWKSet: true,
        });
        expect(payload.sub).toBe("admin");
      });

      it('skips a "use"/"key_ops" mismatched key ordered before the signing key', async () => {
        const { publicKey, privateKey } = await generateJWK("RS256", { modulusLength: 2048 });
        const jws = await sign(payloadObj, privateKey);

        const useMismatch: JWKSet = { keys: [{ ...publicKey, use: "enc" }, publicKey] };
        await expect(verify(jws, useMismatch)).resolves.toBeDefined();

        const opsMismatch: JWKSet = {
          keys: [{ ...publicKey, key_ops: ["wrapKey"] }, publicKey],
        };
        await expect(verify(jws, opsMismatch)).resolves.toBeDefined();
      });

      it("skips non-JWK entries and unusable candidates instead of aborting", async () => {
        const { publicKey, privateKey } = await generateJWK("RS256", { modulusLength: 2048 });
        const jws = await sign(payloadObj, privateKey);
        const kid = publicKey.kid;

        const set = {
          keys: [
            null,
            "x",
            1,
            [],
            {},
            { kty: "RSA", alg: "RS256", kid, n: "!!", e: "AQAB" },
            publicKey,
          ],
        } as unknown as JWKSet;
        const { payload } = await verify(jws, set);
        expect(payload).toEqual(payloadObj);
      });

      it("does not let an alg-less key poison inference for the whole set", async () => {
        const { publicKey, privateKey } = await generateJWK("RS256", { modulusLength: 2048 });
        const jws = await sign(payloadObj, privateKey);
        const { alg: _alg, ...algLess } = publicKey as JWK & { alg?: string };

        const set: JWKSet = { keys: [algLess, publicKey] };
        const { payload } = await verify(jws, set);
        expect(payload).toEqual(payloadObj);
      });

      it("reports every tried candidate as the cause when none verifies", async () => {
        const [a, b] = await Promise.all([
          generateJWK("RS256", { modulusLength: 2048 }),
          generateJWK("RS256", { modulusLength: 2048 }),
        ]);
        const jws = await sign(payloadObj, { ...a.privateKey, kid: undefined });

        const set = {
          keys: [
            { kty: "RSA", alg: "RS256", n: "!!", e: "AQAB" },
            { ...b.publicKey, kid: undefined },
          ],
        } as unknown as JWKSet;
        const error = await verify(jws, set).catch((e) => e);
        expect(isJWTError(error, "ERR_JWS_SIGNATURE_INVALID")).toBe(true);
        const causes = error.cause as JWTError[];
        expect(Array.isArray(causes)).toBe(true);
        expect(causes).toHaveLength(2);
        expect(causes[0].code).toBe("ERR_JWK_INVALID");
        expect(causes[1].code).toBe("ERR_JWS_SIGNATURE_INVALID");
      });
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
        await expect(verify(jws, hs256Key, { payload: "string" })).resolves.toBeDefined();
      });

      // RFC 7515 §4.1.11 — `crit` carries extensions only; a registered parameter such as
      // `alg` must never appear in it, even though the library processes it.
      it("should throw if 'crit' lists a registered header parameter (e.g. alg)", async () => {
        const jws = await signRawHeader({ alg: "HS256", crit: ["alg"] }, payloadString, hs256Key);
        await expect(verify(jws, hs256Key)).rejects.toThrow(
          'Invalid JWS: "crit" must not list registered header parameters.',
        );
      });

      it("should throw if 'crit' lists an unknown header parameter", async () => {
        const jws = await sign(payloadString, hs256Key, {
          alg: "HS256",
          protectedHeader: { crit: ["unknownHeader"], unknownHeader: "value" },
        });
        await expect(verify(jws, hs256Key)).rejects.toThrow(
          "Unprocessed critical header parameters: unknownHeader",
        );

        await expect(jose.compactVerify(jws, hs256Key)).rejects.toThrow(
          'Extension Header Parameter "unknownHeader" is not recognized',
        );
      });

      // RFC 7515 §4.1.11 — registered params are rejected outright, and `recognizedHeaders`
      // cannot opt back into them.
      it.each(["jwk", "jku", "x5c", "x5t", "x5u"])(
        "rejects the registered parameter '%s' in crit",
        async (param) => {
          const jws = await signRawHeader(
            { alg: "HS256", crit: [param], [param]: "irrelevant" },
            payloadString,
            hs256Key,
          );
          const message = 'Invalid JWS: "crit" must not list registered header parameters.';
          await expect(verify(jws, hs256Key)).rejects.toThrow(message);
          await expect(verify(jws, hs256Key, { recognizedHeaders: [param] })).rejects.toThrow(
            message,
          );
        },
      );

      it("should throw if a header listed in 'crit' is not present", async () => {
        const jwsNoExt = await signRawHeader(
          { alg: "HS256", crit: ["app"] },
          payloadString,
          hs256Key,
        );
        await expect(verify(jwsNoExt, hs256Key)).rejects.toThrow(
          'Critical header parameter "app" listed in "crit" but not present in the protected header.',
        );

        await expect(
          jose.compactVerify(jwsNoExt, hs256Key, {
            crit: { app: true },
          }),
        ).rejects.toThrow('Extension Header Parameter "app" is missing');
      });

      it("should throw if 'crit' lists b64 but the header carries no b64 member", async () => {
        const jws = await signRawHeader({ alg: "HS256", crit: ["b64"] }, payloadString, hs256Key);
        const error = await verify(jws, hs256Key, { payload: "string" }).catch((e) => e);
        expect(isJWTError(error, "ERR_JWS_INVALID")).toBe(true);
        expect(error.message).toBe(
          'Critical header parameter "b64" listed in "crit" but not present in the protected header.',
        );
      });

      it("should succeed if 'crit' is present and all params are known, even if options.critical is not set", async () => {
        const jws = await sign(payloadString, hs256Key, {
          alg: "HS256",
          protectedHeader: { crit: ["b64"], b64: false },
        });
        await expect(verify(jws, hs256Key, { payload: "string" })).resolves.toBeDefined();

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

      it("does have an expired claim but validation is skipped", async () => {
        const jws = await sign({ sub: "abc" }, hs256Key, {
          alg: "HS256",
          expiresIn: 60,
          currentDate: new Date(0),
        });

        const { payload } = await verify(jws, hs256Key, {
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
        const headerEncoded = base64UrlStringify(JSON.stringify(header));
        const payloadEncoded = base64UrlStringify(JSON.stringify(payload));
        const signingInput = textEncoder.encode(`${headerEncoded}.${payloadEncoded}`);
        const rawKey = await crypto.subtle.exportKey("raw", hs256Key);
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
        const jws = `${headerEncoded}.${payloadEncoded}.${base64UrlStringify(signatureBytes)}`;

        await expect(verify(jws, hs256Key)).rejects.toThrow("Token has expired");
      });

      it("rejects non-numeric exp as ERR_JWT_CLAIM_INVALID", async () => {
        const jws = await sign({ sub: "abc", exp: "never" }, hs256Key, { alg: "HS256" });

        const err = await verify(jws, hs256Key).catch((e) => e);
        expect(isJWTError(err)).toBe(true);
        expect((err as JWTError).code).toBe("ERR_JWT_CLAIM_INVALID");
        expect((err as Error).message).toContain('"exp" (Expiration Time) Claim must be a number');
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
      const forgedHeader = base64UrlStringify(JSON.stringify({ alg: "HS512", typ: "JWT" }));
      await expect(verify(`${forgedHeader}.${payloadPart}.${sigPart}`, hs256Key)).rejects.toThrow(
        "Algorithm not allowed: HS512",
      );
    });

    // Raw `Uint8Array` keys carry no metadata, so inference cannot pick an alg and
    // verify must demand an explicit `options.algorithms`.
    it("requires explicit options.algorithms when the key shape is ambiguous", async () => {
      const rawKey = await crypto.subtle.exportKey("raw", hs256Key);
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
      await expect(
        verify(jws, hs256Key, { payload: "string", recognizedHeaders: ["exp"] }),
      ).resolves.toBeDefined();
    });

    it("should throw if crit present but no critical options provided", async () => {
      const jws = await sign(payloadString, hs256Key, {
        alg: "HS256",
        protectedHeader: { crit: ["exp"], exp: 12_345 },
      });
      await expect(verify(jws, hs256Key)).rejects.toThrow(
        "Unprocessed critical header parameters: exp",
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
      await expect(sign(payloadObj, publicKey as never)).rejects.toThrow(
        expect.objectContaining({ name: "JWTError", code: "ERR_JWK_INVALID" }),
      );
    });

    it("should throw for header missing alg", async () => {
      const headerWithoutAlg = base64UrlStringify(JSON.stringify({ typ: "JWT" }));
      await expect(verify(`${headerWithoutAlg}.payload.sig`, hs256Key)).rejects.toThrow(
        'Protected header must be an object with an "alg" property',
      );
    });

    it("should throw for invalid signature base64", async () => {
      const jws = await sign(payloadObj, hs256Key, { alg: "HS256" });
      const parts = jws.split(".");
      await expect(verify(`${parts[0]}.${parts[1]}.sig?`, hs256Key)).rejects.toThrow(JWTError);
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
      await expect(verify(jws, failingKeyLookup)).rejects.toThrow("Key lookup failed");
    });

    it("should throw if payload decoding fails (e.g., invalid base64)", async () => {
      const header = base64UrlStringify(JSON.stringify({ alg: "HS256" }));
      const sig = base64UrlStringify(new Uint8Array(32)); // Dummy sig
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
      const error = await verify(jws, jwkSet, { allowSymmetricJWKSet: true }).catch((e) => e);
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

  describe("codec failures wrap into JWTError", () => {
    let hs256Key: CryptoKey;
    beforeAll(async () => {
      hs256Key = await generateKey("HS256");
    });

    const headerEncoded = base64UrlStringify(JSON.stringify({ alg: "HS256" }));

    async function signCompact(payloadEncoded: string): Promise<string> {
      const signature = new Uint8Array(
        await crypto.subtle.sign(
          "HMAC",
          hs256Key,
          textEncoder.encode(`${headerEncoded}.${payloadEncoded}`),
        ),
      );
      return `${headerEncoded}.${payloadEncoded}.${base64UrlStringify(signature)}`;
    }

    it("ERR_JWS_INVALID — malformed protected header, cause is the UnsecureError", async () => {
      const jws = await sign(payloadObj, hs256Key, { alg: "HS256" });
      const [, payloadEncoded, signatureEncoded] = jws.split(".");
      const error = await verify(
        `${headerEncoded}=.${payloadEncoded}.${signatureEncoded}`,
        hs256Key,
      ).catch((e) => e);
      expect(error).toBeInstanceOf(JWTError);
      expect(isJWTError(error, "ERR_JWS_INVALID")).toBe(true);
      expect(error.message).toBe("Invalid JWS: Protected header could not be decoded.");
      expect(isUnsecureError(error.cause, "MALFORMED")).toBe(true);
    });

    it("ERR_JWS_INVALID — malformed signature segment, cause is the UnsecureError", async () => {
      const jws = await sign(payloadObj, hs256Key, { alg: "HS256" });
      const error = await verify(`${jws}=`, hs256Key).catch((e) => e);
      expect(error).toBeInstanceOf(JWTError);
      expect(isJWTError(error, "ERR_JWS_INVALID")).toBe(true);
      expect(error.message).toBe("Invalid JWS: Signature could not be decoded.");
      expect(isUnsecureError(error.cause, "MALFORMED")).toBe(true);
    });

    it("ERR_JWS_INVALID — malformed payload segment, cause is the UnsecureError", async () => {
      const jws = await signCompact(`${base64UrlStringify(JSON.stringify(payloadObj))}=`);
      const error = await verify(jws, hs256Key).catch((e) => e);
      expect(error).toBeInstanceOf(JWTError);
      expect(isJWTError(error, "ERR_JWS_INVALID")).toBe(true);
      expect(error.message).toBe("Invalid JWS: Payload could not be decoded.");
      expect(isUnsecureError(error.cause, "MALFORMED")).toBe(true);
    });
  });
});

describe.concurrent("JWS header, algorithm and RFC 7797 hardening (compact)", () => {
  let hs256Key: CryptoKey;
  let hs256Jwk: JWK_oct<"HS256">;
  let rs256Jwk: JWK_Pair<"RS256">;

  beforeAll(async () => {
    hs256Key = await generateKey("HS256");
    hs256Jwk = await generateJWK("HS256");
    rs256Jwk = await generateJWK("RS256", { modulusLength: 2048 });
  });

  /** Build a compact JWS over an arbitrary (possibly non-object) protected header segment. */
  async function craft(headerSegment: string, payload = "payload"): Promise<string> {
    const payloadEncoded = base64UrlStringify(payload);
    const signature = new Uint8Array(
      await crypto.subtle.sign(
        "HMAC",
        hs256Key,
        textEncoder.encode(`${headerSegment}.${payloadEncoded}`),
      ),
    );
    return `${headerSegment}.${payloadEncoded}.${base64UrlStringify(signature)}`;
  }

  describe("protected header shape", () => {
    it.each(["null", "[]", "123", '"str"'])(
      "rejects a protected header encoding %s",
      async (json) => {
        const jws = await craft(base64UrlStringify(json));
        const error = await verify(jws, hs256Key).catch((e) => e);
        expect(isJWTError(error, "ERR_JWS_INVALID")).toBe(true);
        expect(error.message).toBe("Invalid JWS: Protected header must be a JSON object.");
        expect(error.cause).toBeUndefined();
      },
    );
  });

  describe("algorithm gate", () => {
    it('rejects alg "none" before any key work', async () => {
      const jws = await craft(base64UrlStringify(JSON.stringify({ alg: "none" })));
      const error = await verify(jws, hs256Key).catch((e) => e);
      expect(isJWTError(error, "ERR_JWS_ALG_NOT_ALLOWED")).toBe(true);
      expect(error.message).toBe('"none" is not a valid signing algorithm');
    });

    it("rejects an alg the library does not support", async () => {
      const jws = await craft(base64UrlStringify(JSON.stringify({ alg: "HS1024" })));
      const error = await verify(jws, hs256Key).catch((e) => e);
      expect(isJWTError(error, "ERR_JWS_ALG_NOT_ALLOWED")).toBe(true);
      expect(error.message).toBe('Algorithm not supported: "HS1024"');
    });

    it("quotes and bounds an unsupported alg in the error message", async () => {
      const alg = `HS1024\n"${"x".repeat(10_000)}`;
      const jws = await craft(base64UrlStringify(JSON.stringify({ alg })));
      const error = await verify(jws, hs256Key).catch((e) => e);
      expect(isJWTError(error, "ERR_JWS_ALG_NOT_ALLOWED")).toBe(true);
      expect(error.message).toBe(
        `Algorithm not supported: ${JSON.stringify(`${alg.slice(0, 64)}…`)}`,
      );
      expect(error.message.length).toBeLessThan(120);
    });

    it("still rejects a supported-but-disallowed alg with the allowlist message", async () => {
      const jws = await sign("payload", hs256Key, { alg: "HS256" });
      await expect(verify(jws, hs256Key, { algorithms: ["ES256"] })).rejects.toThrow(
        "Algorithm not allowed: HS256",
      );
    });

    it("refuses an HMAC SHA-1 CryptoKey on sign and verify", async () => {
      const sha1 = await crypto.subtle.generateKey({ name: "HMAC", hash: "SHA-1" }, false, [
        "sign",
        "verify",
      ]);

      const signError = await sign("payload", sha1, { alg: "HS256" }).catch((e) => e);
      expect(isJWTError(signError, "ERR_JWK_INVALID")).toBe(true);

      const hs256 = await craft(base64UrlStringify(JSON.stringify({ alg: "HS256" })));
      const hs256Error = await verify(hs256, sha1).catch((e) => e);
      expect(isJWTError(hs256Error, "ERR_JWS_ALG_NOT_ALLOWED")).toBe(true);
      expect(hs256Error.message).toBe(
        'Cannot infer allowed algorithms from this key; pass "options.algorithms" explicitly.',
      );

      const hs1 = await craft(base64UrlStringify(JSON.stringify({ alg: "HS1" })));
      const hs1Error = await verify(hs1, sha1).catch((e) => e);
      expect(isJWTError(hs1Error, "ERR_JWS_ALG_NOT_ALLOWED")).toBe(true);
      expect(hs1Error.message).toBe('Algorithm not supported: "HS1"');
    });
  });

  describe("key handling errors are JWTErrors", () => {
    it("refuses a key whose declared alg is not the one being verified", async () => {
      const jws = await craft(base64UrlStringify(JSON.stringify({ alg: "ES256" })));

      const octError = await verify(jws, hs256Jwk, { algorithms: ["ES256"] }).catch((e) => e);
      expect(isJWTError(octError, "ERR_JWK_INVALID")).toBe(true);
      expect(octError.message).toBe('JWK "alg" is "HS256" but the operation requires "ES256".');

      const rsaError = await verify(jws, rs256Jwk.publicKey, {
        algorithms: ["ES256"],
      }).catch((e) => e);
      expect(isJWTError(rsaError, "ERR_JWK_INVALID")).toBe(true);
      expect(rsaError.message).toBe('JWK "alg" is "RS256" but the operation requires "ES256".');
    });

    it("wraps a key WebCrypto rejects for the alg into ERR_JWK_INVALID", async () => {
      const jws = await craft(base64UrlStringify(JSON.stringify({ alg: "ES256" })));
      const { publicKey } = await generateJWK("ES384");
      // The curve contradicts the declared alg, which only the import discovers.
      const error = await verify(jws, { ...publicKey, alg: "ES256" } as unknown as JWSVerifyJWK, {
        algorithms: ["ES256"],
      }).catch((e) => e);
      expect(isJWTError(error, "ERR_JWK_INVALID")).toBe(true);
      expect(error.message).toBe('Key is not usable for "ES256".');
      expect(error.cause).toBeDefined();
    });
  });

  describe("RFC 7797 b64", () => {
    it('adds "b64" to crit when signing with b64: false', async () => {
      const jws = await sign("payload", hs256Key, {
        alg: "HS256",
        protectedHeader: { b64: false },
      });
      const header = JSON.parse(base64UrlParse(jws.split(".")[0]));
      expect(header.b64).toBe(false);
      expect(header.crit).toEqual(["b64"]);

      // jose only accepts an unencoded payload when `b64` is integrity protected via `crit`.
      const { payload } = await jose.compactVerify(jws, hs256Key);
      expect(textDecoder.decode(payload)).toBe("payload");
    });

    it('appends "b64" to an existing crit without duplicating it', async () => {
      const jws = await sign("payload", hs256Key, {
        alg: "HS256",
        protectedHeader: { crit: ["app"], app: "web", b64: false },
      });
      const header = JSON.parse(base64UrlParse(jws.split(".")[0]));
      expect(header.crit).toEqual(["app", "b64"]);

      const again = await sign("payload", hs256Key, {
        alg: "HS256",
        protectedHeader: { crit: ["b64"], b64: false },
      });
      expect(JSON.parse(base64UrlParse(again.split(".")[0])).crit).toEqual(["b64"]);
    });

    it('rejects b64: false that is not listed in "crit" on verify', async () => {
      const jws = await craft(
        base64UrlStringify(JSON.stringify({ alg: "HS256", b64: false })),
        "payload",
      );
      // the crafted token base64url-encodes the payload segment, which is irrelevant
      // here: the b64/crit pairing is checked before any payload work.
      const error = await verify(jws, hs256Key).catch((e) => e);
      expect(isJWTError(error, "ERR_JWS_INVALID")).toBe(true);
      expect(error.message).toBe('Invalid JWS: "b64" must be listed in "crit" (RFC 7797 §6).');
    });

    it.each([["false"], [0], [null], [1]])(
      "rejects a non-boolean b64 (%j) on verify",
      async (b64) => {
        const jws = await craft(base64UrlStringify(JSON.stringify({ alg: "HS256", b64 })));
        const error = await verify(jws, hs256Key).catch((e) => e);
        expect(isJWTError(error, "ERR_JWS_INVALID")).toBe(true);
        expect(error.message).toBe('Invalid JWS: "b64" must be a boolean (RFC 7797 §3).');
      },
    );

    it('rejects an unencoded compact payload containing "."', async () => {
      const error = await sign("a.b", hs256Key, {
        alg: "HS256",
        protectedHeader: { b64: false },
      }).catch((e) => e);
      expect(isJWTError(error, "ERR_JWS_INVALID")).toBe(true);
      expect(error.message).toBe(
        'Invalid JWS: unencoded compact payload must not contain "." (RFC 7797 §5.2).',
      );

      const bytesError = await sign(textEncoder.encode("a.b"), hs256Key, {
        alg: "HS256",
        protectedHeader: { b64: false },
      }).catch((e) => e);
      expect(isJWTError(bytesError, "ERR_JWS_INVALID")).toBe(true);
    });

    it("refuses an unencoded payload whose bytes are not UTF-8", async () => {
      const error = await sign(new Uint8Array([0x61, 0xff, 0x62]), hs256Key, {
        alg: "HS256",
        protectedHeader: { b64: false },
      }).catch((e) => e);
      expect(isJWTError(error, "ERR_JWS_INVALID")).toBe(true);
      expect(error.message).toBe("Invalid JWS: Payload is not valid UTF-8.");
    });
  });

  describe('"typ" normalization (RFC 7515 §4.1.9)', () => {
    it("matches a bare media subtype against the application/ form", async () => {
      const jws = await sign({ sub: "u" }, hs256Key, {
        alg: "HS256",
        protectedHeader: { typ: "at+jwt" },
      });
      await expect(verify(jws, hs256Key, { typ: "application/at+jwt" })).resolves.toBeDefined();
      await expect(verify(jws, hs256Key, { typ: "AT+JWT" })).resolves.toBeDefined();
    });

    it("matches an application/-prefixed header against the bare option", async () => {
      const jws = await sign({ sub: "u" }, hs256Key, {
        alg: "HS256",
        protectedHeader: { typ: "application/at+jwt" },
      });
      await expect(verify(jws, hs256Key, { typ: "at+jwt" })).resolves.toBeDefined();
    });

    it("reports a protected header without typ as carrying none", async () => {
      const jws = await sign("payload", hs256Key, { alg: "HS256" });
      expect(JSON.parse(base64UrlParse(jws.split(".")[0])).typ).toBeUndefined();
      const error = await verify(jws, hs256Key, { typ: "at+jwt", payload: "string" }).catch(
        (e) => e,
      );
      expect(isJWTError(error, "ERR_JWS_INVALID")).toBe(true);
      expect(error.message).toBe(
        'Invalid JWS: the protected header carries no "typ"; expected "at+jwt".',
      );
    });

    it("still rejects a genuine typ mismatch", async () => {
      const jws = await sign({ sub: "u" }, hs256Key, {
        alg: "HS256",
        protectedHeader: { typ: "at+jwt" },
      });
      await expect(verify(jws, hs256Key, { typ: "dpop+jwt" })).rejects.toThrow(
        /"typ" \(Type\) Header Parameter mismatch/,
      );
    });
  });
});

describe.concurrent("JWS payload typing (compact)", () => {
  let hs256Key: CryptoKey;

  beforeAll(async () => {
    hs256Key = await generateKey("HS256");
  });

  it("returns the claims object by default", async () => {
    const jws = await sign({ sub: "u" }, hs256Key, { alg: "HS256" });
    const { payload } = await verify(jws, hs256Key);
    expect(payload).toEqual({ sub: "u" });
  });

  it("rejects a non-JSON-object payload under the default mode", async () => {
    const jws = await sign("Payload as string", hs256Key, { alg: "HS256" });
    const error = await verify(jws, hs256Key).catch((e) => e);
    expect(isJWTError(error, "ERR_JWS_INVALID")).toBe(true);
    expect(error.message).toBe("Invalid JWS: Payload is not a JSON object.");
  });

  it.each(["[1,2]", "123", '"str"', "null", "not json at all"])(
    'rejects payload "%s" under payload: "json"',
    async (raw) => {
      const jws = await sign(raw, hs256Key, { alg: "HS256" });
      const error = await verify(jws, hs256Key, { payload: "json" }).catch((e) => e);
      expect(isJWTError(error, "ERR_JWS_INVALID")).toBe(true);
      expect(error.message).toBe("Invalid JWS: Payload is not a JSON object.");
    },
  );

  it('returns a JSON-shaped string verbatim under payload: "string"', async () => {
    const jws = await sign('{"sub":"admin"}', hs256Key, { alg: "HS256" });
    const { payload } = await verify(jws, hs256Key, { payload: "string" });
    expect(payload).toBe('{"sub":"admin"}');
  });

  it('returns bytes under payload: "bytes"', async () => {
    const jws = await sign(textEncoder.encode("raw bytes"), hs256Key, { alg: "HS256" });
    const { payload } = await verify(jws, hs256Key, { payload: "bytes" });
    expect(payload).toBeInstanceOf(Uint8Array);
    expect(textDecoder.decode(payload)).toBe("raw bytes");
  });

  it('forceUint8Array is an alias of payload: "bytes"', async () => {
    const jws = await sign(textEncoder.encode("raw bytes"), hs256Key, { alg: "HS256" });
    const aliased = await verify(jws, hs256Key, { forceUint8Array: true });
    const explicit = await verify(jws, hs256Key, { payload: "bytes" });
    expect(aliased.payload).toEqual(explicit.payload);
  });

  it("rejects forceUint8Array contradicting payload", async () => {
    const jws = await sign({ sub: "u" }, hs256Key, { alg: "HS256" });
    const error = await verify(jws, hs256Key, {
      forceUint8Array: true,
      payload: "json",
    }).catch((e) => e);
    expect(isJWTError(error, "ERR_INVALID_OPTION")).toBe(true);
  });

  it("rejects an unknown payload mode", async () => {
    const jws = await sign({ sub: "u" }, hs256Key, { alg: "HS256" });
    const error = await verify(jws, hs256Key, { payload: "text" as never }).catch((e) => e);
    expect(isJWTError(error, "ERR_INVALID_OPTION")).toBe(true);
  });

  it('rejects validateClaims: true outside payload: "json"', async () => {
    const jws = await sign("plain", hs256Key, { alg: "HS256" });
    const error = await verify(jws, hs256Key, {
      payload: "string",
      validateClaims: true,
    }).catch((e) => e);
    expect(isJWTError(error, "ERR_INVALID_OPTION")).toBe(true);
    expect(error.message).toBe('"validateClaims" requires payload: "json".');
  });

  it("validates claims of a payload that was signed as a string", async () => {
    const expired = JSON.stringify({ sub: "admin", exp: 1_000_000 });
    const jws = await sign(expired, hs256Key, { alg: "HS256" });
    const error = await verify(jws, hs256Key).catch((e) => e);
    expect(isJWTError(error, "ERR_JWT_EXPIRED")).toBe(true);
  });

  it("validates claims under b64: false", async () => {
    const jws = await sign(JSON.stringify({ sub: "u", exp: 1_000_000 }), hs256Key, {
      alg: "HS256",
      protectedHeader: { b64: false },
    });
    const error = await verify(jws, hs256Key).catch((e) => e);
    expect(isJWTError(error, "ERR_JWT_EXPIRED")).toBe(true);
  });

  it('returns the raw segment under b64: false with payload: "string"', async () => {
    const jws = await sign("unencoded", hs256Key, {
      alg: "HS256",
      protectedHeader: { b64: false },
    });
    const { payload } = await verify(jws, hs256Key, { payload: "string" });
    expect(payload).toBe("unencoded");
  });

  it('rejects invalid UTF-8 under payload: "string"', async () => {
    const jws = await sign(new Uint8Array([0xff, 0xfe, 0xfd]), hs256Key, { alg: "HS256" });
    const error = await verify(jws, hs256Key, { payload: "string" }).catch((e) => e);
    expect(isJWTError(error, "ERR_JWS_INVALID")).toBe(true);
  });
});

describe.concurrent("JWS string keys are rejected", () => {
  const message =
    "String keys are not accepted: pass an oct JWK or a Uint8Array secret, or import PEM text with importPEM().";

  it("rejects a string key on sign", async () => {
    const error = await sign({ sub: "u" }, "a-very-long-shared-secret-value" as never, {
      alg: "HS256",
    }).catch((e) => e);
    expect(isJWTError(error, "ERR_JWK_INVALID")).toBe(true);
    expect(error.message).toBe(message);
  });

  it("rejects a string key on verify", async () => {
    const key = await generateKey("HS256");
    const jws = await sign({ sub: "u" }, key, { alg: "HS256" });
    const error = await verify(jws, "a-very-long-shared-secret-value" as never, {
      algorithms: ["HS256"],
    }).catch((e) => e);
    expect(isJWTError(error, "ERR_JWK_INVALID")).toBe(true);
    expect(error.message).toBe(message);
  });

  it("rejects a string returned by a key lookup function", async () => {
    const key = await generateKey("HS256");
    const jws = await sign({ sub: "u" }, key, { alg: "HS256" });
    const error = await verify(jws, () => "secret-from-lookup", {
      algorithms: ["HS256"],
    }).catch((e) => e);
    expect(isJWTError(error, "ERR_JWK_INVALID")).toBe(true);
    expect(error.message).toBe(message);
  });
});

describe.concurrent("JWS producer header gates", () => {
  let key: JWK_oct<"HS256">;

  beforeAll(async () => {
    key = await generateJWK("HS256");
  });

  it('types an object payload as "JWT" without a "cty"', async () => {
    const { protectedHeader } = await verify(await sign({ sub: "u1" }, key), key);
    expect(protectedHeader.typ).toBe("JWT");
    expect(protectedHeader).not.toHaveProperty("cty");
  });

  it('keeps a "cty" set in protectedHeader', async () => {
    const jws = await sign({ sub: "u1" }, key, { protectedHeader: { cty: "application/json" } });
    const { protectedHeader } = await verify(jws, key);
    expect(protectedHeader).toMatchObject({ typ: "JWT", cty: "application/json" });
  });

  it.each([
    ["an empty array", []],
    ["a string", "b64"],
    ["an array with a non-string entry", ["app", 1]],
  ])("refuses a crit that is %s", async (_label, crit) => {
    const error = await sign("payload", key, {
      protectedHeader: { crit, app: "web" } as never,
    }).catch((e) => e);
    expect(isJWTError(error, "ERR_INVALID_OPTION")).toBe(true);
    expect(error.message).toContain('"crit"');
  });

  it.each(["alg", "typ", "cty", "kid", "jwk", "jku", "x5c", "x5t", "x5u"])(
    "refuses the registered parameter %s in crit",
    async (param) => {
      const error = await sign("payload", key, {
        protectedHeader: { crit: [param], [param]: "irrelevant" },
      }).catch((e) => e);
      expect(isJWTError(error, "ERR_INVALID_OPTION")).toBe(true);
      expect(error.message).toContain("registered header parameters");
    },
  );

  it("refuses a crit naming a parameter the header does not carry", async () => {
    const error = await sign("payload", key, {
      protectedHeader: { crit: ["app"] },
    }).catch((e) => e);
    expect(isJWTError(error, "ERR_INVALID_OPTION")).toBe(true);
    expect(error.message).toContain("app");
  });

  it("accepts a crit whose parameters the header carries", async () => {
    const jws = await sign("payload", key, {
      protectedHeader: { crit: ["app"], app: "web" },
    });
    const { payload } = await verify(jws, key, { payload: "string", recognizedHeaders: ["app"] });
    expect(payload).toBe("payload");
  });

  it('accepts "b64" in crit when the header carries b64', async () => {
    const unencoded = await sign("payload", key, {
      protectedHeader: { crit: ["b64"], b64: false },
    });
    expect(unencoded.split(".")[1]).toBe("payload");

    const encoded = await sign("payload", key, {
      protectedHeader: { crit: ["b64"], b64: true },
    });
    expect(JSON.parse(base64UrlParse(encoded.split(".")[0]))).toMatchObject({
      crit: ["b64"],
      b64: true,
    });
    await expect(verify(encoded, key, { payload: "string" })).resolves.toBeDefined();
  });

  it('refuses "b64" in crit when the header carries no b64 member', async () => {
    const error = await sign("payload", key, {
      protectedHeader: { crit: ["b64"] },
    }).catch((e) => e);
    expect(isJWTError(error, "ERR_INVALID_OPTION")).toBe(true);
    expect(error.message).toContain("b64");
  });

  it.each([["false"], [0], [null], [1]])(
    "refuses a non-boolean b64 (%j) in the protected header",
    async (b64) => {
      const error = await sign("payload", key, {
        protectedHeader: { b64 } as never,
      }).catch((e) => e);
      expect(isJWTError(error, "ERR_INVALID_OPTION")).toBe(true);
      expect(error.message).toBe('"b64" must be a boolean (RFC 7797 §3).');
    },
  );

  it.each([
    ["a string", "abc"],
    ["an array", ["typ"]],
    ["null", null],
  ])("refuses a protected header that is %s", async (_label, protectedHeader) => {
    const error = await sign("payload", key, { protectedHeader } as never).catch((e) => e);
    expect(isJWTError(error, "ERR_INVALID_OPTION")).toBe(true);
    expect(error.message).toBe('"options.protectedHeader" must be an object.');
  });

  it("refuses a protected header that cannot be serialized", async () => {
    const circular: Record<string, unknown> = { app: "web" };
    circular.self = circular;

    for (const header of [{ n: 1n } as never, circular as never]) {
      const error = await sign("payload", key, { protectedHeader: header }).catch((e) => e);
      expect(isJWTError(error, "ERR_INVALID_OPTION")).toBe(true);
      expect(error.message).toContain("protected header");
    }
  });

  it.each([[123], [null], [["JWT"]]])("refuses a protected header typ of %j", async (typ) => {
    for (const payload of [{ sub: "u" }, "payload"]) {
      const error = await sign(payload, key, { protectedHeader: { typ } as never }).catch((e) => e);
      expect(isJWTError(error, "ERR_INVALID_OPTION")).toBe(true);
      expect(error.message).toBe('"typ" must be a string.');
    }
  });
});

describe.concurrent("JWS verification option gates", () => {
  let key: JWK_oct<"HS256">;
  let token: string;

  beforeAll(async () => {
    key = await generateJWK("HS256");
    token = await sign({ sub: "u", iss: "i", aud: "a", iat: Math.floor(Date.now() / 1000) }, key, {
      protectedHeader: { typ: "at+jwt" },
    });
  });

  it.each([
    ["an empty audience", { audience: "" }],
    ["an audience list with an empty entry", { audience: ["a", ""] }],
    ["an empty issuer", { issuer: "" }],
    ["an empty subject", { subject: "" }],
    ["an empty typ", { typ: "" }],
    ["maxTokenAge: 0", { maxTokenAge: 0 }],
  ])("refuses %s instead of skipping the check", async (_label, options) => {
    const error = await verify(token, key, options).catch((e) => e);
    expect(isJWTError(error, "ERR_INVALID_OPTION")).toBe(true);
  });

  it("keeps an empty audience list as a check nothing satisfies", async () => {
    const error = await verify(token, key, { audience: [] }).catch((e) => e);
    expect(isJWTError(error, "ERR_JWT_CLAIM_INVALID")).toBe(true);
  });

  it.each([[123], [null], [["at+jwt"]]])("refuses a typ option of %j", async (typ) => {
    const error = await verify(token, key, { typ } as never).catch((e) => e);
    expect(isJWTError(error, "ERR_INVALID_OPTION")).toBe(true);
    expect(error.message).toBe('"typ" must be a non-empty string.');
  });

  it("refuses an algorithms allowlist that is not an array", async () => {
    const error = await verify(token, key, { algorithms: "HS256-disabled" } as never).catch(
      (e) => e,
    );
    expect(isJWTError(error, "ERR_INVALID_OPTION")).toBe(true);
    expect(error.message).toBe('"algorithms" must be an array of strings.');
  });

  it("refuses requiredClaims that is not an array", async () => {
    const error = await verify(token, key, { requiredClaims: "exp" } as never).catch((e) => e);
    expect(isJWTError(error, "ERR_INVALID_OPTION")).toBe(true);
    expect(error.message).toBe('"requiredClaims" must be an array of strings.');
  });

  it("refuses recognizedHeaders that is not an array", async () => {
    const critical = await sign("payload", key, { protectedHeader: { crit: ["app"], app: "web" } });
    const error = await verify(critical, key, {
      payload: "string",
      recognizedHeaders: "app",
    } as never).catch((e) => e);
    expect(isJWTError(error, "ERR_INVALID_OPTION")).toBe(true);
    expect(error.message).toBe('"recognizedHeaders" must be an array of strings.');
  });

  it("refuses options that are not an object", async () => {
    const error = await verify(token, key, null as never).catch((e) => e);
    expect(isJWTError(error, "ERR_INVALID_OPTION")).toBe(true);
    expect(error.message).toBe('"options" must be an object.');
  });

  it("refuses options that are a class instance and accepts JSON-parsed options", async () => {
    class VerifyOptions {
      typ = "at+jwt";
    }
    const error = await verify(token, key, new VerifyOptions()).catch((e) => e);
    expect(isJWTError(error, "ERR_INVALID_OPTION")).toBe(true);
    expect(error.message).toBe('"options" must be an object.');

    const { payload } = await verify(token, key, JSON.parse('{"typ":"at+jwt"}'));
    expect(payload.sub).toBe("u");
  });

  it("quotes and bounds a header kid echoed in a key-not-found message", async () => {
    const kid = `evil\nInjected: yes ${"x".repeat(200)}`;
    const signed = await sign({ sub: "u" }, { ...key, kid });
    const set: JWKSet = { keys: [{ ...key, kid: "other" }] };
    const error = await verify(signed, set, { allowSymmetricJWKSet: true }).catch((e) => e);
    expect(isJWTError(error, "ERR_JWK_KEY_NOT_FOUND")).toBe(true);
    expect(error.message).not.toContain("\n");
    expect(error.message).toContain(String.raw`with kid "evil\nInjected: yes x`);
    expect(error.message.length).toBeLessThan(120);
  });
});

describe("types", () => {
  type MyClaims = { sub: string; role: "admin" | "user" };
  const key = new Uint8Array(32);
  interface MyClaimsInterface {
    sub: string;
    role: "admin" | "user";
  }

  it("accepts an interface as the claims type", () => {
    expectTypeOf(() => verify<MyClaimsInterface>("", key)).returns.resolves.toEqualTypeOf<
      JWSVerifyResult<MyClaimsInterface>
    >();
  });

  it("returns the claims for the default and json payload modes", () => {
    expectTypeOf(() => verify("", key)).returns.resolves.toEqualTypeOf<
      JWSVerifyResult<JWTClaims>
    >();
    expectTypeOf(() => verify("", key, { payload: "json" })).returns.resolves.toEqualTypeOf<
      JWSVerifyResult<JWTClaims>
    >();
    expectTypeOf(() => verify<MyClaims>("", key)).returns.resolves.toEqualTypeOf<
      JWSVerifyResult<MyClaims>
    >();
    expectTypeOf(() =>
      verify<MyClaims>("", key, { payload: "json", algorithms: ["HS256"] }),
    ).returns.resolves.toEqualTypeOf<JWSVerifyResult<MyClaims>>();
  });

  it("returns a string or bytes payload for the string and bytes modes", () => {
    expectTypeOf(() => verify("", key, { payload: "string" })).returns.resolves.toEqualTypeOf<
      JWSVerifyResult<string>
    >();
    expectTypeOf(() => verify("", key, { payload: "bytes" })).returns.resolves.toEqualTypeOf<
      JWSVerifyResult<Uint8Array<ArrayBuffer>>
    >();
  });

  it("returns the union of payloads for a mode that is not a literal", () => {
    expectTypeOf((payload: JOSEPayloadMode) =>
      verify("", key, { payload }),
    ).returns.resolves.toEqualTypeOf<
      JWSVerifyResult<JWTClaims | string | Uint8Array<ArrayBuffer>>
    >();
    expectTypeOf((options: JWSVerifyOptions) =>
      verify("", key, options),
    ).returns.resolves.toEqualTypeOf<
      JWSVerifyResult<JWTClaims | string | Uint8Array<ArrayBuffer>>
    >();
    expectTypeOf((payload: "string" | "bytes") =>
      verify("", key, { payload }),
    ).returns.resolves.toEqualTypeOf<JWSVerifyResult<string | Uint8Array<ArrayBuffer>>>();
  });

  it("keeps the deprecated forceUint8Array overload returning bytes", () => {
    expectTypeOf(() => verify("", key, { forceUint8Array: true })).returns.resolves.toEqualTypeOf<
      JWSVerifyResult<Uint8Array<ArrayBuffer>>
    >();
  });

  it("rejects an unknown payload mode and a claims type outside the json mode", () => {
    // @ts-expect-error not a payload mode
    expectTypeOf(() => verify("", key, { payload: "nonsense" }));
    // @ts-expect-error a claims type implies payload: "json"
    expectTypeOf(() => verify<MyClaims>("", key, { payload: "string" }));
  });

  it("reads each payload mode off the exported map", () => {
    expectTypeOf<PayloadOf<"json">>().toEqualTypeOf<JWTClaims>();
    expectTypeOf<PayloadOf<"json", MyClaims>>().toEqualTypeOf<MyClaims>();
    expectTypeOf<PayloadOf<"string">>().toEqualTypeOf<string>();
    expectTypeOf<PayloadOf<"bytes">>().toEqualTypeOf<Uint8Array<ArrayBuffer>>();
    expectTypeOf<keyof JOSEPayloadTypeMap>().toEqualTypeOf<JOSEPayloadMode>();
  });
});

/**
 * A JWS signed over a protected header the producer refuses to write, so the
 * verification gates can be read on a token whose signature is valid.
 */
async function signRawHeader(
  header: Record<string, unknown>,
  payload: string,
  key: CryptoKey,
): Promise<string> {
  const signingInput = `${base64UrlStringify(JSON.stringify(header))}.${base64UrlStringify(textEncoder.encode(payload))}`;
  const signature = await crypto.subtle.sign("HMAC", key, textEncoder.encode(signingInput));
  return `${signingInput}.${base64UrlStringify(new Uint8Array(signature))}`;
}

function failingKeyLookup(_header: { kid?: string; alg?: string }): never {
  throw new Error("Key lookup failed");
}
