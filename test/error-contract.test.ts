import { describe, it, expect } from "vitest";

import { JWTError, isJWTError } from "../src/core/error";
import { sign, verify, signMulti, verifyMulti, generalToFlattenedJWS } from "../src/core/jws";
import { encrypt, decrypt, encryptMulti, decryptMulti, generalToFlattened } from "../src/core/jwe";
import {
  deriveJWKFromPassword,
  deriveSharedSecret,
  exportKey,
  exportPEM,
  generateJWK,
  generateKey,
  importKey,
  thumbprint,
  unwrapKey,
  wrapKey,
} from "../src/core/jwk";
import { computeDurationInSeconds } from "../src/core/utils";
import type {
  JWK_EC_Private,
  JWK_EC_Public,
  JWEGeneralSerialization,
  JWSGeneralSerialization,
} from "../src/core/types";
import { ec, rsa } from "./keys";

const payload = { sub: "u1" } as const;

const [hs256, a128kw, a256gcmCek, cbcCek, ecdhPair, esPair] = await Promise.all([
  generateJWK("HS256"),
  generateJWK("A128KW"),
  generateJWK("A256GCM"),
  generateJWK("A256CBC-HS512"),
  generateJWK("ECDH-ES+A256KW"),
  generateJWK("ES256"),
]);

/** The error a call threw, or `undefined` when it resolved. */
async function thrown(run: () => Promise<unknown>): Promise<unknown> {
  try {
    await run();
  } catch (error) {
    return error;
  }
  return undefined;
}

/** Assert the call fails with a {@link JWTError} carrying `code`, and return it. */
async function expectCode(run: () => Promise<unknown>, code: string): Promise<JWTError> {
  const error = await thrown(run);
  expect(error, `expected ${code}, nothing was thrown`).toBeInstanceOf(JWTError);
  expect((error as JWTError).code, `expected ${code}, got ${(error as JWTError).code}`).toBe(code);
  return error as JWTError;
}

describe("producer algorithm support gates", () => {
  it("sign rejects an algorithm the library does not implement", async () => {
    await expectCode(
      () => sign(payload, hs256, { alg: "HS257" as "HS256" }),
      "ERR_JWS_ALG_NOT_ALLOWED",
    );
  });

  it('sign rejects "none"', async () => {
    await expectCode(
      () => sign(payload, hs256, { alg: "none" as "HS256" }),
      "ERR_JWS_ALG_NOT_ALLOWED",
    );
  });

  it("sign reports an unsupported algorithm the same way verify does", async () => {
    const signed = await thrown(() => sign(payload, hs256, { alg: "HS257" as "HS256" }));
    const verified = await thrown(() =>
      verify("eyJhbGciOiJIUzI1NyJ9.e30.AAAA", hs256, { algorithms: undefined }),
    );
    expect((signed as JWTError).message).toBe((verified as JWTError).message);
  });

  it("signMulti rejects an unsupported signer algorithm", async () => {
    await expectCode(
      () => signMulti(payload, [{ key: hs256, alg: "HS257" as "HS256" }]),
      "ERR_JWS_ALG_NOT_ALLOWED",
    );
  });

  it("encrypt rejects an unsupported key management algorithm", async () => {
    await expectCode(
      () => encrypt(payload, a128kw, { alg: "A128KWW" as "A128KW", enc: "A256GCM" }),
      "ERR_JWE_ALG_NOT_ALLOWED",
    );
  });

  it('encrypt rejects "none"', async () => {
    await expectCode(
      () => encrypt(payload, a128kw, { alg: "none" as "A128KW", enc: "A256GCM" }),
      "ERR_JWE_ALG_NOT_ALLOWED",
    );
  });

  it("encrypt rejects an unsupported content encryption algorithm", async () => {
    await expectCode(
      () => encrypt(payload, a128kw, { alg: "A128KW", enc: "A128CBC" as "A128GCM" }),
      "ERR_JWE_INVALID",
    );
  });

  it("encryptMulti rejects an unsupported recipient algorithm", async () => {
    await expectCode(
      () => encryptMulti(payload, [{ key: { ...a128kw, alg: "A128KWW" } as any }]),
      "ERR_JWE_ALG_NOT_ALLOWED",
    );
  });

  it("encryptMulti rejects an unsupported content encryption algorithm", async () => {
    await expectCode(
      () => encryptMulti(payload, [{ key: a128kw }], { enc: "A128CBC" as "A128GCM" }),
      "ERR_JWE_INVALID",
    );
  });
});

describe("encrypt key inference", () => {
  it("treats an oct JWK declaring a content encryption algorithm as a dir CEK", async () => {
    const token = await encrypt(payload, a256gcmCek);
    const { protectedHeader, payload: decrypted } = await decrypt(token, a256gcmCek);
    expect(protectedHeader.alg).toBe("dir");
    expect(protectedHeader.enc).toBe("A256GCM");
    expect(decrypted).toEqual(payload);
  });

  it("defaults enc to the CEK's own algorithm under an inferred dir", async () => {
    const token = await encrypt(payload, cbcCek);
    const { protectedHeader } = await decrypt(token, cbcCek);
    expect(protectedHeader.alg).toBe("dir");
    expect(protectedHeader.enc).toBe("A256CBC-HS512");
  });

  it("infers nothing from raw key bytes", async () => {
    await expectCode(
      () => encrypt(payload, new Uint8Array(32) as Uint8Array<ArrayBuffer>),
      "ERR_JWE_ALG_MISSING",
    );
  });

  it("still treats a string key as a PBES2 password", async () => {
    const token = await encrypt(payload, "correct horse battery staple");
    const { protectedHeader } = await decrypt(token, "correct horse battery staple");
    expect(protectedHeader.alg).toBe("PBES2-HS256+A128KW");
  });

  it("refuses a dir CEK recipient in encryptMulti", async () => {
    await expectCode(
      () => encryptMulti(payload, [{ key: a256gcmCek }]),
      "ERR_JWE_ALG_FORBIDDEN_IN_MULTI",
    );
  });

  it("defaults compact encrypt to A256GCM", async () => {
    const token = await encrypt(payload, a128kw);
    const { protectedHeader } = await decrypt(token, a128kw);
    expect(protectedHeader.enc).toBe("A256GCM");
  });
});

describe("key management errors", () => {
  it("importKey rejects a JWK whose alg the library does not implement", async () => {
    await expectCode(
      () => importKey({ ...rsa.jwk.public, alg: "RS257" } as any),
      "ERR_JWK_INVALID",
    );
  });

  it("importKey rejects a JWK whose crv contradicts its alg", async () => {
    await expectCode(
      () => importKey({ ...ec.jwk.public, crv: "P-384" } as any, { alg: "ES256" }),
      "ERR_JWK_INVALID",
    );
  });

  it("importKey rejects an ECDH JWK with an unknown crv", async () => {
    await expectCode(
      () => importKey({ ...ec.jwk.public, alg: "ECDH-ES", crv: "P-999" } as any),
      "ERR_JWK_INVALID",
    );
  });

  it("exportKey rejects a non-extractable CryptoKey", async () => {
    const key = await crypto.subtle.generateKey({ name: "HMAC", hash: "SHA-256" }, false, [
      "sign",
      "verify",
    ]);
    await expectCode(() => exportKey(key), "ERR_JWK_INVALID");
  });

  it("exportKey rejects anything that is not a CryptoKey", async () => {
    await expectCode(() => exportKey(hs256 as unknown as CryptoKey), "ERR_INVALID_OPTION");
  });

  it("exportPEM rejects an algorithm the library does not implement", async () => {
    const { alg: _alg, ...bare } = rsa.jwk.public;
    await expectCode(
      () => exportPEM(bare as any, { alg: "RS257" as "RS256" }),
      "ERR_JWK_UNSUPPORTED",
    );
  });

  it("wrapKey rejects a CEK AES-KW cannot wrap", async () => {
    await expectCode(
      () => wrapKey(new Uint8Array(5) as Uint8Array<ArrayBuffer>, a128kw, { alg: "A128KW" }),
      "ERR_INVALID_OPTION",
    );
  });

  it("wrapKey rejects ECDH-ES key material that is not a key", async () => {
    await expectCode(
      () =>
        wrapKey(new Uint8Array(32) as Uint8Array<ArrayBuffer>, new Uint8Array(32) as any, {
          alg: "ECDH-ES+A256KW",
        }),
      "ERR_JWK_INVALID",
    );
  });

  it("wrapKey rejects RSA-OAEP key material that is not a key", async () => {
    await expectCode(
      () =>
        wrapKey(new Uint8Array(32) as Uint8Array<ArrayBuffer>, new Uint8Array(32) as any, {
          alg: "RSA-OAEP-256",
        }),
      "ERR_JWK_INVALID",
    );
  });

  it("unwrapKey rejects ECDH-ES key material that is not a key", async () => {
    await expectCode(
      () =>
        unwrapKey(new Uint8Array(40) as Uint8Array<ArrayBuffer>, new Uint8Array(32) as any, {
          alg: "ECDH-ES+A256KW",
          enc: "A256GCM",
          epk: ecdhPair.publicKey as JWK_EC_Public,
        }),
      "ERR_JWK_INVALID",
    );
  });

  it("unwrapKey rejects RSA-OAEP key material that is not a key", async () => {
    await expectCode(
      () =>
        unwrapKey(new Uint8Array(256) as Uint8Array<ArrayBuffer>, new Uint8Array(32) as any, {
          alg: "RSA-OAEP-256",
          enc: "A256GCM",
        }),
      "ERR_JWK_INVALID",
    );
  });

  it("sign rejects a key that cannot serve the requested algorithm", async () => {
    const pair = (await generateKey("Ed25519")) as CryptoKeyPair;
    await expectCode(() => sign(payload, pair.privateKey, { alg: "ES256" }), "ERR_JWK_INVALID");
  });

  it("deriveSharedSecret imports JWKs under the requested ECDH-ES variant", async () => {
    const secret = await deriveSharedSecret(
      ecdhPair.publicKey as JWK_EC_Public,
      ecdhPair.privateKey as JWK_EC_Private,
      { enc: "ECDH-ES+A256KW" },
    );
    expect(secret).toBeInstanceOf(Uint8Array);
    expect(secret.length).toBe(32);
  });
});

describe("payload option errors", () => {
  it("sign rejects a payload that is not string, bytes or an object", async () => {
    await expectCode(() => sign(null as any, hs256), "ERR_INVALID_OPTION");
    await expectCode(() => sign(42 as any, hs256), "ERR_INVALID_OPTION");
  });

  it("encrypt rejects a payload that is not string, bytes or an object", async () => {
    await expectCode(() => encrypt(null as any, a128kw), "ERR_INVALID_OPTION");
  });

  it("sign rejects a payload that cannot be serialized as JSON", async () => {
    const error = await expectCode(() => sign({ n: 1n } as any, hs256), "ERR_INVALID_OPTION");
    expect(error.cause).toBeInstanceOf(TypeError);
  });

  it("encrypt rejects a payload that cannot be serialized as JSON", async () => {
    await expectCode(() => encrypt({ n: 1n } as any, a128kw), "ERR_INVALID_OPTION");
  });
});

describe("duration option errors", () => {
  it("computeDurationInSeconds rejects a malformed duration", () => {
    expect(() => computeDurationInSeconds("soon" as any)).toThrow(JWTError);
    expect(() => computeDurationInSeconds(0)).toThrow(
      expect.objectContaining({ code: "ERR_INVALID_OPTION" }),
    );
  });

  it("sign rejects a malformed expiresIn", async () => {
    await expectCode(
      () => sign(payload, hs256, { expiresIn: "soon" as "1h" }),
      "ERR_INVALID_OPTION",
    );
  });

  it("verify rejects a malformed maxTokenAge", async () => {
    const token = await sign({ ...payload, iat: Math.floor(Date.now() / 1000) }, hs256);
    await expectCode(
      () => verify(token, hs256, { maxTokenAge: "soon" as "1h" }),
      "ERR_INVALID_OPTION",
    );
  });
});

describe("compact entry inputs", () => {
  it("verify rejects a token that is not a string", async () => {
    const error = await expectCode(() => verify(42 as any, hs256), "ERR_JWS_INVALID");
    expect(error.message).toBe("Invalid JWS: token must be a string.");
  });

  it("decrypt rejects a token that is not a string", async () => {
    const error = await expectCode(() => decrypt(null as any, a128kw), "ERR_JWE_INVALID");
    expect(error.message).toBe("Invalid JWE: token must be a string.");
  });

  it("generalToFlattenedJWS rejects a non-object", () => {
    expect(() => generalToFlattenedJWS("nope" as any)).toThrow(
      expect.objectContaining({ code: "ERR_JWS_INVALID_SERIALIZATION" }),
    );
  });

  it("generalToFlattened rejects a non-object", () => {
    expect(() => generalToFlattened(null as any)).toThrow(
      expect.objectContaining({ code: "ERR_JWE_INVALID_SERIALIZATION" }),
    );
  });
});

describe("key lookup failures", () => {
  const boom = () => {
    throw new RangeError("lookup exploded");
  };

  it("verify reports a throwing lookup as key-not-found", async () => {
    const token = await sign(payload, hs256);
    const error = await expectCode(() => verify(token, boom as any), "ERR_JWK_KEY_NOT_FOUND");
    expect(error.cause).toBeInstanceOf(RangeError);
  });

  it("decrypt reports a throwing lookup as key-not-found", async () => {
    const token = await encrypt(payload, a128kw);
    const error = await expectCode(() => decrypt(token, boom as any), "ERR_JWK_KEY_NOT_FOUND");
    expect(error.cause).toBeInstanceOf(RangeError);
  });

  it("verifyMulti reports a throwing lookup as key-not-found", async () => {
    const general = await signMulti(payload, [{ key: hs256 }]);
    const error = await expectCode(
      () => verifyMulti(general, boom as any),
      "ERR_JWK_KEY_NOT_FOUND",
    );
    expect(error.cause).toBeInstanceOf(RangeError);
  });

  it("decryptMulti reports a throwing lookup as key-not-found", async () => {
    const general = await encryptMulti(payload, [{ key: a128kw }]);
    const error = await expectCode(
      () => decryptMulti(general, boom as any),
      "ERR_JWK_KEY_NOT_FOUND",
    );
    expect(error.cause).toBeInstanceOf(RangeError);
  });
});

describe("JWE producer option errors", () => {
  it("encrypt rejects a CEK of the wrong size", async () => {
    await expectCode(
      () =>
        encrypt(payload, a128kw, {
          alg: "A128KW",
          enc: "A256GCM",
          cek: new Uint8Array(16) as Uint8Array<ArrayBuffer>,
        }),
      "ERR_INVALID_OPTION",
    );
  });

  it("encrypt rejects a content encryption IV of the wrong length", async () => {
    await expectCode(
      () =>
        encrypt(payload, a128kw, {
          alg: "A128KW",
          enc: "A256GCM",
          contentEncryptionIV: new Uint8Array(8) as Uint8Array<ArrayBuffer>,
        }),
      "ERR_INVALID_OPTION",
    );
  });

  it("encrypt rejects a p2s shorter than 8 octets", async () => {
    await expectCode(
      () => encrypt(payload, "pw", { p2s: new Uint8Array(4) as Uint8Array<ArrayBuffer> }),
      "ERR_INVALID_OPTION",
    );
  });

  it("encrypt rejects p2c: 0 rather than replacing it", async () => {
    await expectCode(() => encrypt(payload, "pw", { p2c: 0 }), "ERR_INVALID_OPTION");
  });

  it("encrypt rejects a p2c below the iteration floor", async () => {
    await expectCode(() => encrypt(payload, "pw", { p2c: 10 }), "ERR_INVALID_OPTION");
  });

  it("encrypt rejects a p2c above the iteration ceiling", async () => {
    await expectCode(() => encrypt(payload, "pw", { p2c: 2_000_000 }), "ERR_INVALID_OPTION");
  });

  it("encryptMulti rejects a recipient p2c of 0", async () => {
    const pbes2 = { ...a128kw, alg: "PBES2-HS256+A128KW" } as const;
    await expectCode(() => encryptMulti(payload, [{ key: pbes2, p2c: 0 }]), "ERR_INVALID_OPTION");
  });

  it("wrapKey rejects a p2s shorter than 8 octets", async () => {
    await expectCode(
      () =>
        wrapKey(new Uint8Array(32) as Uint8Array<ArrayBuffer>, "pw", {
          alg: "PBES2-HS256+A128KW",
          p2s: new Uint8Array(4) as Uint8Array<ArrayBuffer>,
          p2c: 1000,
        }),
      "ERR_INVALID_OPTION",
    );
  });

  it("wrapKey rejects a p2c outside the iteration bounds", async () => {
    await expectCode(
      () =>
        wrapKey(new Uint8Array(32) as Uint8Array<ArrayBuffer>, "pw", {
          alg: "PBES2-HS256+A128KW",
          p2s: new Uint8Array(16) as Uint8Array<ArrayBuffer>,
          p2c: 1,
        }),
      "ERR_INVALID_OPTION",
    );
  });
});

describe("key generation", () => {
  it("stamps alg, ext and key_ops on an AES-CBC+HMAC JWK", async () => {
    expect(cbcCek.alg).toBe("A256CBC-HS512");
    expect(cbcCek.ext).toBe(true);
    expect(cbcCek.key_ops).toEqual(["encrypt", "decrypt"]);
  });

  it("gives every generateKey JWK the thumbprint kid generateJWK promises", async () => {
    const single = await generateKey("A128GCM", { toJWK: true });
    expect(single.kid).toBe(await thumbprint(single));

    const pair = await generateKey("ES256", { toJWK: true });
    expect(pair.publicKey.kid).toBe(await thumbprint(pair.publicKey));
    expect(pair.privateKey.kid).toBe(pair.publicKey.kid);
  });

  it("lets generateJWK keep naming the key itself", async () => {
    const named = await generateJWK("HS256", { kid: "named" });
    expect(named.kid).toBe("named");
    const pair = await generateJWK("ES256", { kid: "pair" });
    expect(pair.privateKey.kid).toBe("pair");
    expect(pair.publicKey.kid).toBe("pair");
  });

  it("never copies option names into the emitted JWK", async () => {
    const jwk = await generateJWK("HS256", {
      extractable: false,
      toJWK: true,
      keyUsage: ["sign", "verify"],
    } as any);
    for (const option of ["extractable", "toJWK", "keyUsage", "modulusLength", "namedCurve"]) {
      expect(jwk).not.toHaveProperty(option);
    }
  });

  it("refuses a reserved JWK member in generateJWK metadata", async () => {
    await expectCode(() => generateJWK("HS256", { kty: "oct" } as any), "ERR_INVALID_OPTION");
  });

  it("refuses a reserved JWK member in deriveJWKFromPassword metadata", async () => {
    await expectCode(
      () =>
        deriveJWKFromPassword("pw", {
          alg: "PBES2-HS256+A128KW",
          salt: "saltsalt",
          iterations: 1000,
          k: "nope",
        } as any),
      "ERR_INVALID_OPTION",
    );
  });

  it("honours a caller-supplied keyUsage for ECDH-ES", async () => {
    const pair = (await generateKey("ECDH-ES", { keyUsage: ["deriveKey"] })) as CryptoKeyPair;
    expect(pair.privateKey.usages).toEqual(["deriveKey"]);
  });

  it("rejects a keyUsage the algorithm cannot serve", async () => {
    await expectCode(() => generateKey("ECDH-ES", { keyUsage: ["sign"] }), "ERR_INVALID_OPTION");
    await expectCode(() => generateKey("HS256", { keyUsage: ["encrypt"] }), "ERR_INVALID_OPTION");
  });
});

describe("round trips the contract must not have broken", () => {
  it("signs and verifies with a generated pair", async () => {
    const token = await sign(payload, esPair.privateKey);
    const { payload: verified } = await verify(token, esPair.publicKey);
    expect(verified).toEqual(payload);
  });

  it("encrypts and decrypts to an ECDH-ES+A256KW recipient", async () => {
    const general: JWEGeneralSerialization = await encryptMulti(payload, [
      { key: ecdhPair.publicKey },
    ]);
    const { payload: decrypted } = await decryptMulti(general, ecdhPair.privateKey);
    expect(decrypted).toEqual(payload);
  });

  it("round-trips a multi-signature document", async () => {
    const general: JWSGeneralSerialization = await signMulti(payload, [{ key: hs256 }]);
    const { payload: verified } = await verifyMulti(general, hs256);
    expect(verified).toEqual(payload);
    expect(isJWTError(new JWTError("x", "ERR_INVALID_OPTION"), "ERR_INVALID_OPTION")).toBe(true);
  });
});
