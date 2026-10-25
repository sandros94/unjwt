import { beforeAll, describe, expect, it, vi } from "vitest";
import * as jose from "jose";
import { JWTError, createDPoPProof, verifyDPoPProof } from "../src/dpop/index.ts";
import { clearJWKCache, configureJWKCache, generateJWK, generateKey } from "../src/core/jwk.ts";
import { digestUrl } from "../src/core/utils/digest.ts";
import { base64UrlStringify } from "../src/core/utils/base64.ts";
import type {
  DPoPCreateOptions,
  DPoPKeyPair,
  DPoPTarget,
  DPoPVerifyOptions,
} from "../src/dpop/types.ts";

const target = { method: "POST", url: "https://server.example/token?ignored=yes#fragment" };
const iat = 1_700_000_000;
const verification: DPoPVerifyOptions = {
  algorithms: ["ES256"],
  currentDate: new Date(iat * 1000),
  maxTokenAge: 60,
};
let creation: DPoPCreateOptions;
let publicJWK: jose.JWK;
let privateKey: CryptoKey;

beforeAll(async () => {
  const keyPair = await generateJWK("ES256");
  creation = { keyPair, algorithm: "ES256", jti: "unique-proof-id", iat };
  publicJWK = keyPair.publicKey;
  privateKey = await jose.importJWK(keyPair.privateKey, "ES256");
});

async function foreignProof(
  payload: Record<string, unknown> = {},
  header: Partial<jose.JWTHeaderParameters> = {},
) {
  return new jose.SignJWT({
    jti: "foreign-proof",
    iat,
    htm: "POST",
    htu: "https://server.example/token",
    ...payload,
  })
    .setProtectedHeader({ alg: "ES256", typ: "dpop+jwt", jwk: publicJWK, ...header })
    .sign(privateKey);
}

describe("DPoP", () => {
  it("accepts a Web Request as the target when creating and verifying a proof", async () => {
    const request = new Request(target.url, { method: target.method });
    const proof = await createDPoPProof(request, creation);
    await expect(verifyDPoPProof(proof, request, verification)).resolves.toHaveProperty(
      "payload.htm",
      request.method,
    );
  });

  it("hashes the raw token supplied in the creation accessToken object", async () => {
    const token = "raw-token.A_1";
    const proof = await createDPoPProof(target, { ...creation, accessToken: { token } });
    const bytes = new TextEncoder().encode(token);
    const expected = jose.base64url.encode(
      new Uint8Array(await crypto.subtle.digest("SHA-256", bytes)),
    );
    expect(jose.decodeJwt(proof).ath).toBe(expected);
  });

  it.each([
    null,
    "raw-token",
    [],
    {},
    { token: undefined },
    { token: "" },
    { token: 1 },
    { token: "\u00e9" },
  ])("rejects malformed creation accessToken %j", async (accessToken) => {
    await expect(
      createDPoPProof(target, { ...creation, accessToken } as DPoPCreateOptions),
    ).rejects.toHaveProperty("code", "ERR_INVALID_OPTION");
  });

  it.each([null, "raw-token", [], {}, { token: "raw-token" }, { thumbprint: "A".repeat(43) }])(
    "requires both token and thumbprint when verifying accessToken %j",
    async (accessToken) => {
      const consumeProof = vi.fn(() => true);
      const proof = await foreignProof({ ath: await digestUrl("raw-token") });
      await expect(
        verifyDPoPProof(proof, target, {
          ...verification,
          accessToken,
          consumeProof,
        } as unknown as DPoPVerifyOptions),
      ).rejects.toHaveProperty("code", "ERR_INVALID_OPTION");
      expect(consumeProof).not.toHaveBeenCalled();
    },
  );

  it.each([
    null,
    "https://server.example/token",
    [],
    {},
    { method: "POST" },
    { url: target.url },
    { ...target, method: "POST GET" },
    { ...target, url: "/token" },
  ])("rejects malformed target argument %j before replay consumption", async (invalidTarget) => {
    const consumeProof = vi.fn(() => true);
    const proof = await foreignProof();
    await expect(
      verifyDPoPProof(proof, invalidTarget as DPoPTarget, { ...verification, consumeProof }),
    ).rejects.toHaveProperty("code", "ERR_INVALID_OPTION");
    await expect(createDPoPProof(invalidTarget as DPoPTarget, creation)).rejects.toHaveProperty(
      "code",
      "ERR_INVALID_OPTION",
    );
    expect(consumeProof).not.toHaveBeenCalled();
  });

  it("omits optional time restrictions unless supplied", async () => {
    const payload = jose.decodeJwt(await createDPoPProof(target, creation));
    expect(payload).not.toHaveProperty("exp");
    expect(payload).not.toHaveProperty("nbf");
  });

  it.each(["exp", "nbf"] as const)("preserves an explicit %s, including zero", async (claim) => {
    for (const value of [0, iat + 0.5]) {
      const proof = await createDPoPProof(target, { ...creation, [claim]: value });
      expect(jose.decodeJwt(proof)[claim]).toBe(value);
    }
  });

  it.each(["exp", "nbf"] as const)("rejects malformed %s on creation", async (claim) => {
    for (const value of [null, "1700000000", NaN, Infinity, -1]) {
      await expect(createDPoPProof(target, { ...creation, [claim]: value })).rejects.toHaveProperty(
        "code",
        "ERR_INVALID_OPTION",
      );
    }
  });

  it("enforces opt-in time restrictions before replay consumption", async () => {
    const consumeProof = vi.fn(() => true);
    const proof = await createDPoPProof(target, { ...creation, nbf: iat + 10, exp: iat + 20 });
    await expect(
      verifyDPoPProof(proof, target, { ...verification, consumeProof }),
    ).rejects.toMatchObject({ code: "ERR_DPOP_CLAIM_INVALID", cause: { code: "ERR_JWT_NBF" } });
    await expect(
      verifyDPoPProof(proof, target, {
        ...verification,
        currentDate: new Date((iat + 20) * 1000),
        consumeProof,
      }),
    ).rejects.toMatchObject({ code: "ERR_DPOP_CLAIM_INVALID", cause: { code: "ERR_JWT_EXPIRED" } });
    expect(consumeProof).not.toHaveBeenCalled();
    await expect(
      verifyDPoPProof(proof, target, {
        ...verification,
        currentDate: new Date((iat + 10) * 1000),
        consumeProof,
      }),
    ).resolves.toMatchObject({ payload: { nbf: iat + 10, exp: iat + 20 } });
    expect(consumeProof).toHaveBeenCalledOnce();
  });

  it("still enforces proof age when optional time restrictions pass", async () => {
    const proof = await createDPoPProof(target, { ...creation, nbf: iat, exp: iat + 600 });
    await expect(
      verifyDPoPProof(proof, target, { ...verification, currentDate: new Date((iat + 61) * 1000) }),
    ).rejects.toHaveProperty("code", "ERR_DPOP_CLAIM_INVALID");
  });

  it.each(["ES256", "RS256", "PS256", "EdDSA", "Ed25519"] as const)(
    "infers %s from the JWK pair",
    async (algorithm) => {
      const keyPair = await generateJWK(algorithm);
      const proof = await createDPoPProof(target, { ...creation, keyPair, algorithm: undefined });
      expect(jose.decodeProtectedHeader(proof).alg).toBe(algorithm);
      await expect(
        verifyDPoPProof(proof, target, { ...verification, algorithms: [algorithm] }),
      ).resolves.toHaveProperty("payload.iat", iat);
    },
  );

  it("infers the unique EC algorithm without alg metadata", async () => {
    const keyPair: DPoPKeyPair = await generateJWK("ES256");
    delete keyPair.privateKey.alg;
    delete keyPair.publicKey.alg;
    const proof = await createDPoPProof(target, { ...creation, keyPair, algorithm: undefined });
    expect(jose.decodeProtectedHeader(proof).alg).toBe("ES256");
  });

  it("uses public JWK alg metadata when the private JWK omits it", async () => {
    const keyPair: DPoPKeyPair = await generateJWK("PS256");
    delete keyPair.privateKey.alg;
    const proof = await createDPoPProof(target, { ...creation, keyPair, algorithm: undefined });
    expect(jose.decodeProtectedHeader(proof).alg).toBe("PS256");
  });

  it.each(["RS256", "Ed25519"] as const)(
    "requires an explicit algorithm for ambiguous %s JWKs",
    async (algorithm) => {
      const keyPair: DPoPKeyPair = await generateJWK(algorithm);
      delete keyPair.privateKey.alg;
      delete keyPair.publicKey.alg;
      await expect(
        createDPoPProof(target, { ...creation, keyPair, algorithm: undefined }),
      ).rejects.toHaveProperty("code", "ERR_INVALID_OPTION");
      const proof = await createDPoPProof(target, { ...creation, keyPair, algorithm });
      expect(jose.decodeProtectedHeader(proof).alg).toBe(algorithm);
    },
  );

  it("rejects conflicting algorithm metadata in the JWK pair", async () => {
    const keyPair: DPoPKeyPair = await generateJWK("RS256");
    keyPair.publicKey.alg = "PS256";
    for (const algorithm of [undefined, "RS256"] as const) {
      await expect(
        createDPoPProof(target, { ...creation, keyPair, algorithm }),
      ).rejects.toHaveProperty("code", "ERR_INVALID_OPTION");
    }
  });

  it.each([null, "", false, 0, "HS256", "none"])(
    "rejects invalid public JWK algorithm metadata %j",
    async (alg) => {
      const keyPair = await generateJWK("ES256");
      await expect(
        createDPoPProof(target, {
          ...creation,
          keyPair: { ...keyPair, publicKey: { ...keyPair.publicKey, alg } },
        } as DPoPCreateOptions),
      ).rejects.toHaveProperty("code", "ERR_INVALID_OPTION");
    },
  );

  it("requires an explicit algorithm for CryptoKey pairs", async () => {
    const keyPair = await generateKey("ES256");
    await expect(
      createDPoPProof(target, { ...creation, keyPair, algorithm: undefined }),
    ).rejects.toHaveProperty("code", "ERR_INVALID_OPTION");
  });

  it("rejects symmetric JWK and CryptoKey pairs even with an asymmetric algorithm", async () => {
    const jwk = await generateJWK("HS256");
    const key = await generateKey("HS256");
    for (const secret of [jwk, key]) {
      for (const algorithm of [undefined, "ES256", "HS256"]) {
        await expect(
          createDPoPProof(target, {
            ...creation,
            algorithm,
            keyPair: { privateKey: secret, publicKey: secret },
          } as DPoPCreateOptions),
        ).rejects.toHaveProperty("code", "ERR_INVALID_OPTION");
      }
    }
  });

  it("rejects a correctly MACed HMAC proof before replay consumption", async () => {
    const key = await generateJWK("HS256");
    const secret = await jose.importJWK(key, "HS256");
    const proof = await new jose.SignJWT({ jti: "id", iat, htm: "POST", htu: target.url })
      .setProtectedHeader({ alg: "HS256", typ: "dpop+jwt", jwk: key })
      .sign(secret);
    const consumeProof = vi.fn(() => true);
    await expect(
      verifyDPoPProof(proof, target, { ...verification, consumeProof }),
    ).rejects.toHaveProperty("code", "ERR_DPOP_INVALID");
    expect(consumeProof).not.toHaveBeenCalled();
  });

  it("defaults each proof to the current second and a fresh UUID without changing options", async () => {
    const options = { keyPair: creation.keyPair, algorithm: creation.algorithm };
    const clock = vi.spyOn(Date, "now").mockReturnValue(iat * 1000 + 999);
    try {
      const first = await createDPoPProof(target, options);
      clock.mockReturnValue((iat + 1) * 1000);
      const second = await createDPoPProof(target, options);
      const a = await verifyDPoPProof(first, target, verification);
      const b = await verifyDPoPProof(second, target, {
        ...verification,
        currentDate: new Date((iat + 1) * 1000),
      });
      expect(a.payload.iat).toBe(iat);
      expect(b.payload.iat).toBe(iat + 1);
      for (const result of [a, b]) {
        expect(result.payload.jti).toMatch(
          /^[\da-f]{8}-[\da-f]{4}-4[\da-f]{3}-[89ab][\da-f]{3}-[\da-f]{12}$/,
        );
      }
      expect(a.payload.jti).not.toBe(b.payload.jti);
      expect(options).not.toHaveProperty("iat");
      expect(options).not.toHaveProperty("jti");
    } finally {
      clock.mockRestore();
    }
  });

  it("preserves explicit proof ID and timestamp overrides, including zero", async () => {
    const proof = await createDPoPProof(target, { ...creation, iat: 0 });
    const result = await verifyDPoPProof(proof, target, {
      ...verification,
      currentDate: new Date(0),
    });
    expect(result.payload.iat).toBe(0);
    expect(result.payload.jti).toBe(creation.jti);
  });

  it("creates a proof a foreign JOSE verifier authenticates", async () => {
    const proof = await createDPoPProof(target, creation);
    const key = await jose.importJWK(publicJWK, "ES256");
    const result = await jose.jwtVerify(proof, key, {
      typ: "dpop+jwt",
      currentDate: verification.currentDate,
    });
    expect(result.payload).toEqual({
      jti: creation.jti,
      iat,
      htm: "POST",
      htu: "https://server.example/token",
    });
    expect(Object.keys(result.protectedHeader.jwk!)).toEqual(["kty", "crv", "x", "y"]);
  });

  it("verifies a foreign proof and returns its authenticated thumbprint", async () => {
    const result = await verifyDPoPProof(await foreignProof(), target, verification);
    expect(result.payload.jti).toBe("foreign-proof");
    expect(result.thumbprint).toBe(await jose.calculateJwkThumbprint(publicJWK));
  });

  it("uses an explicit nonextractable CryptoKey pair", async () => {
    const keyPair = await generateKey("ES256", { extractable: false });
    expect(keyPair.privateKey.extractable).toBe(false);
    const proof = await createDPoPProof(new Request(target.url, { method: target.method }), {
      ...creation,
      keyPair,
    });
    await expect(verifyDPoPProof(proof, target, verification)).resolves.toHaveProperty(
      "payload.jti",
      creation.jti,
    );
  });

  it("checks access token hash and the expected thumbprint together", async () => {
    const token = "access-token";
    const keyThumbprint = await jose.calculateJwkThumbprint(publicJWK);
    const proof = await foreignProof({ ath: await digestUrl(token) });
    await expect(
      verifyDPoPProof(proof, target, {
        ...verification,
        accessToken: { token, thumbprint: keyThumbprint },
      }),
    ).resolves.toHaveProperty("thumbprint", keyThumbprint);
    await expect(
      verifyDPoPProof(proof, target, {
        ...verification,
        accessToken: { token: "wrong", thumbprint: keyThumbprint },
      }),
    ).rejects.toHaveProperty("code", "ERR_DPOP_CLAIM_INVALID");
  });

  it("normalizes percent-encoded unreserved URI characters without decoding escaped slashes", async () => {
    const proof = await foreignProof({ htu: "https://SERVER.example:443/a/%7eb/%2e%2e/token" });
    await expect(
      verifyDPoPProof(proof, { ...target, url: "https://server.example/a/token?x" }, verification),
    ).resolves.toHaveProperty("payload.htm", "POST");
    await expect(
      verifyDPoPProof(
        await foreignProof({ htu: "https://server.example/a%2fb" }),
        { ...target, url: "https://server.example/a/b" },
        verification,
      ),
    ).rejects.toHaveProperty("code", "ERR_DPOP_CLAIM_INVALID");
  });

  it("consumes a proof only after every check succeeds", async () => {
    const consumeProof = vi.fn(() => true);
    await expect(
      verifyDPoPProof(await foreignProof({ nonce: "bad" }), target, {
        ...verification,
        nonce: "required",
        consumeProof,
      }),
    ).rejects.toHaveProperty("code", "ERR_DPOP_NONCE_INVALID");
    expect(consumeProof).not.toHaveBeenCalled();
    await verifyDPoPProof(await foreignProof(), target, { ...verification, consumeProof });
    expect(consumeProof).toHaveBeenCalledOnce();
    await expect(
      verifyDPoPProof(await foreignProof(), target, { ...verification, consumeProof: () => false }),
    ).rejects.toHaveProperty("code", "ERR_DPOP_REPLAY");
  });

  it.each(["ES384", "ES512", "RS256", "PS256", "EdDSA", "Ed25519"] as const)(
    "interoperates with foreign %s proofs in both directions",
    async (algorithm) => {
      const keyPair = await generateJWK(algorithm);
      const proof = await createDPoPProof(target, { ...creation, algorithm, keyPair });
      const publicKey = await jose.importJWK(keyPair.publicKey, algorithm);
      await expect(jose.jwtVerify(proof, publicKey, { typ: "dpop+jwt" })).resolves.toHaveProperty(
        "payload.iat",
        iat,
      );
      const signingKey = await jose.importJWK(keyPair.privateKey, algorithm);
      const foreign = await new jose.SignJWT({
        jti: "foreign",
        iat,
        htm: target.method,
        htu: target.url,
      })
        .setProtectedHeader({ alg: algorithm, typ: "dpop+jwt", jwk: keyPair.publicKey })
        .sign(signingKey);
      await expect(
        verifyDPoPProof(foreign, target, { ...verification, algorithms: [algorithm] }),
      ).resolves.toHaveProperty("thumbprint", await jose.calculateJwkThumbprint(keyPair.publicKey));
    },
  );

  it("issues nonce and independently hashed access token without changing the supplied keys", async () => {
    const original = structuredClone(creation.keyPair);
    const proof = await createDPoPProof(target, {
      ...creation,
      nonce: "nonce!",
      accessToken: { token: "token.A-1" },
    });
    const payload = jose.decodeJwt(proof);
    const hash = new Uint8Array(
      await crypto.subtle.digest("SHA-256", new TextEncoder().encode("token.A-1")),
    );
    expect(payload.ath).toBe(jose.base64url.encode(hash));
    expect(payload.nonce).toBe("nonce!");
    expect(creation.keyPair).toEqual(original);
  });

  it.each(["jti", "iat", "htm", "htu"])("requires authenticated %s", async (claim) => {
    await expect(
      verifyDPoPProof(await foreignProof({ [claim]: undefined }), target, verification),
    ).rejects.toHaveProperty("code", "ERR_DPOP_CLAIM_INVALID");
  });

  it.each([
    { jti: "" },
    { jti: 1 },
    { htm: "" },
    { htm: "GET" },
    { htm: "post" },
    { htm: "POST GET" },
    { htu: 1 },
    { htu: "https://other.example/token" },
    { htu: "/token" },
    { htu: "file:///token" },
    { iat: iat + 0.001 },
    { iat: iat - 60.001 },
    { nonce: "" },
    { nonce: "with space" },
    { nonce: 'quote"' },
    { nonce: "back\\slash" },
    { nonce: "\u00e9" },
    { nonce: null },
    { ath: "" },
    { ath: 1 },
    { ath: "A".repeat(42) },
    { ath: "A".repeat(42) + "B" },
  ])("rejects invalid bound claims %j", async (payload) => {
    await expect(
      verifyDPoPProof(await foreignProof(payload), target, verification),
    ).rejects.toHaveProperty("code", "ERR_DPOP_CLAIM_INVALID");
  });

  it.each([{ iat: "123" }, { iat: -1 }, { iat: null }])(
    "rejects malformed NumericDate %j",
    async (payload) => {
      await expect(
        verifyDPoPProof(await foreignProof(payload), target, verification),
      ).rejects.toHaveProperty("code", "ERR_DPOP_CLAIM_INVALID");
    },
  );

  it("applies exact fractional-second freshness boundaries and tolerance", async () => {
    for (const issuedAt of [iat - 60, iat]) {
      await expect(
        verifyDPoPProof(await foreignProof({ iat: issuedAt }), target, verification),
      ).resolves.toBeDefined();
    }
    await expect(
      verifyDPoPProof(await foreignProof({ iat: iat - 60 }), target, {
        ...verification,
        currentDate: new Date(iat * 1000 + 1),
      }),
    ).rejects.toHaveProperty("code", "ERR_DPOP_CLAIM_INVALID");
    for (const issuedAt of [iat - 61, iat + 1]) {
      await expect(
        verifyDPoPProof(await foreignProof({ iat: issuedAt }), target, {
          ...verification,
          clockTolerance: 1,
        }),
      ).resolves.toBeDefined();
    }
  });

  it.each([
    ["https://SERVER.example:443/token", "https://server.example/token"],
    ["https://server.example", "https://server.example/"],
    ["https://server.example/%74oken", "https://server.example/token"],
    ["https://server.example/a/../token", "https://server.example/token"],
    ["https://server.example/a/%2e%2e/token", "https://server.example/token"],
    ["https://server.example/a/%2E%2e/token", "https://server.example/a/b/%2e%2E/../token"],
    ["https://server.example/a%2fb", "https://server.example/a%2Fb"],
    ["https://server.example/token?bad=%xx#ignored", "https://server.example/token?other=%yy"],
    ["http://server.example:80/token", "http://server.example/token"],
    ["https://B\u00fccher.example/token", "https://xn--bcher-kva.example/token"],
    ["https://[0:0::1]:443/token", "https://[::1]/token"],
  ])("normalizes equivalent URIs %s and %s", async (htu, url) => {
    await expect(
      verifyDPoPProof(await foreignProof({ htu }), { ...target, url }, verification),
    ).resolves.toBeDefined();
  });

  it.each([
    ["https://server.example/Token", "https://server.example/token"],
    ["https://server.example/a%252fb", "https://server.example/a%2fb"],
    ["https://server.example/token", "http://server.example/token"],
    ["https://server.example:444/token", "https://server.example/token"],
  ])("distinguishes different URIs %s and %s", async (htu, url) => {
    await expect(
      verifyDPoPProof(await foreignProof({ htu }), { ...target, url }, verification),
    ).rejects.toHaveProperty("code", "ERR_DPOP_CLAIM_INVALID");
  });

  it.each([
    "https:///server.example/token",
    "https://user@server.example/token",
    "https://@server.example/token",
    "https://server.example/a\\b",
    "https://server.example/\ntoken",
    "https://server.example/%xx",
    " https://server.example/token",
    "https://server.example/a b",
    "https://server.example:%34%34%33/token",
    "https://server.ex%41mple/token",
    "https://%73erver.example/token",
    "https://[%3A%3A1]/token",
  ])("refuses repaired or malformed target %j", async (url) => {
    await expect(createDPoPProof({ ...target, url }, creation)).rejects.toHaveProperty(
      "code",
      "ERR_INVALID_OPTION",
    );
    await expect(
      verifyDPoPProof(await foreignProof({ htu: url }), target, verification),
    ).rejects.toHaveProperty("code", "ERR_DPOP_CLAIM_INVALID");
  });

  it.each(["d", "p", "q", "dp", "dq", "qi", "oth", "k"])(
    "rejects any own private %s member in the embedded public key",
    async (member) => {
      const jwk = { ...publicJWK, [member]: null };
      await expect(
        verifyDPoPProof(await foreignProof({}, { jwk }), target, verification),
      ).rejects.toHaveProperty("code", "ERR_DPOP_INVALID");
      await expect(
        createDPoPProof(target, {
          ...creation,
          keyPair: { ...creation.keyPair, publicKey: jwk },
        } as DPoPCreateOptions),
      ).rejects.toHaveProperty("code", "ERR_INVALID_OPTION");
    },
  );

  it("publishes only required public key members, discarding caller metadata", async () => {
    const keyPair = await generateJWK("ES256");
    const decorated = {
      ...keyPair.publicKey,
      arbitrary: "private application data",
      x5c: ["not a certificate"],
      use: "enc" as const,
    };
    const proof = await createDPoPProof(target, {
      ...creation,
      keyPair: { ...keyPair, publicKey: decorated },
    });
    expect(jose.decodeProtectedHeader(proof).jwk).toEqual({
      kty: "EC",
      crv: keyPair.publicKey.crv,
      x: keyPair.publicKey.x,
      y: keyPair.publicKey.y,
    });
  });

  it.each([
    undefined,
    null,
    {},
    { kty: "oct", k: "YWJj" },
    { kty: "EC", crv: "P-256", x: "x" },
    { kty: "OKP", crv: "X25519", x: "x" },
  ])("rejects missing or invalid public JWK %j", async (jwk) => {
    await expect(
      verifyDPoPProof(
        await foreignProof({}, { jwk } as Partial<jose.JWTHeaderParameters>),
        target,
        verification,
      ),
    ).rejects.toHaveProperty("code", "ERR_DPOP_INVALID");
  });

  it.each([
    ["RS256", "n"],
    ["ES256", "x"],
    ["ES256", "y"],
    ["Ed25519", "x"],
  ] as const)("rejects a non-canonical %s jwk %s member", async (algorithm, member) => {
    const keyPair = await generateJWK(algorithm);
    const publicKey: Record<string, unknown> = { ...keyPair.publicKey };
    const value = String(publicKey[member]);
    const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    const flipped = value.slice(0, -1) + alphabet[alphabet.indexOf(value.at(-1)!) ^ 1];
    const jwk = { ...publicKey, [member]: flipped };
    const signingKey = await jose.importJWK(keyPair.privateKey, algorithm);
    const proof = await new jose.SignJWT({ jti: "id", iat, htm: target.method, htu: target.url })
      .setProtectedHeader({ alg: algorithm, typ: "dpop+jwt", jwk })
      .sign(signingKey);
    const options = { ...verification, algorithms: [algorithm] };
    await expect(verifyDPoPProof(proof, target, options)).rejects.toHaveProperty(
      "code",
      "ERR_DPOP_INVALID",
    );
    await expect(
      createDPoPProof(target, {
        ...creation,
        algorithm,
        keyPair: { ...keyPair, publicKey: jwk },
      } as unknown as DPoPCreateOptions),
    ).rejects.toHaveProperty("code", "ERR_INVALID_OPTION");
    const canonical = await new jose.SignJWT({
      jti: "id",
      iat,
      htm: target.method,
      htu: target.url,
    })
      .setProtectedHeader({ alg: algorithm, typ: "dpop+jwt", jwk: keyPair.publicKey })
      .sign(signingKey);
    await expect(verifyDPoPProof(canonical, target, options)).resolves.toHaveProperty(
      "thumbprint",
      await jose.calculateJwkThumbprint(keyPair.publicKey),
    );
  });

  it("rejects a public key incompatible with the protected algorithm", async () => {
    const other = await generateJWK("ES384");
    await expect(
      verifyDPoPProof(await foreignProof({}, { jwk: other.publicKey }), target, verification),
    ).rejects.toHaveProperty("code", "ERR_DPOP_INVALID");
    await expect(
      createDPoPProof(target, {
        ...creation,
        keyPair: { ...creation.keyPair, publicKey: other.publicKey },
      } as DPoPCreateOptions),
    ).rejects.toHaveProperty("code", "ERR_INVALID_OPTION");
  });

  it("rejects mismatched key pairs when verifying their proof", async () => {
    const other = await generateJWK("ES256");
    const proof = await createDPoPProof(target, {
      ...creation,
      keyPair: { ...creation.keyPair, publicKey: other.publicKey },
    } as DPoPCreateOptions);
    await expect(verifyDPoPProof(proof, target, verification)).rejects.toMatchObject({
      code: "ERR_DPOP_INVALID",
      cause: { code: "ERR_JWS_SIGNATURE_INVALID" },
    });
  });

  it.each([undefined, "JWT", "not-dpop+jwt"])(
    "rejects missing or incorrect typ %j",
    async (typ) => {
      await expect(
        verifyDPoPProof(await foreignProof({}, { typ }), target, verification),
      ).rejects.toHaveProperty("code", "ERR_DPOP_INVALID");
    },
  );

  it.each(["DPoP+JWT", "application/dpop+jwt"])("accepts media type spelling %s", async (typ) => {
    await expect(
      verifyDPoPProof(await foreignProof({}, { typ }), target, verification),
    ).resolves.toBeDefined();
  });

  it.each(["none", "HS256", "ES256K"])(
    "rejects forbidden or unsupported header algorithm %s",
    async (alg) => {
      const proof = `${base64UrlStringify(JSON.stringify({ alg, typ: "dpop+jwt", jwk: publicJWK }))}.e30.AA`;
      await expect(verifyDPoPProof(proof, target, verification)).rejects.toHaveProperty(
        "code",
        "ERR_DPOP_INVALID",
      );
    },
  );

  it("rejects unencoded and unknown-critical proofs", async () => {
    const flattened = await new jose.FlattenedSign(new TextEncoder().encode("{}"))
      .setProtectedHeader({
        alg: "ES256",
        typ: "dpop+jwt",
        jwk: publicJWK,
        b64: false,
        crit: ["b64"],
      })
      .sign(privateKey);
    const proof = `${flattened.protected}.{}.${flattened.signature}`;
    await expect(verifyDPoPProof(proof, target, verification)).rejects.toHaveProperty(
      "code",
      "ERR_DPOP_INVALID",
    );
    const critical = await new jose.SignJWT({ iat, jti: "id", htm: target.method, htu: target.url })
      .setProtectedHeader({
        alg: "ES256",
        typ: "dpop+jwt",
        jwk: publicJWK,
        crit: ["extension"],
        extension: true,
      })
      .sign(privateKey, { crit: { extension: true } });
    await expect(verifyDPoPProof(critical, target, verification)).rejects.toHaveProperty(
      "code",
      "ERR_DPOP_INVALID",
    );
  });

  it.each([
    { algorithms: [] },
    { algorithms: ["HS256"] },
    { algorithms: ["none"] },
    { algorithms: null },
    { maxTokenAge: 0 },
    { maxTokenAge: -1 },
    { maxTokenAge: Infinity },
    { maxTokenAge: NaN },
    { maxTokenAge: "60" },
    { clockTolerance: -1 },
    { clockTolerance: Infinity },
    { clockTolerance: NaN },
    { clockTolerance: null },
    { currentDate: new Date(NaN) },
    { currentDate: null },
    { currentDate: "now" },
    { nonce: "with space" },
    { accessToken: { token: "abc" } },
    { accessToken: { thumbprint: "A".repeat(43) } },
    { accessToken: { token: "\u00e9", thumbprint: "A".repeat(43) } },
    { consumeProof: true },
  ])("rejects invalid verifier options %j", async (options) => {
    await expect(
      verifyDPoPProof(await foreignProof(), target, {
        ...verification,
        ...options,
      } as DPoPVerifyOptions),
    ).rejects.toHaveProperty("code", "ERR_INVALID_OPTION");
  });

  it.each([
    { algorithm: "HS256" },
    { algorithm: "none" },
    { jti: "" },
    { jti: null },
    { iat: null },
    { iat: NaN },
    { iat: Infinity },
    { iat: -1 },
    { nonce: "" },
    { nonce: 'quote"' },
    { accessToken: { token: "\u00e9" } },
    { keyPair: undefined },
  ])("rejects invalid creator options %j", async (options) => {
    await expect(
      createDPoPProof(target, { ...creation, ...options } as DPoPCreateOptions),
    ).rejects.toHaveProperty("code", "ERR_INVALID_OPTION");
  });

  it("checks algorithm policy before accepting a signature", async () => {
    await expect(
      verifyDPoPProof(await foreignProof(), target, { ...verification, algorithms: ["ES384"] }),
    ).rejects.toMatchObject({
      code: "ERR_DPOP_INVALID",
      cause: { code: "ERR_JWS_ALG_NOT_ALLOWED" },
    });
  });

  it("imports the embedded proof key without the JWK import cache", async () => {
    const get = vi.fn(() => undefined);
    const set = vi.fn();
    const proof = await foreignProof();
    const signature = proof.split(".")[2];
    const tampered =
      proof.slice(0, -signature.length) + (signature[0] === "A" ? "B" : "A") + signature.slice(1);
    configureJWKCache({ get, set });
    try {
      await expect(verifyDPoPProof(proof, target, verification)).resolves.toHaveProperty(
        "payload.jti",
        "foreign-proof",
      );
      await expect(verifyDPoPProof(tampered, target, verification)).rejects.toHaveProperty(
        "code",
        "ERR_DPOP_INVALID",
      );
    } finally {
      clearJWKCache();
    }
    expect(get).not.toHaveBeenCalled();
    expect(set).not.toHaveBeenCalled();
  });

  it("reads each verification option once, before the first await", async () => {
    const once = <T, U>(first: T, later: U) => {
      let reads = 0;
      return () => (reads++ === 0 ? first : later);
    };
    const withGetter = (name: string, get: () => unknown) =>
      Object.defineProperty({ ...verification }, name, { get, enumerable: true });
    const token = "access-token";
    const keyThumbprint = await jose.calculateJwkThumbprint(publicJWK);
    const proof = await foreignProof({ ath: await digestUrl(token) });
    await expect(
      verifyDPoPProof(
        await foreignProof({ iat: iat - 100 }),
        target,
        withGetter("maxTokenAge", once(60, NaN)),
      ),
    ).rejects.toHaveProperty("code", "ERR_DPOP_CLAIM_INVALID");
    await expect(
      verifyDPoPProof(proof, target, withGetter("nonce", once("required", undefined))),
    ).rejects.toHaveProperty("code", "ERR_DPOP_NONCE_INVALID");
    await expect(
      verifyDPoPProof(
        proof,
        target,
        withGetter(
          "consumeProof",
          once(() => false, undefined),
        ),
      ),
    ).rejects.toHaveProperty("code", "ERR_DPOP_REPLAY");
    await expect(
      verifyDPoPProof(
        proof,
        target,
        withGetter(
          "accessToken",
          once({ token: "other-token", thumbprint: keyThumbprint }, undefined),
        ),
      ),
    ).rejects.toHaveProperty("code", "ERR_DPOP_CLAIM_INVALID");
    const accessToken = { thumbprint: keyThumbprint };
    Object.defineProperty(accessToken, "token", {
      get: once("other-token", token),
      enumerable: true,
    });
    await expect(
      verifyDPoPProof(proof, target, {
        ...verification,
        accessToken: accessToken as { token: string; thumbprint: string },
      }),
    ).rejects.toHaveProperty("code", "ERR_DPOP_CLAIM_INVALID");
    const algorithms: DPoPVerifyOptions["algorithms"] = ["ES256"];
    const pending = verifyDPoPProof(proof, target, { ...verification, algorithms });
    algorithms[0] = "ES384";
    await expect(pending).resolves.toHaveProperty("thumbprint", keyThumbprint);
  });

  it("isolates the returned result from the replay callback", async () => {
    const proof = await foreignProof();
    const result = await verifyDPoPProof(proof, target, {
      ...verification,
      consumeProof: (accepted) => {
        accepted.payload.jti = "changed";
        accepted.thumbprint = "changed";
        return true;
      },
    });
    expect(result.payload.jti).toBe("foreign-proof");
    expect(result.thumbprint).toBe(await jose.calculateJwkThumbprint(publicJWK));
  });

  it("never consumes proofs failing signature, binding, claims, or policy checks", async () => {
    const consumeProof = vi.fn(() => true);
    const proof = await foreignProof();
    const signature = proof.split(".")[2];
    const tampered =
      proof.slice(0, -signature.length) + (signature[0] === "A" ? "B" : "A") + signature.slice(1);
    const cases: [string, Partial<DPoPVerifyOptions>, DPoPTarget?][] = [
      [tampered, {}],
      [proof, { algorithms: ["RS256"] }],
      [await foreignProof({ iat: iat - 100 }), {}],
      [proof, {}, { ...target, method: "GET" }],
      [proof, { nonce: "required" }],
      [
        proof,
        {
          accessToken: { token: "token", thumbprint: await jose.calculateJwkThumbprint(publicJWK) },
        },
      ],
    ];
    for (const [token, options, proofTarget = target] of cases) {
      await expect(
        verifyDPoPProof(token, proofTarget, { ...verification, ...options, consumeProof }),
      ).rejects.toBeInstanceOf(Error);
    }
    expect(consumeProof).not.toHaveBeenCalled();
  });

  it("reports a missing or different expected nonce only once every other check passes", async () => {
    const consumeProof = vi.fn(() => true);
    const binding = { token: "token", thumbprint: await jose.calculateJwkThumbprint(publicJWK) };
    const cases: [string, Partial<DPoPVerifyOptions>, string][] = [
      [await foreignProof(), {}, "ERR_DPOP_NONCE_INVALID"],
      [await foreignProof({ nonce: "other" }), {}, "ERR_DPOP_NONCE_INVALID"],
      [await foreignProof({ nonce: "with space" }), {}, "ERR_DPOP_CLAIM_INVALID"],
      [await foreignProof({ iat: iat - 100 }), {}, "ERR_DPOP_CLAIM_INVALID"],
      [await foreignProof(), { accessToken: binding }, "ERR_DPOP_CLAIM_INVALID"],
      [await foreignProof({}, { typ: "JWT" }), {}, "ERR_DPOP_INVALID"],
    ];
    for (const [proof, options, code] of cases) {
      await expect(
        verifyDPoPProof(proof, target, {
          ...verification,
          ...options,
          nonce: "required",
          consumeProof,
        }),
      ).rejects.toHaveProperty("code", code);
    }
    expect(consumeProof).not.toHaveBeenCalled();
  });

  it("throws only DPoP codes for proof failures, keeping the core error as cause", async () => {
    const proof = await foreignProof();
    const [header, payload] = proof.split(".");
    const resign = async (claims: Record<string, unknown>) =>
      new jose.CompactSign(new TextEncoder().encode(JSON.stringify(claims)))
        .setProtectedHeader({ alg: "ES256", typ: "dpop+jwt", jwk: publicJWK })
        .sign(privateKey);
    const invalid = {
      code: "ERR_DPOP_INVALID",
      cause: { code: expect.stringMatching(/^ERR_JWS_/) },
    };
    const claim = {
      code: "ERR_DPOP_CLAIM_INVALID",
      cause: { code: expect.stringMatching(/^ERR_JWT_/) },
    };
    const claims = { jti: "id", iat, htm: "POST", htu: target.url };
    const cases: [unknown, object][] = [
      [1, invalid],
      [`${header}.${payload}`, invalid],
      [`${header}.${payload}.AA`, invalid],
      [`${header}.%%%.${proof.split(".")[2]}`, invalid],
      [await resign({ ...claims, exp: "soon" }), claim],
      [await resign({ ...claims, exp: iat }), claim],
      [await resign({ ...claims, nbf: iat + 1 }), claim],
    ];
    for (const [token, expected] of cases) {
      const rejection = verifyDPoPProof(token as string, target, verification);
      await expect(rejection).rejects.toBeInstanceOf(JWTError);
      await expect(rejection).rejects.toMatchObject(expected);
      await expect(rejection.catch((error: JWTError) => error.cause)).resolves.toBeInstanceOf(
        JWTError,
      );
    }
  });

  it("fails closed for replay callback rejection, nonboolean return and thrown cause", async () => {
    const proof = await foreignProof();
    const cause = new Error("store unavailable");
    await expect(
      verifyDPoPProof(proof, target, {
        ...verification,
        consumeProof: async () => {
          throw cause;
        },
      }),
    ).rejects.toMatchObject({ code: "ERR_DPOP_REPLAY", cause });
    for (const value of [false, undefined, null, "yes", 1]) {
      await expect(
        verifyDPoPProof(proof, target, {
          ...verification,
          consumeProof: (() => value) as DPoPVerifyOptions["consumeProof"],
        }),
      ).rejects.toHaveProperty("code", "ERR_DPOP_REPLAY");
    }
    await expect(
      verifyDPoPProof(proof, target, { ...verification, consumeProof: async () => true }),
    ).resolves.toBeDefined();
  });

  it("allows a valid proof repeatedly when replay consumption is omitted", async () => {
    const proof = await foreignProof({ extension: { hello: "world" } });
    for (let count = 0; count < 2; count++) {
      await expect(verifyDPoPProof(proof, target, verification)).resolves.toHaveProperty(
        "payload.extension",
        { hello: "world" },
      );
    }
  });

  it("preserves unexpected delegated failures as typed errors with their cause", async () => {
    const throwing = {
      get method(): string {
        throw new RangeError("unexpected");
      },
      url: target.url,
    };
    await expect(
      verifyDPoPProof(await foreignProof(), throwing, verification),
    ).rejects.toMatchObject({
      code: "ERR_INVALID_OPTION",
      cause: expect.any(RangeError),
    });
    await expect(
      verifyDPoPProof(await foreignProof({ nbf: 1e308 }), target, verification),
    ).rejects.toMatchObject({
      code: "ERR_DPOP_CLAIM_INVALID",
      cause: expect.objectContaining({ code: "ERR_JWT_NBF" }),
    });
  });

  it("checks exact nonce and public key binding independently of the correct token hash", async () => {
    const token = "token";
    const proof = await foreignProof({ nonce: "nonce", ath: await digestUrl(token) });
    const binding = { token, thumbprint: await jose.calculateJwkThumbprint(publicJWK) };
    await expect(
      verifyDPoPProof(proof, target, { ...verification, nonce: "nonce", accessToken: binding }),
    ).resolves.toBeDefined();
    await expect(
      verifyDPoPProof(proof, target, { ...verification, nonce: "Nonce", accessToken: binding }),
    ).rejects.toHaveProperty("code", "ERR_DPOP_NONCE_INVALID");
    const other = await generateJWK("ES256");
    await expect(
      verifyDPoPProof(proof, target, {
        ...verification,
        accessToken: { token, thumbprint: await jose.calculateJwkThumbprint(other.publicKey) },
      }),
    ).rejects.toHaveProperty("code", "ERR_DPOP_CLAIM_INVALID");
  });

  it.each(["", "a.b", "a.b.c.d", "e30.e30.", "[].e30.AA", "eyJhbGciOiJFUzI1NiJ9.***.AA"])(
    "rejects malformed compact proof %j",
    async (proof) => {
      await expect(verifyDPoPProof(proof, target, verification)).rejects.toHaveProperty(
        "code",
        "ERR_DPOP_INVALID",
      );
    },
  );

  it("rejects non-object payloads even with a valid signature", async () => {
    const proof = await new jose.CompactSign(new TextEncoder().encode("[]"))
      .setProtectedHeader({ alg: "ES256", typ: "dpop+jwt", jwk: publicJWK })
      .sign(privateKey);
    await expect(verifyDPoPProof(proof, target, verification)).rejects.toHaveProperty(
      "code",
      "ERR_DPOP_INVALID",
    );
  });

  it("rejects the wrong bound key even when the token hash matches, before replay consumption", async () => {
    const token = "access-token";
    const otherPair = await generateJWK("ES256");
    const consumeProof = vi.fn(() => true);
    const proof = await foreignProof({ ath: await digestUrl(token) });
    await expect(
      verifyDPoPProof(proof, target, {
        ...verification,
        accessToken: {
          token,
          thumbprint: await jose.calculateJwkThumbprint(otherPair.publicKey),
        },
        consumeProof,
      }),
    ).rejects.toHaveProperty("code", "ERR_DPOP_CLAIM_INVALID");
    expect(consumeProof).not.toHaveBeenCalled();
  });

  it("awaits the atomic store's decision for concurrent uses of one proof", async () => {
    const proof = await foreignProof();
    const seen = new Set<string>();
    const consumeProof: NonNullable<DPoPVerifyOptions["consumeProof"]> = async ({
      payload,
      thumbprint,
    }) => {
      await Promise.resolve();
      const key = JSON.stringify([thumbprint, payload.jti]);
      if (seen.has(key)) return false;
      seen.add(key);
      return true;
    };
    const results = await Promise.allSettled(
      Array.from({ length: 8 }, () =>
        verifyDPoPProof(proof, target, { ...verification, consumeProof }),
      ),
    );
    expect(results.filter((result) => result.status === "fulfilled")).toHaveLength(1);
    const rejected = results.filter((result) => result.status === "rejected");
    expect(rejected).toHaveLength(7);
    for (const result of rejected) {
      expect(result.reason).toHaveProperty("code", "ERR_DPOP_REPLAY");
    }
  });
});
