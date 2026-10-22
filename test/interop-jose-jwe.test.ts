import * as jose from "jose";
import { describe, it, expect } from "vitest";
import { textEncoder, textDecoder } from "unsecure";
import { base64UrlStringify, base64UrlParse } from "../src/core/utils/base64.ts";
import {
  encrypt,
  decrypt,
  encryptMulti,
  decryptMulti,
  generalToFlattened,
  JWTError,
} from "../src/core/jwe.ts";
import {
  generateKey,
  generateJWK,
  importKey,
  exportKey,
  importPEM,
  exportPEM,
  thumbprint,
} from "../src/core/jwk.ts";
import type {
  JWK,
  JWK_oct,
  JWEEncryptJWK,
  JWEDecryptJWK,
  JWEDecryptOptions,
  JWKPEMAlgorithm,
  GenerateKeyAlgorithm,
  GenerateKeyOptions,
  KeyManagementAlgorithm,
  ContentEncryptionAlgorithm,
  JWEGeneralSerialization,
  JWEFlattenedSerialization,
} from "../src/core/types/index.ts";
import { rsa, ec } from "./keys.ts";

type Pair = { priv: JWK; pub: JWK };
type JoseKey = Uint8Array | jose.JWK;
type Probe = {
  token: () => Promise<string>;
  ours?: JWEDecryptOptions;
  theirs?: jose.DecryptOptions;
  keys?: () => Promise<[JWEDecryptJWK | string, JoseKey]>;
};

const PASSWORD = "correct horse battery staple";
const P2C = 1000;
const bytes = textEncoder.encode("raw bytes payload é\u0000ÿ");
const claims = { sub: "u1", role: "admin" };

const THUMBPRINT_ALGS = ["HS256", "RS256", "PS256", "ES256", "ES384", "ES512", "EdDSA", "Ed25519"];

// Every alg × enc pair below is supported by both libraries on Node, A192KW included; nothing is skipped.
const JWE_ALGS: KeyManagementAlgorithm[] = [
  "dir",
  "A128KW",
  "A192KW",
  "A256KW",
  "A128GCMKW",
  "A256GCMKW",
  "RSA-OAEP-256",
  "RSA-OAEP-384",
  "RSA-OAEP-512",
  "ECDH-ES",
  "ECDH-ES+A128KW",
  "ECDH-ES+A256KW",
  "PBES2-HS256+A128KW",
  "PBES2-HS512+A256KW",
];
const ENCS: ContentEncryptionAlgorithm[] = ["A128GCM", "A256GCM", "A128CBC-HS256", "A256CBC-HS512"];
const JWE_MATRIX = JWE_ALGS.flatMap((alg) => ENCS.map((enc) => [alg, enc] as const));

describe.concurrent("interop with jose: JWE compact", () => {
  it.each(JWE_MATRIX)("%s + %s: unjwt encrypt -> jose compactDecrypt", async (alg, enc) => {
    const k = await jweKeys(alg, enc);
    const token = await encrypt(claims, k.uEnc as JWEEncryptJWK, {
      alg,
      enc,
      ...(alg.startsWith("PBES2") ? { p2c: P2C } : {}),
    });
    const res = await jose.compactDecrypt(token, k.jDec, {
      keyManagementAlgorithms: [alg],
      contentEncryptionAlgorithms: [enc],
    });
    expect(JSON.parse(textDecoder.decode(res.plaintext))).toEqual(claims);
    expect(res.protectedHeader).toEqual(headerOf(token));
    expect(res.protectedHeader).toMatchObject({ alg, enc });
  });

  it.each(JWE_MATRIX)("%s + %s: jose CompactEncrypt -> unjwt decrypt", async (alg, enc) => {
    const k = await jweKeys(alg, enc);
    const builder = new jose.CompactEncrypt(textEncoder.encode(JSON.stringify(claims)));
    builder.setProtectedHeader({ alg, enc, kid: "k1" });
    if (alg.startsWith("PBES2")) builder.setKeyManagementParameters({ p2c: P2C });
    const token = await builder.encrypt(k.jEnc);
    const res = await decrypt(token, k.uDec as JWEDecryptJWK, {
      algorithms: [alg],
      encryptionAlgorithms: [enc],
    });
    expect(res.payload).toEqual(claims);
    expect(res.protectedHeader).toEqual(headerOf(token));
  });
});

describe.concurrent("interop with jose: JWE JSON serialization", () => {
  it("General, 2 recipients (A256KW + RSA-OAEP-256): unjwt encryptMulti -> jose", async () => {
    const [kw, rs] = await Promise.all([keysFor("A256KW"), keysFor("RSA-OAEP-256")]);
    const jwe = await encryptMulti(
      claims,
      [{ key: kw.priv as JWEEncryptJWK }, { key: rs.pub as JWEEncryptJWK }],
      { enc: "A256GCM", aad: "external" },
    );
    for (const key of [kw.priv, rs.priv]) {
      const res = await jose.generalDecrypt(jwe, joseKey(key));
      expect(JSON.parse(textDecoder.decode(res.plaintext))).toEqual(claims);
      expect(textDecoder.decode(res.additionalAuthenticatedData)).toBe("external");
    }
  });

  it("General, 2 recipients (A256KW + RSA-OAEP-256): jose GeneralEncrypt -> unjwt", async () => {
    const [kw, rs] = await Promise.all([keysFor("A256KW"), keysFor("RSA-OAEP-256")]);
    const builder = new jose.GeneralEncrypt(textEncoder.encode(JSON.stringify(claims)))
      .setProtectedHeader({ enc: "A256GCM" })
      .setAdditionalAuthenticatedData(textEncoder.encode("external"));
    builder.addRecipient(joseKey(kw.priv)).setUnprotectedHeader({ alg: "A256KW", kid: "kw" });
    builder.addRecipient(joseKey(rs.pub)).setUnprotectedHeader({ alg: "RSA-OAEP-256" });
    const jwe = (await builder.encrypt()) as JWEGeneralSerialization;
    const a = await decryptMulti(jwe, kw.priv as JWEDecryptJWK);
    expect(a).toMatchObject({ payload: claims, recipientIndex: 0 });
    const b = await decryptMulti(jwe, rs.priv as JWEDecryptJWK);
    expect(b).toMatchObject({ payload: claims, recipientIndex: 1 });
  });

  it("Flattened: unjwt -> jose", async () => {
    const kw = await keysFor("A128KW");
    const flat = generalToFlattened(
      await encryptMulti(claims, [{ key: kw.priv as JWEEncryptJWK }], { enc: "A128CBC-HS256" }),
    );
    const res = await jose.flattenedDecrypt(flat, joseKey(kw.priv));
    expect(JSON.parse(textDecoder.decode(res.plaintext))).toEqual(claims);
  });

  it("Flattened: jose -> unjwt", async () => {
    const ecdh = await keysFor("ECDH-ES+A256KW");
    const flat = await new jose.FlattenedEncrypt(bytes)
      .setProtectedHeader({ alg: "ECDH-ES+A256KW", enc: "A256GCM" })
      .encrypt(joseKey(ecdh.pub));
    const res = await decryptMulti(flat as JWEFlattenedSerialization, ecdh.priv as JWEDecryptJWK, {
      payload: "bytes",
    });
    expect(res.payload).toEqual(bytes);
  });

  // RFC 7516 §7.2.2 — a Flattened `dir` / `ECDH-ES` token carries neither `header` nor `encrypted_key`.
  it.each([
    ["dir", "A256GCM"],
    ["ECDH-ES", "A256GCM"],
  ] as const)("Flattened %s: jose -> unjwt", async (alg, enc) => {
    const k = await jweKeys(alg, enc);
    const flat = await new jose.FlattenedEncrypt(bytes)
      .setProtectedHeader({ alg, enc })
      .encrypt(k.jEnc);
    expect(flat).not.toHaveProperty("header");
    expect(flat).not.toHaveProperty("encrypted_key");
    const res = await decryptMulti(flat as JWEFlattenedSerialization, k.uDec as JWEDecryptJWK, {
      payload: "bytes",
    });
    expect(res.payload).toEqual(bytes);
    expect(res.protectedHeader).toMatchObject({ alg, enc });
  });

  // RFC 7516 §7.2.1 lets `enc` sit in the shared unprotected header.
  it("General JWE with enc in shared unprotected header: both accept", async () => {
    const key = (await keysFor("A256KW")).priv;
    const builder = new jose.GeneralEncrypt(bytes).setSharedUnprotectedHeader({ enc: "A256GCM" });
    builder.addRecipient(joseKey(key)).setUnprotectedHeader({ alg: "A256KW" });
    const jwe = await builder.encrypt();
    const ours = await decryptMulti(jwe as JWEGeneralSerialization, key as JWEDecryptJWK, {
      payload: "bytes",
    });
    expect(ours).toMatchObject({ payload: bytes, sharedUnprotectedHeader: { enc: "A256GCM" } });
    await expect(jose.generalDecrypt(jwe, joseKey(key))).resolves.toBeDefined();
  });
});

describe.concurrent("interop with jose: JWK", () => {
  const ASYM: [string, GenerateKeyAlgorithm, Pick<GenerateKeyOptions, "namedCurve">?][] = [
    ["RS256", "RS256"],
    ["PS256", "PS256"],
    ["RSA-OAEP-256", "RSA-OAEP-256"],
    ["ES256", "ES256"],
    ["ES384", "ES384"],
    ["ES512", "ES512"],
    ["Ed25519", "Ed25519"],
    ["ECDH-ES P-256", "ECDH-ES"],
    ["ECDH-ES X25519", "ECDH-ES", { namedCurve: "X25519" }],
  ];

  it.each(ASYM)("%s: exportKey/importKey match jose exportJWK/importJWK", async (_, alg, opts) => {
    const pair = (await generateKey(alg, { ...opts, toJWK: false })) as CryptoKeyPair;
    for (const key of [pair.privateKey, pair.publicKey]) {
      const ours = await exportKey(key);
      const theirs = await jose.exportJWK(key);
      expect(stripMeta(ours)).toEqual(theirs);
      const viaJose = await jose.importJWK(ours, alg, { extractable: true });
      expect(await jose.exportJWK(viaJose)).toEqual(theirs);
      const viaUnjwt = await importKey(theirs as JWK, { alg, extractable: true });
      expect(stripMeta(await exportKey(viaUnjwt as CryptoKey))).toEqual(theirs);
    }
  });

  it.each(["HS256", "A128KW", "A256GCM"] as const)("oct %s: import/export parity", async (alg) => {
    const key = await generateKey(alg);
    const ours = await exportKey<JWK_oct>(key);
    expect(stripMeta(ours)).toEqual(await jose.exportJWK(key));
    expect(await jose.importJWK(ours as jose.JWK)).toEqual(await importKey(ours));
  });

  it.each([...THUMBPRINT_ALGS, "RSA-OAEP-256", "ECDH-ES", "A256KW", "A128CBC-HS256"])(
    "%s: thumbprint() and generated kid equal jose calculateJwkThumbprint",
    async (alg) => {
      const { priv, pub } = await keysFor(alg);
      const expected = await jose.calculateJwkThumbprint(pub, "sha256");
      expect(await thumbprint(pub)).toBe(expected);
      expect(await thumbprint(priv)).toBe(expected);
      expect(pub.kid).toBe(expected);
    },
  );

  const PEMS: [string, JWKPEMAlgorithm, () => Promise<Pair>][] = [
    ["RSA fixture", "RS256", async () => ({ priv: rsa.jwk.private, pub: rsa.jwk.public })],
    ["EC fixture", "ES256", async () => ({ priv: ec.jwk.private, pub: ec.jwk.public })],
    ["Ed25519", "Ed25519", () => keysFor("Ed25519")],
    ["ES384", "ES384", () => keysFor("ES384")],
  ];

  it.each(PEMS)("%s: exportPEM/importPEM match jose SPKI/PKCS8", async (_, alg, get) => {
    const { priv, pub } = await get();
    const pubKey = await jose.importJWK(pub, alg, { extractable: true });
    const privKey = await jose.importJWK(priv, alg, { extractable: true });
    const spki = await jose.exportSPKI(pubKey as CryptoKey);
    const pkcs8 = await jose.exportPKCS8(privKey as CryptoKey);
    expect(pemBody(await exportPEM(pub))).toBe(pemBody(spki));
    expect(pemBody(await exportPEM(priv))).toBe(pemBody(pkcs8));
    expect(stripMeta(await importPEM(spki, alg))).toEqual(await jose.exportJWK(pubKey));
    expect(stripMeta(await importPEM(pkcs8, alg))).toEqual(await jose.exportJWK(privKey));
    const back = await jose.importSPKI(await exportPEM(pub), alg, { extractable: true });
    expect(await jose.exportJWK(back)).toEqual(stripMeta(pub));
    const backPriv = await jose.importPKCS8(await exportPEM(priv), alg, { extractable: true });
    expect(await jose.exportJWK(backPriv)).toEqual(stripMeta(priv));
  });
});

describe.concurrent("interop with jose: JWE rejection parity", () => {
  const kw = async () => (await keysFor("A256KW")).priv;
  const dir = async () => (await keysFor("A256GCM")).priv;
  const kwToken = once(async () => encrypt(claims, (await kw()) as JWEEncryptJWK));
  const dirToken = once(async () => encrypt(claims, (await dir()) as JWEEncryptJWK));
  const dirKeys = async (): Promise<[JWEDecryptJWK, JoseKey]> => {
    const key = await dir();
    return [key as JWEDecryptJWK, joseKey(key)];
  };
  const pwKeys = async (): Promise<[string, JoseKey]> => [PASSWORD, textEncoder.encode(PASSWORD)];
  const pbes2Only = ["PBES2-HS256+A128KW"];
  const pbes2 = (p2c: number) =>
    once(() =>
      new jose.CompactEncrypt(textEncoder.encode(JSON.stringify(claims)))
        .setProtectedHeader({ alg: "PBES2-HS256+A128KW", enc: "A128GCM" })
        .setKeyManagementParameters({ p2c })
        .encrypt(textEncoder.encode(PASSWORD)),
    );
  const critToken = once(async () =>
    new jose.CompactEncrypt(textEncoder.encode(JSON.stringify(claims)))
      .setProtectedHeader({ "alg": "A256KW", "enc": "A256GCM", "crit": ["x-foo"], "x-foo": 1 })
      .encrypt(joseKey(await kw()), { crit: { "x-foo": true } }),
  );
  const zipped = once(async () =>
    new jose.CompactEncrypt(textEncoder.encode(JSON.stringify(claims)))
      .setProtectedHeader({ alg: "dir", enc: "A256GCM", zip: "DEF" })
      .encrypt(joseKey(await dir())),
  );

  const controls: [string, Probe][] = [
    ["A256KW token", { token: kwToken }],
    ["dir token", { token: dirToken, keys: dirKeys }],
    [
      "crit x-foo when recognised",
      {
        token: critToken,
        ours: { recognizedHeaders: ["x-foo"] },
        theirs: { crit: { "x-foo": true } },
      },
    ],
    [
      "PBES2 p2c=10000 within limits",
      { token: pbes2(10_000), keys: pwKeys, theirs: { keyManagementAlgorithms: pbes2Only } },
    ],
  ];

  const rejects: [string, Probe][] = [
    [
      "dir with non-empty encrypted_key",
      { token: async () => withSegment(await dirToken(), 1, new Uint8Array(32)), keys: dirKeys },
    ],
    ["GCM tag truncated by one byte", { token: async () => truncateTag(await kwToken()) }],
    ["tampered ciphertext", { token: async () => tamper(await kwToken(), 3) }],
    ["crit names unknown extension", { token: critToken }],
    [
      "enc outside allowlist",
      {
        token: kwToken,
        ours: { encryptionAlgorithms: ["A128GCM"] },
        theirs: { contentEncryptionAlgorithms: ["A128GCM"] },
      },
    ],
    [
      "alg outside allowlist",
      {
        token: kwToken,
        ours: { algorithms: ["A128KW"] },
        theirs: { keyManagementAlgorithms: ["A128KW"] },
      },
    ],
    [
      "PBES2 p2c above consumer limit",
      {
        token: pbes2(10_000),
        keys: pwKeys,
        ours: { maxIterations: 5000 },
        theirs: { maxPBES2Count: 5000, keyManagementAlgorithms: pbes2Only },
      },
    ],
  ];

  const divergences: [string, "accepts" | "rejects", Probe][] = [
    // unjwt does not implement zip and rejects; jose 6.2 inflates DEF (250 kB cap) and accepts.
    ['zip:"DEF"', "rejects", { token: zipped, keys: dirKeys }],
    // unjwt rejects p2c below the RFC 7518 §4.8.1.2 floor of 1000; jose has no floor.
    [
      "PBES2 p2c=500 under defaults",
      "rejects",
      { token: pbes2(500), keys: pwKeys, theirs: { keyManagementAlgorithms: pbes2Only } },
    ],
    // unjwt's default p2c ceiling is the 600_000 it mints by default; jose's default maxPBES2Count is 10_000.
    [
      "PBES2 p2c=20000 under defaults",
      "accepts",
      { token: pbes2(20_000), keys: pwKeys, theirs: { keyManagementAlgorithms: pbes2Only } },
    ],
  ];

  it.each(controls)("control, %s: both accept", async (_, probe) => {
    const [ours, theirs] = await consumers(probe);
    await expect(ours()).resolves.toBeDefined();
    await expect(theirs()).resolves.toBeDefined();
  });

  it.each(rejects)("%s: both reject", async (_, probe) => {
    const [ours, theirs] = await consumers(probe);
    await expect(ours()).rejects.toThrow(JWTError);
    await expect(theirs()).rejects.toThrow(Error);
  });

  describe("divergences from jose", () => {
    it.each(divergences)("%s: unjwt %s, jose the opposite", async (_, expected, probe) => {
      const [ours, theirs] = await consumers(probe);
      expect(await outcome(ours)).toBe(expected);
      expect(await outcome(theirs)).toBe(expected === "accepts" ? "rejects" : "accepts");
    });
  });
});

async function consumers(probe: Probe): Promise<[() => Promise<unknown>, () => Promise<unknown>]> {
  const token = await probe.token();
  const kw = (await keysFor("A256KW")).priv;
  const [ours, theirs] = probe.keys ? await probe.keys() : [kw as JWEDecryptJWK, joseKey(kw)];
  return [
    () => decrypt(token, ours as JWEDecryptJWK, probe.ours),
    () => jose.compactDecrypt(token, theirs, probe.theirs),
  ];
}

function outcome(run: () => Promise<unknown>): Promise<"accepts" | "rejects"> {
  return run().then(
    () => "accepts",
    () => "rejects",
  );
}

function once<T>(fn: () => Promise<T>): () => Promise<T> {
  let pending: Promise<T> | undefined;
  return () => (pending ??= fn());
}

const keyCache = new Map<string, Promise<Pair>>();

function keysFor(alg: string): Promise<Pair> {
  let pending = keyCache.get(alg);
  if (!pending) {
    pending = generateJWK(alg as GenerateKeyAlgorithm).then((k) => {
      const generated = k as JWK | { privateKey: JWK; publicKey: JWK };
      return "privateKey" in generated
        ? { priv: generated.privateKey, pub: generated.publicKey }
        : { priv: generated, pub: generated };
    });
    keyCache.set(alg, pending);
  }
  return pending;
}

async function jweKeys(alg: KeyManagementAlgorithm, enc: ContentEncryptionAlgorithm) {
  if (alg.startsWith("PBES2")) {
    const password = textEncoder.encode(PASSWORD);
    return { uEnc: PASSWORD, uDec: PASSWORD, jEnc: password, jDec: password };
  }
  const { priv, pub } = await keysFor(alg === "dir" ? enc : alg);
  return { uEnc: pub, uDec: priv, jEnc: joseKey(pub), jDec: joseKey(priv) };
}

function joseKey(jwk: JWK): JoseKey {
  return jwk.kty === "oct" ? octBytes(jwk) : jwk;
}

function octBytes(jwk: JWK): Uint8Array<ArrayBuffer> {
  return base64UrlParse((jwk as JWK_oct).k, { returnAs: "uint8array" });
}

function headerOf(token: string): Record<string, unknown> {
  return JSON.parse(base64UrlParse(token.split(".")[0]));
}

function stripMeta(jwk: object): Record<string, unknown> {
  const {
    alg: _a,
    key_ops: _k,
    ext: _e,
    kid: _i,
    use: _u,
    ...rest
  } = jwk as Record<string, unknown>;
  return rest;
}

function pemBody(pem: string): string {
  return pem.replace(/-----[^-]+-----|\s/g, "");
}

function withSegment(token: string, index: number, value: Uint8Array): string {
  const parts = token.split(".");
  parts[index] = base64UrlStringify(value);
  return parts.join(".");
}

function tamper(token: string, index: number): string {
  const segment = base64UrlParse(token.split(".")[index], { returnAs: "uint8array" });
  segment[0] ^= 1;
  return withSegment(token, index, segment);
}

function truncateTag(token: string): string {
  const tag = base64UrlParse(token.split(".")[4], { returnAs: "uint8array" });
  return withSegment(token, 4, tag.slice(0, -1));
}
