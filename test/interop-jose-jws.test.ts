import * as jose from "jose";
import { describe, it, expect } from "vitest";
import { textEncoder, textDecoder } from "unsecure";
import { base64UrlStringify, base64UrlParse } from "../src/utils/base64.ts";
import {
  sign,
  verify,
  signMulti,
  verifyMulti,
  verifyMultiAll,
  generalToFlattenedJWS,
  JWTError,
} from "../src/core/jws/index.ts";
import { generateJWK } from "../src/core/jwk/index.ts";
import type {
  JWK,
  JWK_oct,
  JWSAlgorithm,
  JWSSignJWK,
  JWSVerifyJWK,
  JWSVerifyOptions,
  GenerateKeyAlgorithm,
  JWSGeneralSerialization,
  JWSFlattenedSerialization,
} from "../src/core/types/index.ts";
import { rsa } from "./keys.ts";

type Pair = { priv: JWK; pub: JWK };
type JoseKey = Uint8Array | jose.JWK | CryptoKey;
type Probe = {
  token: () => Promise<string>;
  ours?: JWSVerifyOptions;
  theirs?: jose.JWTVerifyOptions;
  keys?: () => Promise<[JWSVerifyJWK | Uint8Array<ArrayBuffer>, JoseKey]>;
};

const ISS = "https://issuer.example";
const AUD = "interop-aud";
const bytes = textEncoder.encode("raw bytes payload é\u0000ÿ");
const claims = { sub: "u1", role: "admin" };

const JWS_ALGS: JWSAlgorithm[] = [
  "HS256",
  "HS384",
  "HS512",
  "RS256",
  "RS384",
  "RS512",
  "PS256",
  "PS384",
  "PS512",
  "ES256",
  "ES384",
  "ES512",
  "EdDSA",
  "Ed25519",
];

describe.concurrent("interop with jose: JWS compact", () => {
  it.each(JWS_ALGS)("%s: unjwt sign -> jose compactVerify (bytes)", async (alg) => {
    const { priv, pub } = await keysFor(alg);
    const token = await sign(bytes, priv as JWSSignJWK, { protectedHeader: { kid: "k1" } });
    const res = await jose.compactVerify(token, joseKey(pub));
    expect(res.payload).toEqual(bytes);
    expect(res.protectedHeader).toEqual(headerOf(token));
    expect(res.protectedHeader).toMatchObject({ alg, kid: "k1" });
  });

  it.each(JWS_ALGS)("%s: jose CompactSign -> unjwt verify (bytes)", async (alg) => {
    const { priv, pub } = await keysFor(alg);
    const token = await new jose.CompactSign(bytes)
      .setProtectedHeader({ alg, kid: "k1" })
      .sign(joseKey(priv));
    const res = await verify(token, pub as JWSVerifyJWK, { payload: "bytes" });
    expect(res.payload).toEqual(bytes);
    expect(res.protectedHeader).toEqual({ alg, kid: "k1" });
  });

  it.each(JWS_ALGS)("%s: unjwt sign JWT -> jose jwtVerify", async (alg) => {
    const { priv, pub } = await keysFor(alg);
    const token = await sign({ ...claims, iss: ISS, aud: AUD }, priv as JWSSignJWK, {
      expiresIn: "1h",
    });
    const res = await jose.jwtVerify(token, joseKey(pub), {
      issuer: ISS,
      audience: AUD,
      algorithms: [alg],
    });
    expect(res.payload).toMatchObject(claims);
    expect(res.payload.exp! - res.payload.iat!).toBe(3600);
    expect(res.protectedHeader.typ).toBe("JWT");
  });

  it.each(JWS_ALGS)("%s: jose SignJWT -> unjwt verify with claims validation", async (alg) => {
    const { priv, pub } = await keysFor(alg);
    const token = await new jose.SignJWT(claims)
      .setProtectedHeader({ alg, typ: "JWT" })
      .setIssuer(ISS)
      .setAudience(AUD)
      .setIssuedAt()
      .setExpirationTime("1h")
      .sign(joseKey(priv));
    const res = await verify(token, pub as JWSVerifyJWK, {
      issuer: ISS,
      audience: AUD,
      algorithms: [alg],
      typ: "JWT",
    });
    expect(res.payload).toMatchObject({ ...claims, iss: ISS, aud: AUD });
  });
});

describe.concurrent("interop with jose: JWS JSON serialization", () => {
  it("General, 2 signatures (ES256 + RS256): unjwt signMulti -> jose", async () => {
    const [es, rs] = await Promise.all([keysFor("ES256"), keysFor("RS256")]);
    const jws = await signMulti(bytes, [
      { key: es.priv as JWSSignJWK, protectedHeader: { kid: "es" } },
      { key: rs.priv as JWSSignJWK, protectedHeader: { kid: "rs" }, unprotectedHeader: { x: 1 } },
    ]);
    for (const [i, pub] of [es.pub, rs.pub].entries()) {
      const res = await jose.flattenedVerify(
        { payload: jws.payload, ...jws.signatures[i] },
        joseKey(pub),
      );
      expect(res.payload).toEqual(bytes);
    }
    const general = await jose.generalVerify(jws, joseKey(rs.pub));
    expect(general.unprotectedHeader).toEqual({ x: 1 });
  });

  it("General, 2 signatures (ES256 + RS256): jose GeneralSign -> unjwt", async () => {
    const [es, rs] = await Promise.all([keysFor("ES256"), keysFor("RS256")]);
    const sig = new jose.GeneralSign(bytes);
    sig.addSignature(joseKey(es.priv)).setProtectedHeader({ alg: "ES256", kid: "es" });
    sig
      .addSignature(joseKey(rs.priv))
      .setProtectedHeader({ alg: "RS256", kid: "rs" })
      .setUnprotectedHeader({ x: 1 });
    const jws = (await sig.sign()) as JWSGeneralSerialization;
    const outcomes = await verifyMultiAll(
      jws,
      ({ header }) => (header.kid === "es" ? es.pub : rs.pub),
      {
        payload: "bytes",
      },
    );
    expect(outcomes.map((o) => o.verified)).toEqual([true, true]);
    const one = await verifyMulti(jws, rs.pub as JWSVerifyJWK, { payload: "bytes" });
    expect(one).toMatchObject({ payload: bytes, signerIndex: 1, signerHeader: { x: 1 } });
  });

  it("Flattened: unjwt -> jose", async () => {
    const ed = await keysFor("EdDSA");
    const flat = generalToFlattenedJWS(await signMulti(claims, [{ key: ed.priv as JWSSignJWK }]));
    const res = await jose.flattenedVerify(flat, joseKey(ed.pub));
    expect(JSON.parse(textDecoder.decode(res.payload))).toEqual(claims);
  });

  it("Flattened: jose -> unjwt", async () => {
    const ed = await keysFor("EdDSA");
    const flat = await new jose.FlattenedSign(bytes)
      .setProtectedHeader({ alg: "EdDSA" })
      .sign(joseKey(ed.priv));
    const res = await verifyMulti(flat as JWSFlattenedSerialization, ed.pub as JWSVerifyJWK, {
      payload: "bytes",
    });
    expect(res.payload).toEqual(bytes);
  });

  // RFC 7515 §7.2.1 lets `alg` sit in the per-signature unprotected header.
  it("General JWS with alg only in unprotected header: both accept", async () => {
    const es = await keysFor("ES256");
    const sig = new jose.GeneralSign(bytes);
    sig
      .addSignature(joseKey(es.priv))
      .setProtectedHeader({ kid: "es" })
      .setUnprotectedHeader({ alg: "ES256" });
    const jws = (await sig.sign()) as JWSGeneralSerialization;
    const ours = await verifyMulti(jws, es.pub as JWSVerifyJWK, { payload: "bytes" });
    expect(ours).toMatchObject({ payload: bytes, signerHeader: { alg: "ES256" } });
    await expect(
      jose.generalVerify(jws as jose.GeneralJWSInput, joseKey(es.pub)),
    ).resolves.toBeDefined();
  });

  it("Flattened JWS without protected header: both accept", async () => {
    const es = await keysFor("ES256");
    const flat = (await new jose.FlattenedSign(bytes)
      .setUnprotectedHeader({ alg: "ES256" })
      .sign(joseKey(es.priv))) as JWSFlattenedSerialization;
    const ours = await verifyMulti(flat, es.pub as JWSVerifyJWK, { payload: "bytes" });
    expect(ours.payload).toEqual(bytes);
    await expect(
      jose.flattenedVerify(flat as jose.FlattenedJWSInput, joseKey(es.pub)),
    ).resolves.toBeDefined();
  });
});

describe.concurrent("interop with jose: RFC 7797 unencoded payload", () => {
  const text = "unencoded $ payload";
  const dotted = "unencoded.payload.with dots";

  it("compact b64:false: unjwt -> jose (crit added automatically)", async () => {
    const { priv } = await keysFor("HS256");
    const token = await sign(text, priv as JWSSignJWK, { protectedHeader: { b64: false } });
    expect(token.split(".")[1]).toBe(text);
    const res = await jose.compactVerify(token, joseKey(priv));
    expect(textDecoder.decode(res.payload)).toBe(text);
    expect(res.protectedHeader).toMatchObject({ b64: false, crit: ["b64"] });
  });

  it("compact b64:false: jose (detached Flattened, re-attached) -> unjwt", async () => {
    const { priv } = await keysFor("HS256");
    const flat = await new jose.FlattenedSign(textEncoder.encode(text))
      .setProtectedHeader({ alg: "HS256", b64: false, crit: ["b64"] })
      .sign(joseKey(priv));
    expect(flat.payload).toBe("");
    const token = `${flat.protected}.${text}.${flat.signature}`;
    const res = await verify(token, priv as JWSVerifyJWK, { payload: "string" });
    expect(res.payload).toBe(text);
  });

  it("Flattened b64:false with '.' in payload: unjwt -> jose", async () => {
    const es = await keysFor("ES256");
    const flat = generalToFlattenedJWS(
      await signMulti(dotted, [{ key: es.priv as JWSSignJWK, protectedHeader: { b64: false } }]),
    );
    expect(flat.payload).toBe(dotted);
    const res = await jose.flattenedVerify(flat, joseKey(es.pub));
    expect(textDecoder.decode(res.payload)).toBe(dotted);
  });

  it("Flattened b64:false with '.' in payload: jose (detached, re-attached) -> unjwt", async () => {
    const es = await keysFor("ES256");
    const flat = await new jose.FlattenedSign(textEncoder.encode(dotted))
      .setProtectedHeader({ alg: "ES256", b64: false, crit: ["b64"] })
      .sign(joseKey(es.priv));
    expect(flat.payload).toBe("");
    const attached = { ...flat, payload: dotted } as JWSFlattenedSerialization;
    const res = await verifyMulti(attached, es.pub as JWSVerifyJWK, { payload: "string" });
    expect(res.payload).toBe(dotted);
  });
});

describe.concurrent("interop with jose: JWS rejection parity", () => {
  const now = Math.floor(Date.now() / 1000);
  const hs = async () => (await keysFor("HS256")).priv;
  const good = once(async () => sign(claims, (await hs()) as JWSSignJWK));
  const forged = async (header: unknown, payload: string = seg(claims)) =>
    forgeHS(header, payload, octBytes(await hs()));
  const urlChars = once(async () => {
    for (let i = 0; ; i++) {
      const t = await sign({ sub: `x${i}` }, (await hs()) as JWSSignJWK);
      if (/[-_]/.test(t.split(".")[2])) return t.replaceAll("-", "+").replaceAll("_", "/");
    }
  });
  const shortSecret = new Uint8Array(16).fill(7);

  const controls: [string, Probe][] = [
    ["unjwt-signed HS256 JWT", { token: good }],
    ["hand-forged HS256 JWT", { token: () => forged({ alg: "HS256" }, seg({ exp: now + 60 })) }],
  ];

  const rejects: [string, Probe][] = [
    ['alg "none"', { token: async () => `${seg({ alg: "none" })}.${seg(claims)}.` }],
    ["2 segments", { token: async () => (await good()).split(".").slice(0, 2).join(".") }],
    ["4 segments", { token: async () => `${await good()}.AAAA` }],
    ["'+'/'/' in signature", { token: urlChars }],
    ["tampered signature", { token: async () => tamper(await good(), 2) }],
    [
      "crit names unknown extension",
      { token: () => forged({ "alg": "HS256", "crit": ["x-foo"], "x-foo": 1 }) },
    ],
    ['crit names registered "alg"', { token: () => forged({ alg: "HS256", crit: ["alg"] }) }],
    ['crit:["b64"] with b64 absent', { token: () => forged({ alg: "HS256", crit: ["b64"] }) }],
    [
      "alg outside allowlist",
      { token: good, ours: { algorithms: ["HS512"] }, theirs: { algorithms: ["HS512"] } },
    ],
    [
      "RS/HS confusion (HS256 over RSA SPKI)",
      {
        token: () => forgeHS({ alg: "HS256" }, seg(claims), textEncoder.encode(rsa.pem.spki)),
        ours: { algorithms: ["RS256"] },
        keys: async () => [rsa.jwk.public, await jose.importSPKI(rsa.pem.spki, "RS256")],
      },
    ],
    ["expired exp", { token: () => forged({ alg: "HS256" }, seg({ exp: now - 60 })) }],
    ["future nbf", { token: () => forged({ alg: "HS256" }, seg({ nbf: now + 600 })) }],
    [
      "wrong aud",
      {
        token: () => forged({ alg: "HS256" }, seg({ aud: "a" })),
        ours: { audience: "b" },
        theirs: { audience: "b" },
      },
    ],
    [
      "wrong iss",
      {
        token: () => forged({ alg: "HS256" }, seg({ iss: "a" })),
        ours: { issuer: "b" },
        theirs: { issuer: "b" },
      },
    ],
  ];

  const divergences: [string, "accepts" | "rejects", Probe][] = [
    // unjwt rejects (RFC 7797 §6: b64 must be in crit); jose ignores b64 outside crit and decodes the segment as base64url.
    ["b64:false without crit", "rejects", { token: () => forged({ alg: "HS256", b64: false }) }],
    // unjwt rejects non-canonical base64url; jose (atob path) accepts a correctly padded segment.
    ["'=' padding on signature segment", "rejects", { token: async () => `${await good()}=` }],
    // unjwt rejects; jose's atob path strips ASCII whitespace inside a segment.
    [
      "whitespace inside payload segment",
      "rejects",
      { token: () => forged({ alg: "HS256" }, ` ${seg(claims)}`) },
    ],
    // unjwt enforces the RFC 7518 §3.2 HMAC key-size floor; jose accepts a 16-byte HS256 secret.
    [
      "HS256 with a 16-byte secret",
      "rejects",
      {
        token: () => forgeHS({ alg: "HS256" }, seg(claims), shortSecret),
        ours: { algorithms: ["HS256"] },
        keys: async () => [shortSecret, shortSecret],
      },
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

describe("interop with jose: JWS wire format", () => {
  it("unjwt adds typ and kid for an object payload where jose adds nothing", async () => {
    const { priv } = await keysFor("HS256");
    const ours = headerOf(await sign(claims, priv as JWSSignJWK));
    const theirs = headerOf(
      await new jose.SignJWT(claims).setProtectedHeader({ alg: "HS256" }).sign(joseKey(priv)),
    );
    expect(theirs).toEqual({ alg: "HS256" });
    expect(ours).toEqual({ alg: "HS256", kid: priv.kid, typ: "JWT" });
  });
});

async function consumers(probe: Probe): Promise<[() => Promise<unknown>, () => Promise<unknown>]> {
  const token = await probe.token();
  const hs = (await keysFor("HS256")).priv;
  const [ours, theirs] = probe.keys ? await probe.keys() : [hs as JWSVerifyJWK, joseKey(hs)];
  return [
    () => verify(token, ours as JWSVerifyJWK, probe.ours),
    () => jose.jwtVerify(token, theirs, probe.theirs),
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

function joseKey(jwk: JWK): JoseKey {
  return jwk.kty === "oct" ? octBytes(jwk) : jwk;
}

function octBytes(jwk: JWK): Uint8Array<ArrayBuffer> {
  return base64UrlParse((jwk as JWK_oct).k, { returnAs: "uint8array" });
}

function seg(value: unknown): string {
  return base64UrlStringify(JSON.stringify(value));
}

function headerOf(token: string): Record<string, unknown> {
  return JSON.parse(base64UrlParse(token.split(".")[0]));
}

function tamper(token: string, index: number): string {
  const parts = token.split(".");
  const segment = base64UrlParse(parts[index], { returnAs: "uint8array" });
  segment[0] ^= 1;
  parts[index] = base64UrlStringify(segment);
  return parts.join(".");
}

async function forgeHS(header: unknown, payload: string, secret: Uint8Array): Promise<string> {
  const input = `${seg(header)}.${payload}`;
  const key = await crypto.subtle.importKey(
    "raw",
    secret as Uint8Array<ArrayBuffer>,
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"],
  );
  const mac = await crypto.subtle.sign("HMAC", key, textEncoder.encode(input));
  return `${input}.${base64UrlStringify(new Uint8Array(mac))}`;
}
