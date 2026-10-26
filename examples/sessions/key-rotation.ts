// #region jwe
import { type JWKSet, type JWK_oct, defineJWESession, defineJWSSession } from "unjwt/session";

// A JWK Set as JSON, newest key first: { "keys": [{ "kid": "2026-10", … }, { "kid": "2026-09", … }] }
const sealing = process.env.SESSION_KEYS;
if (!sealing) throw new Error("SESSION_KEYS is not set");
const ring: JWKSet<JWK_oct<"A256KW">[]> = JSON.parse(sealing);
const [current] = ring.keys;
if (!current) throw new Error("SESSION_KEYS holds no key");

export const appSession = defineJWESession<{ userId: string }, "7D">({
  key: current,
  maxAge: "7D",
  hooks: {
    onKeyLookup: () => ring,
  },
});
// #endregion

// #region jws
// The same layout for HMAC keys, here while moving from HS256 to HS512: the newest key signs HS512
const signing = process.env.SIGNING_KEYS;
if (!signing) throw new Error("SIGNING_KEYS is not set");
const signingRing: JWKSet<JWK_oct<"HS256" | "HS512">[]> = JSON.parse(signing);
const [signingKey] = signingRing.keys;
if (!signingKey) throw new Error("SIGNING_KEYS holds no key");

export const signedSession = defineJWSSession<{ userId: string }, "1h">({
  key: signingKey,
  maxAge: "1h",
  jws: { verifyOptions: { algorithms: ["HS256"] } },
  hooks: {
    onKeyLookup: () => signingRing,
  },
});
// #endregion
