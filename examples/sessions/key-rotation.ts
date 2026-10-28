// #region jwe
import { type JWKSet, type JWK_oct, defineJWESession, defineJWSSession } from "unjwt/session";

// A JWK Set as JSON, newest key first: { "keys": [{ "kid": "2026-10", … }, { "kid": "2026-09", … }] }
const sealing = process.env.SESSION_KEYS;
if (!sealing) throw new Error("SESSION_KEYS is not set");
const sessionKeys: JWKSet<JWK_oct<"A256KW">[]> = JSON.parse(sealing);

export const appSession = defineJWESession<{ userId: string }, "7D">({
  key: sessionKeys,
  maxAge: "7D",
});
// #endregion

// #region jws
// The same layout for HMAC keys, here while moving from HS256 to HS512: the newest key signs HS512
const signing = process.env.SIGNING_KEYS;
if (!signing) throw new Error("SIGNING_KEYS is not set");
const signingKeys: JWKSet<JWK_oct<"HS256" | "HS512">[]> = JSON.parse(signing);

export const signedSession = defineJWSSession<{ userId: string }, "1h">({
  key: signingKeys,
  maxAge: "1h",
});
// #endregion
