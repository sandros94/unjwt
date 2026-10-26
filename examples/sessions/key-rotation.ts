// #region jwe
import {
  type JWKSet,
  type JWK_oct,
  type SessionDefinition,
  defineJWESession,
  defineJWSSession,
} from "unjwt/session";

// A JWK Set as JSON, newest key first: { "keys": [{ "kid": "2026-10", … }, { "kid": "2026-09", … }] }
const sealing = process.env.SESSION_KEYS;
if (!sealing) throw new Error("SESSION_KEYS is not set");
const [current, ...previous]: JWK_oct<"A256KW">[] = JSON.parse(sealing).keys;
if (!current) throw new Error("SESSION_KEYS holds no key");

export const appSession: SessionDefinition<{ userId: string }, "7D"> = defineJWESession({
  key: { current, keys: previous },
  maxAge: "7D",
});
// #endregion

// #region jws
// The same layout for HS256 keys: the first one signs, every one of them verifies
const signing = process.env.SIGNING_KEYS;
if (!signing) throw new Error("SIGNING_KEYS is not set");
const keyring: JWKSet<JWK_oct<"HS256">[]> = JSON.parse(signing);
const [signingKey] = keyring.keys;
if (!signingKey) throw new Error("SIGNING_KEYS holds no key");

export const signedSession: SessionDefinition<{ userId: string }, "1h"> = defineJWSSession({
  key: signingKey,
  maxAge: "1h",
  jws: { signOptions: { alg: "HS256" } },
  hooks: {
    onVerifyKeyLookup: () => keyring,
  },
});
// #endregion
