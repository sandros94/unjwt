// #region docs
import {
  type JWKSet,
  type JWK_EC_Private,
  type JWK_EC_Public,
  defineJWSSession,
  toPublicJWK,
} from "unjwt/session";

// The private ES256 JWK that signs from now on, as JSON
const json = process.env.SESSION_SIGNING_KEY;
if (!json) throw new Error("SESSION_SIGNING_KEY is not set");
const privateKey: JWK_EC_Private<"ES256"> = JSON.parse(json);

// The public halves of the keys that signed before it, as a JWK Set: { "keys": [{ "kid": "2026-09", … }] }
const earlier: JWKSet<JWK_EC_Public<"ES256" | "ES384" | "ES512">[]> = JSON.parse(
  process.env.SESSION_EARLIER_KEYS ?? '{ "keys": [] }',
);

export const signedSession = defineJWSSession<{ userId: string }, "1h">({
  key: { privateKey, publicKey: [toPublicJWK(privateKey), ...earlier.keys] },
  maxAge: "1h",
});
// #endregion
