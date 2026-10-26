// #region docs
import {
  type JWK_EC_Private,
  type SessionDefinition,
  type WebSessionEvent,
  defineJWSSession,
  toPublicJWK,
} from "unjwt/session";

// A private ES256 JWK as JSON; services that only verify get its public half
const json = process.env.SESSION_SIGNING_KEY;
if (!json) throw new Error("SESSION_SIGNING_KEY is not set");
const privateKey: JWK_EC_Private<"ES256"> = JSON.parse(json);

export interface SignedSession {
  userId: string;
  locale: string;
}

export const signedSession: SessionDefinition<SignedSession, "1h", WebSessionEvent> =
  defineJWSSession({
    key: { privateKey, publicKey: toPublicJWK(privateKey) },
    maxAge: "1h",
    jws: { signOptions: { alg: "ES256" } },
  });
// #endregion
