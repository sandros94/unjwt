// #region docs
import { defineJWSSession, importPEM, toPublicJWK } from "unjwt/session";

// A PKCS#8 private key, "-----BEGIN PRIVATE KEY-----…", as your key store hands it out
const pem = process.env.SESSION_SIGNING_PEM;
if (!pem) throw new Error("SESSION_SIGNING_PEM is not set");
const privateKey = await importPEM(pem, "ES256", {
  pemType: "pkcs8",
  jwkParams: { kid: "2026-10" },
});

export const signedSession = defineJWSSession<{ userId: string }, "1h">({
  key: { privateKey, publicKey: toPublicJWK(privateKey) },
  maxAge: "1h",
});
// #endregion
