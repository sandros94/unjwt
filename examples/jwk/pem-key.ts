// #region docs
import { importPEM } from "unjwt/jwk";
import { sign } from "unjwt/jws";

const pem = process.env.SIGNING_KEY_PEM; // "-----BEGIN PRIVATE KEY-----…"
if (!pem) throw new Error("SIGNING_KEY_PEM is not set");

const signingKey = await importPEM(pem, "RS256", {
  pemType: "pkcs8",
  jwkParams: { kid: "2026-10" },
});

export function issueToken(userId: string) {
  return sign({ sub: userId }, signingKey, { expiresIn: "15m" });
}
// #endregion
