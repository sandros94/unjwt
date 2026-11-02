// #region docs
import { sign } from "unjwt/jws";
import type { JWSSignJWK } from "unjwt/jws";
import { isPrivateJWK } from "unjwt/utils";

const raw = process.env.TOKEN_SIGNING_KEY;
if (!raw) throw new Error("TOKEN_SIGNING_KEY is not set");
const signingKey: JWSSignJWK = JSON.parse(raw);
if (!isPrivateJWK(signingKey)) throw new Error("TOKEN_SIGNING_KEY must be a private JWK");

/** A 15-minute access token for `api.example.com`, signed with the issuer's private key. */
export function issueAccessToken(userId: string, scope: string[]) {
  return sign(
    {
      iss: "https://auth.example.com",
      aud: "https://api.example.com",
      sub: userId,
      scope: scope.join(" "),
    },
    signingKey,
    { expiresIn: "15m", protectedHeader: { typ: "at+jwt" } },
  );
}
// #endregion
