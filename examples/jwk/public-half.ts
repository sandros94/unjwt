// #region docs
import { toPublicJWK, type JWK_EC_Public } from "unjwt/jwk";
import { verify } from "unjwt/jws";
import { signingKey } from "./signing-key.ts";

/** Derived once at start-up: the same JWK without its private members. */
export const verifyKey: JWK_EC_Public<"ES256"> = toPublicJWK(signingKey);

export async function readToken(token: string) {
  const { payload } = await verify(token, verifyKey);
  return payload;
}
// #endregion
