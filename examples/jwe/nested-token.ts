// #region docs
import { sign, verify } from "unjwt/jws";
import type { JWSSignJWK, JWSVerifyJWK } from "unjwt/jws";
import { encrypt, decrypt } from "unjwt/jwe";
import type { JWEDecryptJWK, JWEEncryptJWK } from "unjwt/jwe";

export interface Grant {
  sub: string;
  plan: string;
}

/** Sign the claims, then encrypt the signed token: private and provably yours. */
export async function issueSealedGrant(
  grant: Grant,
  keys: { issuer: JWSSignJWK; recipient: JWEEncryptJWK },
): Promise<string> {
  const signed = await sign(grant, keys.issuer, { expiresIn: "1h" });
  return encrypt(signed, keys.recipient, { protectedHeader: { cty: "JWT" } });
}

/** Decrypt, then verify the token inside. */
export async function openSealedGrant(
  token: string,
  keys: { recipient: JWEDecryptJWK; issuer: JWSVerifyJWK },
): Promise<Grant> {
  const { payload: signed } = await decrypt(token, keys.recipient, { payload: "string" });
  const { payload } = await verify<Grant>(signed, keys.issuer);
  return payload;
}
// #endregion
