// #region docs
import { generateJWK } from "unjwt/jwk";

const { privateKey, publicKey } = await generateJWK("ES256", { kid: "2026-10" });

export const env: Record<string, string> = {
  TOKEN_PRIVATE_JWK: JSON.stringify(privateKey), // only where tokens are issued
  TOKEN_PUBLIC_JWK: JSON.stringify(publicKey), // wherever tokens are verified
};
// #endregion
