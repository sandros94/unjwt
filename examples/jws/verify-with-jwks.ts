// #region docs
import { verify } from "unjwt/jws";
import type { JWKSet } from "unjwt/jwk";
import { isJWTError } from "unjwt/error";
import { isJWKSet } from "unjwt/utils";

const raw = process.env.ISSUER_JWKS;
if (!raw) throw new Error("ISSUER_JWKS is not set");
const issuerKeys: JWKSet = JSON.parse(raw);
if (!isJWKSet(issuerKeys)) throw new Error("ISSUER_JWKS must be a JWK Set");

export interface AccessClaims {
  sub: string;
  scope: string;
}

/** The caller's claims from `Authorization: Bearer …`, or `null` when the token is missing or refused. */
export async function authenticate(request: Request) {
  const header = request.headers.get("authorization");
  if (!header?.startsWith("Bearer ")) return null;
  try {
    const { payload } = await verify<AccessClaims>(header.slice(7), issuerKeys, {
      algorithms: ["ES256"],
      issuer: "https://auth.example.com",
      audience: "https://api.example.com",
      typ: "at+jwt",
      requiredClaims: ["sub", "exp"],
    });
    return payload;
  } catch (error) {
    if (isJWTError(error)) return null;
    throw error;
  }
}
// #endregion
