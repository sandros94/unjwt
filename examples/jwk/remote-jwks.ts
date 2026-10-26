// #region docs
import type { JWKSet } from "unjwt/jwk";
import { verify, type JWSKeyLookup } from "unjwt/jws";

const JWKS_URL = "https://auth.example.com/.well-known/jwks.json";
const MAX_AGE_MS = 10 * 60 * 1000;

let cached: { set: JWKSet; fetchedAt: number } | undefined;

const issuerKeys: JWSKeyLookup = async () => {
  if (!cached || Date.now() - cached.fetchedAt > MAX_AGE_MS) {
    const response = await fetch(JWKS_URL);
    if (!response.ok) throw new Error(`JWK Set fetch failed with ${response.status}`);
    cached = { set: await response.json(), fetchedAt: Date.now() };
  }
  return cached.set;
};

export async function readIssuerToken(token: string) {
  const { payload } = await verify(token, issuerKeys, {
    algorithms: ["RS256"],
    issuer: "https://auth.example.com",
    audience: "api.example.com",
  });
  return payload;
}
// #endregion

/** Drops the cached set, so each test starts from an empty one. */
export function forgetIssuerKeys() {
  cached = undefined;
}
