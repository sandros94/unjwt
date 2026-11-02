// #region docs
import { configureJWKCache, thumbprint, type JWK, type JWKAlgorithm } from "unjwt/jwk";

const MAX_ENTRIES = 500;
const entries: Map<string, CryptoKey> = new Map();

/** The key material, the half of the pair, and the algorithm: never the `kid`. */
async function entryName(jwk: JWK, alg: JWKAlgorithm): Promise<string> {
  const half = "d" in jwk ? "private" : "public";
  return `${await thumbprint(jwk)}:${half}:${alg}`;
}

configureJWKCache({
  async get(jwk, alg) {
    return entries.get(await entryName(jwk, alg));
  },
  async set(jwk, alg, key) {
    if (entries.size >= MAX_ENTRIES) {
      const [oldest] = entries.keys();
      if (oldest !== undefined) entries.delete(oldest);
    }
    entries.set(await entryName(jwk, alg), key);
  },
});
// #endregion

export { entries };
