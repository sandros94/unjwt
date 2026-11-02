import { generateJWK, type JWKSet, type JWK_EC_Private, type JWK_EC_Public } from "unjwt/jwk";
import { sign, verify } from "unjwt/jws";

// #region docs
/** Every key whose tokens you still accept; only `signing` signs new ones. */
export interface Keyring {
  signing: string;
  pairs: Array<{ privateKey: JWK_EC_Private<"ES256">; publicKey: JWK_EC_Public<"ES256"> }>;
}

/** What `/.well-known/jwks.json` serves: the public halves, never a private one. */
export function publishedSet(ring: Keyring): JWKSet {
  return { keys: ring.pairs.map((pair) => pair.publicKey) };
}

export function issueToken(ring: Keyring, userId: string) {
  const pair = ring.pairs.find((p) => p.privateKey.kid === ring.signing);
  if (!pair) throw new Error(`No key named "${ring.signing}" in the keyring`);
  return sign({ sub: userId }, pair.privateKey, { expiresIn: "1h" });
}

/** A verifier holds only the set; the token's `kid` picks the key. */
export async function readToken(set: JWKSet, token: string) {
  const { payload } = await verify(token, set, { algorithms: ["ES256"] });
  return payload;
}
// #endregion

// #region rotate
export async function createKeyring(kid: string): Promise<Keyring> {
  return { signing: kid, pairs: [await generateJWK("ES256", { kid })] };
}

/** Step 2: publish the next key before it signs anything. */
export async function addKey(ring: Keyring, kid: string): Promise<Keyring> {
  return { ...ring, pairs: [...ring.pairs, await generateJWK("ES256", { kid })] };
}

/** Step 3: sign with the next key; the old one stays so its tokens still verify. */
export function switchSigning(ring: Keyring, kid: string): Keyring {
  if (!ring.pairs.some((p) => p.publicKey.kid === kid)) throw new Error(`Add "${kid}" first`);
  return { ...ring, signing: kid };
}

/** Step 4: drop the old key once its last token has expired. */
export function retireKey(ring: Keyring, kid: string): Keyring {
  if (kid === ring.signing) throw new Error(`"${kid}" still signs new tokens`);
  return { ...ring, pairs: ring.pairs.filter((p) => p.publicKey.kid !== kid) };
}
// #endregion
