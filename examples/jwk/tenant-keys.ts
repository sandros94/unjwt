// #region docs
import { importKey, unwrapKey, wrapKey, type JWK_oct } from "unjwt/jwk";
import { base64UrlParse, base64UrlStringify } from "unjwt/utils";

const raw = process.env.MASTER_KEY; // an A256KW JWK from generateJWK("A256KW")
if (!raw) throw new Error("MASTER_KEY is not set");
const masterKey: JWK_oct<"A256KW"> = JSON.parse(raw);

/** The form you store in the tenant's row: the wrapped bytes, plus the `kid` in clear. */
export interface SealedKey {
  kid: string;
  wrapped: string;
}

export async function sealTenantKey(tenantKey: JWK_oct<"HS256">): Promise<SealedKey> {
  if (!tenantKey.kid) throw new Error("A tenant key needs a kid");
  const secret = await importKey(tenantKey);
  const { encryptedKey } = await wrapKey(secret, masterKey, { alg: "A256KW" });
  return { kid: tenantKey.kid, wrapped: base64UrlStringify(encryptedKey) };
}

export async function openTenantKey(sealed: SealedKey): Promise<JWK_oct<"HS256">> {
  const encryptedKey = base64UrlParse(sealed.wrapped, { returnAs: "bytes" });
  const secret = await unwrapKey(encryptedKey, masterKey, { alg: "A256KW", format: "raw" });
  return { kty: "oct", k: base64UrlStringify(secret), alg: "HS256", kid: sealed.kid };
}
// #endregion
