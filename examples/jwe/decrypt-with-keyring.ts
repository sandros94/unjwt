// #region docs
import { decrypt } from "unjwt/jwe";
import type { JWKSet } from "unjwt/jwk";
import { isJWKSet } from "unjwt/utils";

const raw = process.env.REPORTS_DECRYPTION_KEYS;
if (!raw) throw new Error("REPORTS_DECRYPTION_KEYS is not set");
const keyring: JWKSet = JSON.parse(raw);
if (!isJWKSet(keyring)) throw new Error("REPORTS_DECRYPTION_KEYS must be a JWK Set");

export interface CustomerRecord {
  customerId: string;
  email: string;
  country: string;
}

/** Open a sealed customer record with whichever private key in the keyring its `kid` names. */
export async function openCustomer(token: string): Promise<CustomerRecord> {
  const { payload } = await decrypt<CustomerRecord>(token, keyring, {
    algorithms: ["ECDH-ES+A256KW"],
    encryptionAlgorithms: ["A256GCM"],
    requiredClaims: ["exp"],
  });
  return payload;
}
// #endregion
