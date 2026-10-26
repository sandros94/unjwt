// #region docs
import { encrypt } from "unjwt/jwe";
import type { JWEEncryptJWK } from "unjwt/jwe";

export interface CustomerRecord {
  customerId: string;
  email: string;
  country: string;
}

/** Seal a record so only the holder of the matching private key can read it. */
export function sealCustomer(record: CustomerRecord, recipientKey: JWEEncryptJWK): Promise<string> {
  return encrypt(record, recipientKey, { expiresIn: "10m" });
}
// #endregion
