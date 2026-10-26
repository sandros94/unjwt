// #region docs
import { decrypt, encrypt } from "unjwt/jwe";
import { generateJWK } from "unjwt/jwk";
import type { JWTClaims } from "unjwt";

// The billing service makes its key pair once and hands out the public half
const billing = await generateJWK("ECDH-ES+A256KW", { kid: "billing-2026-10" });

/** Sender side: only the holder of the private half can open the result. */
export async function sealInvoice(invoice: { id: string; iban: string }): Promise<string> {
  return encrypt(invoice, billing.publicKey, { expiresIn: "1h" });
}

/** Billing side: the invoice, or a `JWTError` when the token was not sealed for this key. */
export async function openInvoice(token: string): Promise<JWTClaims> {
  const { payload } = await decrypt(token, billing.privateKey);
  return payload;
}
// #endregion
