// #region docs
import { signMulti, verifyMulti, verifyMultiAll } from "unjwt/jws";
import type { JWSGeneralSerialization } from "unjwt/jws";
import { generateJWK } from "unjwt/jwk";
import type { JWKSet } from "unjwt/jwk";

// In production each party loads its own private key; generated here so the example runs.
const vendor = await generateJWK("ES256", { kid: "vendor-2026-10" });
const notary = await generateJWK("Ed25519", { kid: "notary-2026-10" });

/** The public halves of everyone allowed to sign a contract. */
export const signers: JWKSet = { keys: [vendor.publicKey, notary.publicKey] };

export interface Contract {
  contractId: string;
  customer: string;
  total: number;
}

/** One payload, two signatures: the vendor's and the notary's. */
export function signContract(contract: Contract) {
  return signMulti(contract, [{ key: vendor.privateKey }, { key: notary.privateKey }], {
    expiresIn: "30D",
  });
}

/** `true` only when every required party signed this exact contract. */
export async function isFullySigned(contract: JWSGeneralSerialization) {
  const outcomes = await verifyMultiAll(contract, () => signers);
  const signedBy = new Set(
    outcomes.filter((outcome) => outcome.verified).map((outcome) => outcome.protectedHeader.kid),
  );
  return ["vendor-2026-10", "notary-2026-10"].every((kid) => signedBy.has(kid));
}
// #endregion

// #region any
/** Accept the contract when the notary's signature alone verifies. */
export async function notarized(contract: JWSGeneralSerialization) {
  const { payload } = await verifyMulti<Contract>(contract, notary.publicKey);
  return payload;
}
// #endregion
