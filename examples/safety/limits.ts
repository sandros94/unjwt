// #region docs
import type { JWKSet } from "unjwt/jwk";
import { verify, verifyMultiAll, type JWSGeneralSerialization } from "unjwt/jws";

/**
 * A partner publishes 12 public keys and signs without a `kid`, so every
 * token has to be tried against all of them. The default of 8 refuses that
 * set; this reader raises the bound to exactly what the partner publishes.
 */
export async function readPartnerToken(token: string, partnerKeys: JWKSet) {
  const { payload } = await verify(token, partnerKeys, {
    algorithms: ["ES256"],
    issuer: "https://partner.example.com",
    limits: { keyCandidates: 12 },
  });
  return payload;
}
// #endregion

// #region multi
/**
 * A release signed by up to 24 maintainers, accepted once 3 signatures verify.
 * Every signature carries its maintainer's `kid`, so each costs one key trial.
 */
export async function isApproved(release: JWSGeneralSerialization, maintainers: JWKSet) {
  const outcomes = await verifyMultiAll(release, () => maintainers, {
    algorithms: ["Ed25519"],
    limits: { signatures: 24, keyAttempts: 24 },
  });
  return outcomes.filter((outcome) => outcome.verified).length >= 3;
}
// #endregion
