// #region docs
import { encryptMulti, decryptMulti } from "unjwt/jwe";
import type { JWEDecryptJWK, JWEEncryptJWK, JWEGeneralSerialization } from "unjwt/jwe";

export interface IncidentReport {
  incidentId: string;
  summary: string;
}

/** Encrypt one report once, readable by the security team, legal and the offline archive. */
export function sealIncident(
  report: IncidentReport,
  recipients: { security: JWEEncryptJWK; legal: JWEEncryptJWK; archive: JWEEncryptJWK },
): Promise<JWEGeneralSerialization> {
  return encryptMulti(
    report,
    [
      { key: recipients.security },
      { key: recipients.legal },
      { key: recipients.archive, header: { "x-retention": "7y" } },
    ],
    { aad: `incident:${report.incidentId}`, expiresIn: "90D" },
  );
}

/** Each reader opens the same object with its own private key. */
export async function readIncident(
  sealed: JWEGeneralSerialization,
  myKey: JWEDecryptJWK,
): Promise<IncidentReport> {
  const { payload } = await decryptMulti<IncidentReport>(sealed, myKey);
  return payload;
}
// #endregion
