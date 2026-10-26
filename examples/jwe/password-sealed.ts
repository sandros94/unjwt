// #region docs
import { encrypt, decrypt } from "unjwt/jwe";

const ITERATIONS = 600_000;

/** Seal a backup file with a passphrase the user types. */
export function sealBackup(file: Uint8Array<ArrayBuffer>, passphrase: string) {
  return encrypt(file, passphrase, { alg: "PBES2-HS512+A256KW", p2c: ITERATIONS });
}

/** Open a backup sealed by `sealBackup`; a wrong passphrase throws `ERR_JWE_DECRYPTION_FAILED`. */
export async function openBackup(token: string, passphrase: string) {
  const { payload } = await decrypt(token, passphrase, {
    algorithms: ["PBES2-HS512+A256KW"],
    maxIterations: ITERATIONS,
    payload: "bytes",
  });
  return payload;
}
// #endregion
