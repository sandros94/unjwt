// #region docs
import { deriveJWKFromPassword } from "unjwt/jwk";
import { decrypt, encrypt } from "unjwt/jwe";

const passphrase = process.env.EXPORT_PASSPHRASE;
const salt = process.env.EXPORT_SALT; // random, generated once, not secret
if (!passphrase || !salt) throw new Error("EXPORT_PASSPHRASE and EXPORT_SALT must be set");

// Runs PBKDF2 once, here; every token after this is an ordinary A128KW encryption.
const exportKey = await deriveJWKFromPassword(passphrase, {
  alg: "PBES2-HS256+A128KW",
  salt,
  iterations: 600_000,
  kid: "exports-2026",
});

export interface ExportManifest {
  accountId: string;
  files: string[];
}

export function sealManifest(manifest: ExportManifest): Promise<string> {
  return encrypt(manifest, exportKey);
}

export async function openManifest(token: string): Promise<ExportManifest> {
  const { payload } = await decrypt<ExportManifest>(token, exportKey);
  return payload;
}
// #endregion
