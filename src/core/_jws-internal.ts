import type { JWK, JWKSet } from "./types/jwk.ts";
import type { JWSAlgorithm, JWSHeaderParameters, JWSProtectedHeader } from "./types/jws.ts";
import { importKey, getJWKsFromSet } from "./_import-key.ts";
import { verify as joseVerify } from "./_crypto/_sign-verify.ts";
import { JWTError } from "./error.ts";
import { isJWK, isJWKSet } from "./utils/guards.ts";
import { applyTypDefault } from "./_jwt-internal.ts";
import {
  applyB64Header,
  asKeyUsageError,
  assertJWKSetCandidates,
  assertProducerCrit,
  buildJWKSetFilter,
  copyJsonObject,
  resolveSigningKey,
} from "./_internal.ts";

/** Build a signature's protected header; precedence: `alg` > caller's header > the JWK's `kid`. */
export function buildJWSProtectedHeader(
  alg: JWSAlgorithm,
  key: unknown,
  userHeader: JWSHeaderParameters | undefined,
  options: { payload: unknown; b64?: boolean },
): JWSProtectedHeader {
  const safeHeader = copyJsonObject<JWSHeaderParameters | undefined>(userHeader, {
    code: "ERR_INVALID_OPTION",
    message: '"protectedHeader" must hold only JSON values.',
  });
  // oxlint-disable-next-line typescript/no-unsafe-type-assertion -- `alg` is assigned below, before the header leaves this function
  const header = {} as JWSProtectedHeader;
  if (isJWK(key) && key.kid) header.kid = key.kid;
  if (safeHeader) Object.assign(header, safeHeader);
  header.alg = alg;
  applyTypDefault(header, options.payload);
  if (options.b64 === false) header.b64 = false;
  applyB64Header(header);
  assertProducerCrit(header, "JWS");
  return header;
}

export type VerificationKeyMaterial = CryptoKey | JWK | JWKSet | Uint8Array<ArrayBuffer>;

export interface VerifyWithKeyOptions {
  signature: Uint8Array<ArrayBuffer>;
  signingInput: Uint8Array<ArrayBuffer>;
  kid: string | undefined;
  allowSymmetric: boolean | undefined;
  keyCandidates: number;
}

/** Verify one signature; a JWK Set tries each candidate, failing with one `ERR_JWS_SIGNATURE_INVALID` carrying every attempt. */
export async function verifyWithKey(
  alg: JWSAlgorithm,
  rawKeyMaterial: VerificationKeyMaterial,
  options: VerifyWithKeyOptions,
): Promise<boolean> {
  try {
    return await verifyWithKeyMaterial(alg, rawKeyMaterial, options);
  } catch (err) {
    throw asKeyUsageError(err, alg);
  }
}

async function verifyWithKeyMaterial(
  alg: JWSAlgorithm,
  rawKeyMaterial: VerificationKeyMaterial,
  options: VerifyWithKeyOptions,
): Promise<boolean> {
  const { signature, signingInput, kid, allowSymmetric, keyCandidates } = options;

  if (isJWKSet(rawKeyMaterial)) {
    const candidates = getJWKsFromSet(
      rawKeyMaterial,
      buildJWKSetFilter({ kid, alg }, { op: "sig", allowSymmetric }),
    );
    assertJWKSetCandidates(candidates, { limit: keyCandidates, kid });
    const attempts: JWTError[] = [];
    for (const candidate of candidates) {
      try {
        const verificationKey = await resolveSigningKey(
          alg,
          await importKey(candidate, { alg, expect: "public" }),
          "verify",
        );
        if (await joseVerify(alg, verificationKey, signature, signingInput)) {
          return true;
        }
        attempts.push(
          new JWTError("JWS signature verification failed.", "ERR_JWS_SIGNATURE_INVALID"),
        );
      } catch (error) {
        attempts.push(asKeyUsageError(error, alg));
      }
    }
    throw new JWTError("JWS signature verification failed.", "ERR_JWS_SIGNATURE_INVALID", attempts);
  }

  const verificationKey = await resolveSigningKey(
    alg,
    await importKey(rawKeyMaterial, { alg, expect: "public" }),
    "verify",
  );
  return joseVerify(alg, verificationKey, signature, signingInput);
}
