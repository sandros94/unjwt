import type {
  ContentEncryptionAlgorithm,
  JWEHeaderParameters,
  KeyManagementAlgorithm,
  UnwrapKeyOptions,
} from "../../types/index.ts";
import { JWTError } from "../../../error.ts";
import { isCryptoKey } from "../../../utils/guards.ts";
import { assertPBES2Iterations } from "../../_crypto/index.ts";

/** PBKDF2 iterations one call may still spend, summed over every PBES2 attempt. */
export interface PBES2Budget {
  /** Charge one PBES2 attempt's `p2c`; throws without charging when out of bounds or over budget. */
  spend(attempt: Pick<UnwrapKeyOptions, "alg" | "p2c" | "minIterations" | "maxIterations">): void;
}

export function createPBES2Budget(limit: number): PBES2Budget {
  let remaining = limit;
  return {
    spend(attempt) {
      const { alg, p2c } = attempt;
      if (!alg.startsWith("PBES2")) return;
      // A non-positive `p2c` is rejected by the PBES2 primitive itself.
      if (typeof p2c !== "number" || !(p2c > 0)) return;
      assertPBES2Iterations(p2c, attempt);
      if (p2c > remaining) {
        throw new JWTError(`PBES2 iteration budget of ${limit} exhausted.`, "ERR_JWE_INVALID");
      }
      remaining -= p2c;
    },
  };
}

const JWE_ENC_CEK_FORMAT = /* @__PURE__ */ Object.freeze({
  "A128GCM": "cryptokey",
  "A192GCM": "cryptokey",
  "A256GCM": "cryptokey",
  "A128CBC-HS256": "raw",
  "A192CBC-HS384": "raw",
  "A256CBC-HS512": "raw",
} satisfies Record<ContentEncryptionAlgorithm, "cryptokey" | "raw">);

/** The CEK as bytes for `returnCek`; a non-extractable key is `ERR_INVALID_OPTION`. */
export async function exportReturnedCek(
  cek: CryptoKey | Uint8Array<ArrayBuffer>,
): Promise<Uint8Array<ArrayBuffer>> {
  if (!isCryptoKey(cek)) return cek;
  if (!cek.extractable) {
    throw new JWTError(
      '"returnCek" requires an extractable content encryption key.',
      "ERR_INVALID_OPTION",
    );
  }
  return new Uint8Array(await crypto.subtle.exportKey("raw", cek));
}

export function cekFormatForEnc(enc: ContentEncryptionAlgorithm): "cryptokey" | "raw" {
  return JWE_ENC_CEK_FORMAT[enc];
}

/** One recipient's unwrap options; header parameters it lacks are left off, not `undefined`. */
export function buildUnwrapKeyOptions(
  header: JWEHeaderParameters,
  algorithms: { alg: KeyManagementAlgorithm; enc: ContentEncryptionAlgorithm },
  options:
    | Pick<
        UnwrapKeyOptions,
        "keyUsage" | "unwrappedKeyAlgorithm" | "extractable" | "minIterations" | "maxIterations"
      >
    | undefined,
): UnwrapKeyOptions {
  const { alg, enc } = algorithms;
  const opts: UnwrapKeyOptions = {
    alg,
    enc,
    format: cekFormatForEnc(enc),
    keyUsage: options?.keyUsage || ["decrypt"],
  };
  if (header.iv) opts.iv = header.iv;
  if (header.tag) opts.tag = header.tag;
  if (header.p2s) opts.p2s = header.p2s;
  if (header.p2c) opts.p2c = header.p2c;
  if (header.epk) opts.epk = header.epk;
  if (header.apu) opts.apu = header.apu;
  if (header.apv) opts.apv = header.apv;
  if (options?.unwrappedKeyAlgorithm) opts.unwrappedKeyAlgorithm = options.unwrappedKeyAlgorithm;
  if (options?.extractable !== undefined) opts.extractable = options.extractable;
  if (options?.minIterations !== undefined) opts.minIterations = options.minIterations;
  if (options?.maxIterations !== undefined) opts.maxIterations = options.maxIterations;
  return opts;
}
