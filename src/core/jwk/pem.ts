import type { JWK, JWKPEMAlgorithm, ImportedPEMJWK, PEMType, JWKMetadata } from "../types/index.ts";
import { assertPlainObject, isCryptoKey } from "../../utils/guards.ts";
import { JWTError } from "../../error.ts";
import { importKey } from "../_internal/import-key.ts";
import { fromPKCS8, fromSPKI, fromX509, toPKCS8, toSPKI } from "../_crypto/index.ts";
import { exportJWK } from "./export.ts";

/**
 * Imports a PEM key as a JWK carrying `alg`. The type follows the label — `PRIVATE KEY`
 * (PKCS#8), `PUBLIC KEY` (SPKI), `CERTIFICATE` (X.509, only its SPKI kept) — unless
 * `options.pemType` overrides it. The JWK holds the key material in plain JavaScript.
 *
 * @throws `ERR_JWK_INVALID` if the type cannot be inferred or does not match the label;
 *   `ERR_JWK_UNSUPPORTED` for an unknown `pemType`; `ERR_INVALID_OPTION` if `jwkParams` sets
 *   `alg`, `kty`, `key_ops`, `ext` or a key-material member.
 */
export async function importPEM<
  A extends JWKPEMAlgorithm,
  Type extends PEMType | undefined = undefined,
>(
  pem: string,
  alg: A,
  options?: {
    /** PEM type. Inferred from the PEM label when omitted, which leaves the result public or private. */
    pemType?: Type;
    /** Additional JWK properties merged into the exported key (e.g. `kid`). */
    jwkParams?: JWKMetadata;
  },
): Promise<ImportedPEMJWK<A, Type>> {
  if (typeof pem !== "string") {
    throw new JWTError('"pem" must be a PEM-encoded string.', "ERR_INVALID_OPTION");
  }
  if (options !== undefined) assertPlainObject(options, "options");
  const extractable = true;
  const pemType = options?.pemType ?? inferPEMType(pem);

  if (!pemType) {
    throw new JWTError('Cannot infer PEM type from the input, pass "pemType".', "ERR_JWK_INVALID");
  }

  let cryptoKey: CryptoKey;
  switch (pemType) {
    case "pkcs8": {
      cryptoKey = await fromPKCS8(pem, alg, { extractable });
      break;
    }
    case "spki": {
      cryptoKey = await fromSPKI(pem, alg, { extractable });
      break;
    }
    case "x509": {
      cryptoKey = await fromX509(pem, alg, { extractable });
      break;
    }
    default: {
      throw new JWTError(`Unsupported PEM type: ${String(pemType)}`, "ERR_JWK_UNSUPPORTED");
    }
  }

  const jwk = await exportJWK<ImportedPEMJWK<A, Type>>(cryptoKey, options?.jwkParams);
  return { ...jwk, alg };
}

/**
 * Exports an asymmetric JWK as PEM: PKCS#8 when it carries `d`, SPKI otherwise.
 *
 * @throws `ERR_JWK_UNSUPPORTED` for `oct` JWKs or an unknown format or algorithm;
 *   `ERR_JWK_INVALID` for a missing `alg` or a `pemFormat` that contradicts the JWK's half.
 */
export async function exportPEM(
  jwk: JWK,
  options?: {
    /** PEM format. Inferred from the JWK shape when omitted. */
    pemFormat?: "pkcs8" | "spki";
    /** Algorithm hint used when `jwk.alg` is absent. */
    alg?: JWKPEMAlgorithm;
  },
): Promise<string> {
  assertPlainObject(jwk, "jwk");
  if (options !== undefined) assertPlainObject(options, "options");
  if (jwk.kty === "oct") {
    throw new JWTError(
      "An oct JWK cannot be exported to PKCS8 or SPKI PEM.",
      "ERR_JWK_UNSUPPORTED",
    );
  }

  const effectiveAlg = jwk.alg || options?.alg;
  if (!effectiveAlg && (jwk.kty === "RSA" || jwk.kty === "EC" || jwk.kty === "OKP")) {
    throw new JWTError(
      '"alg" is required, set it on the JWK or pass it in options.',
      "ERR_JWK_INVALID",
    );
  }
  if (effectiveAlg !== undefined && !PEM_ALGORITHMS.has(effectiveAlg)) {
    throw new JWTError(`Unsupported PEM algorithm: ${effectiveAlg}`, "ERR_JWK_UNSUPPORTED");
  }

  const pemFormat = options?.pemFormat ?? ("d" in jwk ? "pkcs8" : "spki");

  const cryptoKeyCandidate = await importKey(
    { ...jwk, ext: true },
    {
      alg: effectiveAlg,
      expect: pemFormat === "pkcs8" ? "private" : "public",
      extractable: true,
    },
  );

  if (!isCryptoKey(cryptoKeyCandidate)) {
    throw new JWTError(
      "Failed to convert JWK to a CryptoKey instance suitable for PEM export.",
      "ERR_JWK_INVALID",
    );
  }
  const cryptoKey = cryptoKeyCandidate;

  switch (pemFormat) {
    case "pkcs8": {
      if (cryptoKey.type !== "private") {
        throw new JWTError(
          `Only a private CryptoKey can be exported to PKCS8 PEM (got ${cryptoKey.type}).`,
          "ERR_JWK_INVALID",
        );
      }
      return toPKCS8(cryptoKey);
    }
    case "spki": {
      if (cryptoKey.type !== "public") {
        throw new JWTError(
          `Only a public CryptoKey can be exported to SPKI PEM (got ${cryptoKey.type}).`,
          "ERR_JWK_INVALID",
        );
      }
      return toSPKI(cryptoKey);
    }
    default: {
      throw new JWTError(`Unsupported PEM format: ${String(pemFormat)}`, "ERR_JWK_UNSUPPORTED");
    }
  }
}

function inferPEMType(pem: string): "pkcs8" | "spki" | "x509" | undefined {
  if (pem.includes("-----BEGIN PRIVATE KEY-----")) return "pkcs8";
  if (pem.includes("-----BEGIN PUBLIC KEY-----")) return "spki";
  if (pem.includes("-----BEGIN CERTIFICATE-----")) return "x509";
  return undefined;
}

/** Algorithms the PEM helpers round-trip; `satisfies` keeps them in lockstep with the union. */
const PEM_ALGORITHMS: ReadonlySet<string> = /* @__PURE__ */ new Set(
  Object.keys({
    "PS256": true,
    "PS384": true,
    "PS512": true,
    "RS256": true,
    "RS384": true,
    "RS512": true,
    "RSA-OAEP": true,
    "RSA-OAEP-256": true,
    "RSA-OAEP-384": true,
    "RSA-OAEP-512": true,
    "ES256": true,
    "ES384": true,
    "ES512": true,
    "ECDH-ES": true,
    "ECDH-ES+A128KW": true,
    "ECDH-ES+A192KW": true,
    "ECDH-ES+A256KW": true,
    "Ed25519": true,
    "EdDSA": true,
  } satisfies Record<JWKPEMAlgorithm, true>),
);
