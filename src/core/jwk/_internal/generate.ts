import type {
  JWK,
  JWK_Asymmetric_Algorithm,
  JWKAlgorithm,
  GenerateKeyAlgorithm,
  GenerateKeyOptions,
} from "../../types/index.ts";
import { JWTError } from "../../../error.ts";
import { ECDSA_CURVES, aesBitsOf, jwsHashOf, rsaOaepHashOf } from "../../_crypto/_key-algorithm.ts";

export function getGenerateKeyParams(
  alg: GenerateKeyAlgorithm,
  options?: Omit<GenerateKeyOptions, "toJWK">,
): {
  algorithm: AlgorithmIdentifier | RsaHashedKeyGenParams | EcKeyGenParams;
  keyUsages: KeyUsage[];
} {
  let algorithm: AlgorithmIdentifier | AesKeyAlgorithm | RsaHashedKeyGenParams | EcKeyGenParams;
  let keyUsages: KeyUsage[];

  const requested = options?.keyUsage;
  const usage = (allowed: readonly KeyUsage[], fallback: KeyUsage[]): KeyUsage[] =>
    resolveKeyUsage(requested, { allowed, fallback, alg });
  const pairUsage = (allowed: readonly KeyUsage[], fallback: KeyUsage[]): KeyUsage[] =>
    assertPairUsages(usage(allowed, fallback), { fallback, alg });

  switch (alg) {
    case "HS256":
    case "HS384":
    case "HS512": {
      algorithm = {
        name: "HMAC",
        hash: jwsHashOf(alg),
      };
      keyUsages = usage(SIGNATURE_USAGES, ["sign", "verify"]);
      break;
    }

    case "RS256":
    case "RS384":
    case "RS512": {
      algorithm = {
        name: "RSASSA-PKCS1-v1_5",
        modulusLength: assertModulusLength(options?.modulusLength),
        publicExponent: assertPublicExponent(options?.publicExponent),
        hash: jwsHashOf(alg),
      };
      keyUsages = pairUsage(SIGNATURE_USAGES, ["sign", "verify"]);
      break;
    }

    case "PS256":
    case "PS384":
    case "PS512": {
      algorithm = {
        name: "RSA-PSS",
        modulusLength: assertModulusLength(options?.modulusLength),
        publicExponent: assertPublicExponent(options?.publicExponent),
        hash: jwsHashOf(alg),
      };
      keyUsages = pairUsage(SIGNATURE_USAGES, ["sign", "verify"]);
      break;
    }

    case "RSA-OAEP":
    case "RSA-OAEP-256":
    case "RSA-OAEP-384":
    case "RSA-OAEP-512": {
      algorithm = {
        name: "RSA-OAEP",
        modulusLength: assertModulusLength(options?.modulusLength),
        publicExponent: assertPublicExponent(options?.publicExponent),
        hash: rsaOaepHashOf(alg),
      };
      keyUsages = pairUsage(KEY_ENCRYPTION_USAGES, ["encrypt", "decrypt", "wrapKey", "unwrapKey"]);
      break;
    }

    case "A128KW":
    case "A192KW":
    case "A256KW": {
      algorithm = { name: "AES-KW", length: aesBitsOf(alg) };
      keyUsages = usage(KEY_WRAPPING_USAGES, ["wrapKey", "unwrapKey"]);
      break;
    }

    case "A128GCM":
    case "A192GCM":
    case "A256GCM":
    case "A128GCMKW":
    case "A192GCMKW":
    case "A256GCMKW": {
      algorithm = { name: "AES-GCM", length: aesBitsOf(alg) };
      // RFC 7518 §4.7: AES-GCMKW wraps by encrypting, so the key encrypts rather than wraps.
      keyUsages = usage(KEY_ENCRYPTION_USAGES, ["encrypt", "decrypt"]);
      break;
    }

    case "ES256":
    case "ES384":
    case "ES512": {
      const namedCurve = ECDSA_CURVES[alg];
      assertNamedCurve(options?.namedCurve, namedCurve, alg);
      algorithm = { name: "ECDSA", namedCurve };
      keyUsages = pairUsage(SIGNATURE_USAGES, ["sign", "verify"]);
      break;
    }
    case "Ed25519": {
      assertNamedCurve(options?.namedCurve, "Ed25519", alg);
      keyUsages = pairUsage(SIGNATURE_USAGES, ["sign", "verify"]);
      algorithm = { name: "Ed25519" };
      break;
    }
    case "EdDSA": {
      keyUsages = pairUsage(SIGNATURE_USAGES, ["sign", "verify"]);
      const namedCurve = options?.namedCurve ?? "Ed25519";
      if (namedCurve !== "Ed25519") {
        throw new JWTError("Unsupported namedCurve, expected Ed25519", "ERR_JWK_UNSUPPORTED");
      }
      algorithm = { name: namedCurve };
      break;
    }

    case "ECDH-ES":
    case "ECDH-ES+A128KW":
    case "ECDH-ES+A192KW":
    case "ECDH-ES+A256KW": {
      keyUsages = pairUsage(DERIVATION_USAGES, ["deriveBits"]);
      const namedCurve = options?.namedCurve ?? "P-256";
      switch (namedCurve) {
        case "P-256":
        case "P-384":
        case "P-521": {
          algorithm = { name: "ECDH", namedCurve };
          break;
        }
        case "X25519": {
          algorithm = { name: "X25519" };
          break;
        }
        default: {
          throw new JWTError(
            "Unsupported namedCurve, expected P-256, P-384, P-521 or X25519",
            "ERR_JWK_UNSUPPORTED",
          );
        }
      }
      break;
    }

    default: {
      throw new JWTError(
        `Unsupported or invalid algorithm for key generation: ${alg}`,
        "ERR_JWK_UNSUPPORTED",
      );
    }
  }

  return { algorithm, keyUsages };
}

/** A `namedCurve` contradicting the curve `alg` fixes is refused, not ignored. */
function assertNamedCurve(
  requested: string | undefined,
  expected: string,
  alg: GenerateKeyAlgorithm,
): void {
  if (requested === undefined || requested === expected) return;
  throw new JWTError(
    `"namedCurve" ${requested} contradicts ${alg}, which is defined over ${expected}.`,
    "ERR_INVALID_OPTION",
  );
}

/** RSA public exponents are big-endian byte strings — RFC 7518 §6.3.1.2. */
function assertPublicExponent(
  publicExponent: Uint8Array<ArrayBuffer> | undefined,
): Uint8Array<ArrayBuffer> {
  if (publicExponent === undefined) return new Uint8Array([0x01, 0x00, 0x01]);
  if (!(publicExponent instanceof Uint8Array) || publicExponent.length === 0) {
    throw new JWTError(
      '"publicExponent" must be the exponent\'s big-endian bytes as a Uint8Array.',
      "ERR_INVALID_OPTION",
    );
  }
  return publicExponent;
}

/** `key_ops` each algorithm family admits — a caller's `keyUsage` may narrow it. */
const SIGNATURE_USAGES: readonly KeyUsage[] = ["sign", "verify"];
const KEY_WRAPPING_USAGES: readonly KeyUsage[] = ["wrapKey", "unwrapKey"];
const KEY_ENCRYPTION_USAGES: readonly KeyUsage[] = ["encrypt", "decrypt", "wrapKey", "unwrapKey"];
const DERIVATION_USAGES: readonly KeyUsage[] = ["deriveBits", "deriveKey"];
export const CONTENT_ENCRYPTION_USAGES: readonly KeyUsage[] = ["encrypt", "decrypt"];

/** The caller's `keyUsage` when given (each entry one `alg` admits), else the default. */
export function resolveKeyUsage(
  requested: KeyUsage[] | undefined,
  options: { allowed: readonly KeyUsage[]; fallback: KeyUsage[]; alg: JWKAlgorithm },
): KeyUsage[] {
  const { allowed, fallback, alg } = options;
  if (requested === undefined) return fallback;
  if (!Array.isArray(requested) || requested.length === 0) {
    throw new JWTError('"keyUsage" must be a non-empty array.', "ERR_INVALID_OPTION");
  }
  const rejected = requested.filter((entry) => !allowed.includes(entry));
  if (rejected.length > 0) {
    throw new JWTError(
      `"keyUsage" ${rejected.join(", ")} cannot be served by ${alg}, use ${allowed.join(", ")}.`,
      "ERR_INVALID_OPTION",
    );
  }
  return requested;
}

/** The half of a generated pair each usage belongs to — RFC 7517 §4.3. */
const PRIVATE_KEY_USAGES: readonly KeyUsage[] = [
  "sign",
  "decrypt",
  "unwrapKey",
  "deriveBits",
  "deriveKey",
];
const PUBLIC_KEY_USAGES: readonly KeyUsage[] = ["verify", "encrypt", "wrapKey"];

/** Each pair half the default populates must keep a usage; ECDH public keys carry none. */
function assertPairUsages(
  usages: KeyUsage[],
  options: { fallback: KeyUsage[]; alg: JWKAlgorithm },
): KeyUsage[] {
  const { fallback, alg } = options;
  for (const [half, side] of [
    [PRIVATE_KEY_USAGES, "private"],
    [PUBLIC_KEY_USAGES, "public"],
  ] as const) {
    const wanted = fallback.filter((entry) => half.includes(entry));
    if (wanted.length === 0 || usages.some((entry) => half.includes(entry))) continue;
    throw new JWTError(
      `"keyUsage" leaves the ${side} half of a ${alg} key pair unusable, add ${wanted.join(" or ")}.`,
      "ERR_INVALID_OPTION",
    );
  }
  return usages;
}

/** RFC 7518 §3.3 — an RSA key is 2048 bits or larger. */
function assertModulusLength(modulusLength: number | undefined): number {
  const length = modulusLength ?? 2048;
  if (!Number.isInteger(length) || length < 2048) {
    throw new JWTError("modulusLength must be at least 2048 bits", "ERR_INVALID_OPTION");
  }
  return length;
}

/** The JWK with `alg` set to the algorithm it was produced for; `A` must be one its family serves. */
export function withAlg<J extends JWK, A extends NonNullable<J["alg"]>>(
  jwk: J,
  alg: A,
): J & { alg: A } {
  return { ...jwk, alg };
}

/** Web Crypto returned a key pair, so `alg` is one of the asymmetric algorithms `generateKey` admits. */
export function generatedPairAlgorithm(
  alg: GenerateKeyAlgorithm,
): Extract<GenerateKeyAlgorithm, JWK_Asymmetric_Algorithm> {
  // oxlint-disable-next-line typescript/no-unsafe-type-assertion -- the pair shape fixes the family; `getGenerateKeyParams` maps each `alg` to one
  return alg as Extract<GenerateKeyAlgorithm, JWK_Asymmetric_Algorithm>;
}

/** Web Crypto returned a single key, so `alg` is one of the symmetric algorithms `generateKey` admits. */
export function generatedSecretAlgorithm(
  alg: GenerateKeyAlgorithm,
): Exclude<GenerateKeyAlgorithm, JWK_Asymmetric_Algorithm> {
  // oxlint-disable-next-line typescript/no-unsafe-type-assertion -- the secret-key shape fixes the family; `getGenerateKeyParams` maps each `alg` to one
  return alg as Exclude<GenerateKeyAlgorithm, JWK_Asymmetric_Algorithm>;
}
