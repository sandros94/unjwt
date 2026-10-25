import { JWTError } from "../core/error.ts";
import { exportJWK } from "../core/jwk.ts";
import { base64UrlParse, base64UrlStringify } from "../core/utils/base64.ts";
import { inferJWSAllowedAlgorithms } from "../core/utils/algorithms.ts";
import { isCryptoKey, isPlainObject, isPrivateJWK } from "../core/utils/guards.ts";
import type { JWSAsymmetricPublicJWK } from "../core/types/jws.ts";
import type { DPoPAlgorithm, DPoPKeyPair } from "./types.ts";
import { assertDPoPAlgorithm, type DPoPValidationCode } from "./_validation.ts";

const PRIVATE_MEMBERS = ["d", "p", "q", "dp", "dq", "qi", "oth", "k"];

export function resolveProofAlgorithm(
  pair: DPoPKeyPair,
  options: { algorithm?: DPoPAlgorithm },
): DPoPAlgorithm {
  let algorithm: unknown = options.algorithm;
  if (algorithm === undefined) {
    if (!isPlainObject(pair) || !isPrivateJWK(pair.privateKey) || !isPlainObject(pair.publicKey)) {
      throw new JWTError(
        "DPoP algorithm inference requires an asymmetric JWK pair; provide algorithm for CryptoKey pairs.",
        "ERR_INVALID_OPTION",
      );
    }
    algorithm = pair.privateKey.alg === undefined ? pair.publicKey.alg : pair.privateKey.alg;
    if (algorithm === undefined) {
      const candidates = inferJWSAllowedAlgorithms(pair.privateKey);
      if (candidates?.length !== 1) {
        throw new JWTError(
          "DPoP signing algorithm is ambiguous; provide algorithm or JWK alg metadata.",
          "ERR_INVALID_OPTION",
        );
      }
      algorithm = candidates[0];
    }
  }
  assertDPoPAlgorithm(algorithm, "ERR_INVALID_OPTION");
  return algorithm;
}

export async function publicKeyForProof(
  pair: DPoPKeyPair,
  algorithm: DPoPAlgorithm,
): Promise<JWSAsymmetricPublicJWK> {
  if (!isPlainObject(pair)) {
    throw new JWTError("DPoP keyPair must supply privateKey and publicKey.", "ERR_INVALID_OPTION");
  }
  const { privateKey, publicKey } = pair;
  if (isCryptoKey(privateKey) && isCryptoKey(publicKey)) {
    if (privateKey.type !== "private" || publicKey.type !== "public" || !publicKey.extractable) {
      throw new JWTError(
        "DPoP requires a private signing key and an extractable public key.",
        "ERR_INVALID_OPTION",
      );
    }
    if (!inferJWSAllowedAlgorithms(publicKey)?.includes(algorithm)) {
      throw new JWTError(
        "DPoP public key is incompatible with the signing algorithm.",
        "ERR_INVALID_OPTION",
      );
    }
    return projectPublicKey(await exportJWK(publicKey), { algorithm, code: "ERR_INVALID_OPTION" });
  }
  if (!isPrivateJWK(privateKey) || isCryptoKey(publicKey)) {
    throw new JWTError(
      "DPoP keyPair must be a CryptoKey pair or an asymmetric JWK pair.",
      "ERR_INVALID_OPTION",
    );
  }
  const jwk = projectPublicKey(publicKey, { algorithm, code: "ERR_INVALID_OPTION" });
  if (isPlainObject(publicKey) && publicKey.alg !== undefined) {
    assertDPoPAlgorithm(publicKey.alg, "ERR_INVALID_OPTION");
    if (!inferJWSAllowedAlgorithms(publicKey)?.includes(algorithm)) {
      throw new JWTError(
        "DPoP public JWK alg does not match the signing algorithm.",
        "ERR_INVALID_OPTION",
      );
    }
  }
  return jwk;
}

export function projectPublicKey(
  value: unknown,
  options: { algorithm: DPoPAlgorithm; code: DPoPValidationCode },
): JWSAsymmetricPublicJWK {
  if (!isPlainObject(value) || PRIVATE_MEMBERS.some((member) => Object.hasOwn(value, member))) {
    throw new JWTError(
      "DPoP jwk must be a public asymmetric JWK without private members.",
      options.code,
    );
  }
  const members =
    value.kty === "RSA"
      ? ["n", "e"]
      : value.kty === "EC"
        ? ["crv", "x", "y"]
        : value.kty === "OKP"
          ? ["crv", "x"]
          : undefined;
  if (
    !members ||
    members.some((name) => typeof value[name] !== "string" || value[name].length === 0)
  ) {
    throw new JWTError("DPoP jwk is missing required asymmetric public key members.", options.code);
  }
  if (members.some((name) => name !== "crv" && !isCanonicalBase64Url(value[name]))) {
    throw new JWTError("DPoP jwk members must be canonical unpadded base64url.", options.code);
  }
  const key = Object.fromEntries([
    ["kty", value.kty],
    ...members.map((name) => [name, value[name]]),
  ]);
  const supported =
    value.kty === "RSA"
      ? /^(?:RS|PS)(?:256|384|512)$/.test(options.algorithm)
      : inferJWSAllowedAlgorithms(key)?.includes(options.algorithm);
  if (!supported) {
    throw new JWTError("DPoP jwk is incompatible with the signing algorithm.", options.code);
  }
  // oxlint-disable-next-line typescript/no-unsafe-type-assertion -- required members and algorithm compatibility checked above
  return key as JWSAsymmetricPublicJWK;
}

function isCanonicalBase64Url(value: unknown): boolean {
  if (typeof value !== "string") return false;
  try {
    return base64UrlStringify(base64UrlParse(value, { returnAs: "bytes" })) === value;
  } catch {
    return false;
  }
}
