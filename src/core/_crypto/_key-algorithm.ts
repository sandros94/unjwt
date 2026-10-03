/**
 * Reads of the family-specific members of a `CryptoKey`'s `algorithm`. Each
 * returns `undefined` when the algorithm does not carry the member.
 */

/** `namedCurve` of an EC algorithm (`ECDSA`, `ECDH`). */
export function namedCurveOf(algorithm: KeyAlgorithm): string | undefined {
  return "namedCurve" in algorithm && typeof algorithm.namedCurve === "string"
    ? algorithm.namedCurve
    : undefined;
}

/** The curve a key agrees on: its EC `namedCurve`, or `X25519` for an X25519 key. */
export function cryptoKeyCurve(key: CryptoKey): string | undefined {
  const { algorithm } = key;
  return namedCurveOf(algorithm) ?? (algorithm.name === "X25519" ? algorithm.name : undefined);
}

/** `hash.name` of a hashed algorithm (`HMAC`, `RSASSA-PKCS1-v1_5`, `RSA-PSS`, `RSA-OAEP`). */
export function hashNameOf(algorithm: KeyAlgorithm): string | undefined {
  if (!("hash" in algorithm)) return undefined;
  const { hash } = algorithm;
  return typeof hash === "object" &&
    hash !== null &&
    "name" in hash &&
    typeof hash.name === "string"
    ? hash.name
    : undefined;
}

/** `length` of an AES algorithm, in bits. */
export function lengthOf(algorithm: KeyAlgorithm): number | undefined {
  return "length" in algorithm && typeof algorithm.length === "number"
    ? algorithm.length
    : undefined;
}

/** `modulusLength` of an RSA algorithm, in bits. */
export function modulusLengthOf(algorithm: KeyAlgorithm): number | undefined {
  return "modulusLength" in algorithm && typeof algorithm.modulusLength === "number"
    ? algorithm.modulusLength
    : undefined;
}
