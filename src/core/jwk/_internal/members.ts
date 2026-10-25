import type { JWK } from "../../types/index.ts";
import { JWTError } from "../../../error.ts";
import { thumbprint } from "../../_crypto/index.ts";

/** JWK members derived from the key itself, which caller metadata may not set. */
const RESERVED_JWK_PARAMS = new Set([
  "kty",
  "alg",
  "key_ops",
  "ext",
  "k",
  "d",
  "n",
  "e",
  "p",
  "q",
  "dp",
  "dq",
  "qi",
  "oth",
  "x",
  "y",
  "crv",
]);

export function assertNoReservedJWKParams(jwkParams: object): void {
  const reserved = Object.keys(jwkParams).filter((name) => RESERVED_JWK_PARAMS.has(name));
  if (reserved.length > 0) {
    throw new JWTError(
      `jwkParams must not set reserved JWK members: ${reserved.join(", ")}`,
      "ERR_INVALID_OPTION",
    );
  }
}

/** A `kid` option is a string, `false` or absent; anything else is refused, not ignored. */
export function assertKidOption(kid: unknown): string | false | undefined {
  if (kid === undefined || kid === false || typeof kid === "string") return kid;
  throw new JWTError('"kid" must be a string or false.', "ERR_INVALID_OPTION");
}

/** Names a fresh JWK by the given `kid`, by none for `false`, else by its RFC 7638 thumbprint. */
export async function withGeneratedKid<T extends JWK>(
  kid: string | false | undefined,
  jwk: T,
): Promise<T> {
  if (kid === false) return jwk;
  return { ...jwk, kid: kid ?? (await thumbprint(jwk)) };
}

/** The usages a caller's `keyUsage` left on the key, to travel as `key_ops`; none when the option was not given. */
export function requestedKeyOps(
  options: { keyUsage?: KeyUsage[] },
  key: CryptoKey,
): KeyUsage[] | undefined {
  return options.keyUsage === undefined ? undefined : [...key.usages];
}

export function withKeyOps<J extends JWK>(jwk: J, keyOps: KeyUsage[] | undefined): J {
  return keyOps === undefined ? jwk : { ...jwk, key_ops: keyOps };
}
