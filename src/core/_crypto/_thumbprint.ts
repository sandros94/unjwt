import { textEncoder } from "unsecure/utils";
import { base64UrlStringify } from "../utils/base64";
import { JWTError } from "../error";

import type { JWK } from "../types";

/** Hash functions RFC 7638 §3.4 leaves open to the application. */
export type ThumbprintHash = "SHA-256" | "SHA-384" | "SHA-512";

/**
 * RFC 7638 §3.2 — the required members of each key type, in the lexicographic
 * order the canonical form is built in.
 */
const THUMBPRINT_MEMBERS: Readonly<Record<string, readonly string[]>> =
  /* @__PURE__ */ Object.freeze({
    EC: ["crv", "kty", "x", "y"],
    RSA: ["e", "kty", "n"],
    OKP: ["crv", "kty", "x"],
    oct: ["k", "kty"],
  });

const THUMBPRINT_HASHES: ReadonlySet<string> = /* @__PURE__ */ new Set([
  "SHA-256",
  "SHA-384",
  "SHA-512",
] satisfies ThumbprintHash[]);

/**
 * The JWK Thumbprint of a key (RFC 7638): the digest of the key's required
 * members alone, as a JSON object with no whitespace and its member names in
 * lexicographic order.
 *
 * Only the members that make the key what it is take part — `kid`, `use`,
 * `alg`, `key_ops` and the private members do not — so a public key and its
 * private counterpart share one thumbprint, and two structurally identical
 * keys carry the same name however they are labelled.
 *
 * @param jwk The key to name. A missing required member or a `kty` the
 *        specification defines no members for throws `ERR_JWK_INVALID`.
 * @param options
 *   - `hash?` — `"SHA-256"` (the default of RFC 7638 §3.4), `"SHA-384"` or
 *     `"SHA-512"`.
 * @returns The base64url-encoded digest.
 */
export async function thumbprint(
  jwk: JWK,
  options: { hash?: ThumbprintHash } = {},
): Promise<string> {
  if (typeof jwk !== "object" || jwk === null) {
    throw new JWTError(
      `"jwk" must be a JWK object, got ${jwk === null ? "null" : typeof jwk}.`,
      "ERR_INVALID_OPTION",
    );
  }
  if (typeof options !== "object" || options === null) {
    throw new JWTError(
      `"options" must be an object, got ${options === null ? "null" : typeof options}.`,
      "ERR_INVALID_OPTION",
    );
  }
  const hash = options.hash ?? "SHA-256";
  if (!THUMBPRINT_HASHES.has(hash)) {
    throw new JWTError('"hash" must be "SHA-256", "SHA-384" or "SHA-512".', "ERR_INVALID_OPTION");
  }

  const members = THUMBPRINT_MEMBERS[jwk?.kty as string];
  if (!members) {
    throw new JWTError(`JWK thumbprint is not defined for kty "${jwk?.kty}".`, "ERR_JWK_INVALID");
  }

  const key = jwk as unknown as Record<string, unknown>;
  const canonical = members.map((name) => {
    const value = key[name];
    if (typeof value !== "string" || value.length === 0) {
      throw new JWTError(
        `JWK thumbprint requires the member "${name}" on an ${jwk.kty} key.`,
        "ERR_JWK_INVALID",
      );
    }
    return `${JSON.stringify(name)}:${JSON.stringify(value)}`;
  });

  const digest = await crypto.subtle.digest(hash, textEncoder.encode(`{${canonical.join(",")}}`));
  return base64UrlStringify(new Uint8Array(digest));
}
