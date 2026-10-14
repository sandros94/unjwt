import { textEncoder } from "unsecure/utils";
import { base64UrlStringify } from "../utils/base64";
import { JWTError } from "../error";
import { assertPlainObject } from "../utils/guards";

import type { JWK } from "../types";

/** Hash functions RFC 7638 §3.4 leaves open to the application. */
export type ThumbprintHash = "SHA-256" | "SHA-384" | "SHA-512";

/** RFC 7638 §3.2 — each key type's required members, in lexicographic order. */
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
 * The base64url JWK Thumbprint of a key (RFC 7638), over its required members only, so a
 * public key and its private counterpart share one. `hash` defaults to `"SHA-256"`
 * (RFC 7638 §3.4); a missing required member or unknown `kty` throws `ERR_JWK_INVALID`.
 */
export async function thumbprint(
  jwk: JWK,
  options: { hash?: ThumbprintHash } = {},
): Promise<string> {
  assertPlainObject(jwk, "jwk");
  assertPlainObject(options, "options");
  const hash = options.hash ?? "SHA-256";
  if (!THUMBPRINT_HASHES.has(hash)) {
    throw new JWTError('"hash" must be "SHA-256", "SHA-384" or "SHA-512".', "ERR_INVALID_OPTION");
  }

  const kty: unknown = jwk.kty;
  const members =
    typeof kty === "string" && Object.hasOwn(THUMBPRINT_MEMBERS, kty)
      ? THUMBPRINT_MEMBERS[kty]
      : undefined;
  if (!members) {
    throw new JWTError(
      `JWK thumbprint is not defined for kty "${String(kty)}".`,
      "ERR_JWK_INVALID",
    );
  }

  const canonical = members.map((name) => {
    const value: unknown = Reflect.get(jwk, name);
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
