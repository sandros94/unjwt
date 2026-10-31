import { textEncoder } from "unsecure/utils";
import { base64UrlStringify } from "./base64.ts";

/** The hash functions the JOSE specs name for digests in token members. */
export type DigestHash = "SHA-256" | "SHA-384" | "SHA-512";

/**
 * Returns the unpadded base64url digest of `data` under `hash`, `SHA-256` when omitted.
 * A string is digested as its UTF-8 bytes.
 * Examples: a DPoP `ath` (RFC 9449 §4.2), an `x5t#S256`, a JWK thumbprint.
 */
export async function digestUrl(
  data: string | Uint8Array<ArrayBuffer>,
  hash: DigestHash = "SHA-256",
): Promise<string> {
  const bytes = typeof data === "string" ? textEncoder.encode(data) : data;
  return base64UrlStringify(new Uint8Array(await crypto.subtle.digest(hash, bytes)));
}
