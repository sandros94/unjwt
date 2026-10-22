import { textEncoder } from "unsecure/utils";
import { base64UrlStringify } from "./base64.ts";

/** Hash functions the JOSE specs name for digests carried in tokens. */
export type DigestHash = "SHA-256" | "SHA-384" | "SHA-512";

/**
 * The base64url digest of text or bytes, SHA-256 unless `hash` says otherwise: a DPoP `ath`
 * (RFC 9449 §4.2) over the access token, an `x5t#S256` over a certificate, the last step of a
 * JWK thumbprint. Text is digested as UTF-8.
 */
export async function digestUrl(
  data: string | Uint8Array<ArrayBuffer>,
  hash: DigestHash = "SHA-256",
): Promise<string> {
  const bytes = typeof data === "string" ? textEncoder.encode(data) : data;
  return base64UrlStringify(new Uint8Array(await crypto.subtle.digest(hash, bytes)));
}
