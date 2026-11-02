// #region docs
import {
  deriveSharedSecret,
  type JWK_EC_Private,
  type JWK_EC_Public,
  type JWK_oct,
} from "unjwt/jwk";
import { base64UrlStringify } from "unjwt/utils";

const encoder = new TextEncoder();
// The same two labels on both sides, in the same order.
const partyUInfo = encoder.encode("billing.example.com");
const partyVInfo = encoder.encode("api.example.com");

/** Each service passes its own private key and the other service's public key. */
export async function channelKey(
  ownKey: JWK_EC_Private<"ECDH-ES">,
  peerKey: JWK_EC_Public<"ECDH-ES">,
): Promise<JWK_oct<"A256GCM">> {
  const secret = await deriveSharedSecret(peerKey, ownKey, {
    enc: "A256GCM",
    partyUInfo,
    partyVInfo,
  });
  return { kty: "oct", k: base64UrlStringify(secret), alg: "A256GCM", kid: "billing-api" };
}
// #endregion
