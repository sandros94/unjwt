// #region docs
import { importKey, type JWK_EC_Private } from "unjwt/jwk";

const raw = process.env.SIGNING_KEY;
if (!raw) throw new Error("SIGNING_KEY is not set");

/** The private half, for `sign()`. Never log it or send it anywhere. */
export const signingKey: JWK_EC_Private<"ES256"> = JSON.parse(raw);

// Fails at start-up, not on the first request, when the variable holds the wrong key.
await importKey(signingKey, { alg: "ES256", expect: "private" });
// #endregion
