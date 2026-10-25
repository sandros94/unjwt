# DPoP (`unjwt/dpop`)

Optional RFC 9449 proof helpers. No root re-export, HTTP calls, key derivation, nonce generation or replay storage. Core/session entries never import this module.

```ts
import { createDPoPProof, verifyDPoPProof } from "unjwt/dpop";
import { generateJWK } from "unjwt/jwk";

const keyPair = await generateJWK("ES256");
const target = { method: "POST", url: "https://auth.example.com/token" };
const proof = await createDPoPProof(target, {
  keyPair,
});
const { payload, thumbprint } = await verifyDPoPProof(proof, target, {
  algorithms: ["ES256"],
  maxTokenAge: 60,
});
```

- Signatures: `createDPoPProof(target, options)` and `verifyDPoPProof(proof, target, options)`.
- Target (first argument of creation, second of verification): `{ method: string, url: string }`, including a Web `Request`. HTTP method is case-sensitive. URL comparison ignores query/fragment and normalizes HTTP URL syntax while preserving reserved escapes.
- Creation: explicit corresponding `{ privateKey, publicKey }` JWK pair or `CryptoKeyPair`, optional `algorithm` inferred from private JWK `alg`, then public JWK `alg`, then a single core key-shape candidate; optional `jti` defaults to a fresh UUID v4 per call and optional `iat` defaults to `Math.floor(Date.now() / 1000)`. Explicit overrides are validated, not replaced. Nonextractable private CryptoKey supported; public CryptoKey must export. No signature self-test. Optional `accessToken: { token }` (exact ASCII token string) adds `ath`; optional `nonce` copies the server challenge.
- Optional time restrictions: `exp?: number` and `nbf?: number` are absolute Unix timestamps in seconds, omitted by default. Creation rejects non-finite, negative or nonnumeric values. Verification enforces expiration and not-before with `clockTolerance`, in addition to the proof age limit.
- Signing algorithm: ambiguous JWKs (e.g. RSA without `alg`, Ed25519 without an algorithm spelling) and all `CryptoKeyPair` inputs require explicit `algorithm`. Explicit/inferred algorithms must be asymmetric and agree with key metadata. Symmetric JWKs, secret CryptoKeys, HMAC and `none` are rejected.
- Verification options: required asymmetric `algorithms`, positive finite numeric `maxTokenAge` seconds; optional nonnegative finite `clockTolerance` seconds (default 0), `currentDate` (default now), expected `nonce`.
- Resource verification: pass `accessToken: { token, thumbprint }`. `token` is the exact presented access token; `thumbprint` is its already authenticated `cnf.jkt`. Both the token hash and signing key binding must match. The helper does not validate the access token or authorize its use.
- Result: `{ payload, thumbprint }`. Proof claims include `jti`, `iat`, `htm`, `htu`; `exp`, `nbf`, `nonce` and `ath` may be present. Without the corresponding verification options, the presence of `nonce` or `ath` is not a verified nonce/token binding.
- Replay: optional `consumeProof(result): boolean | Promise<boolean>` runs last. Caller atomically checks and stores the proof ID, scoped to its key. Only `true` accepts. Store through `iat + maxTokenAge + clockTolerance`, inclusive; hash/bound storage keys. No hook means no replay tracking.
- Freshness always uses `iat`; a nonce does not replace the age check. Caller owns nonce issuance/validation policy and retries, HTTPS, exactly one DPoP header, the DPoP authorization scheme, token validity, permissions and replay storage.
- Errors: shared `JWTError`/`isJWTError` exports; `ERR_DPOP_INVALID`, `ERR_DPOP_CLAIM_INVALID`, `ERR_DPOP_REPLAY`, plus existing JWS/JWK and `ERR_INVALID_OPTION` codes. Callback failures preserve their cause.

When overriding `jti`, use a UUID v4 or at least 96 random bits. Reuse the key pair for its bound token's lifetime; create a new proof ID for each HTTP call.
