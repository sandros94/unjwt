# Utils Reference (unjwt/utils)

Encoding, type guards, JWT claim validation, and sanitization utilities.

Import: `import { ... } from "unjwt/utils"`

Every name below is also a named export of the root entry point `unjwt` — it re-exports this whole module flat, no namespace objects.

`secureRandomBytes`, the sanitizers and `textEncoder`/`textDecoder` are re-exported from the [`unsecure`](https://github.com/sandros94/unsecure) package; the Base64 helpers are thin unjwt wrappers over unsecure's `base64Stringify`/`base64Parse` with the alphabet fixed. Failures inside them surface as unsecure's `UnsecureError` (`code`: `MALFORMED`, `INVALID_TYPE`, …), not native `TypeError`/`SyntaxError`.

`UnsecureError`, `UnsecureErrorCode` and `isUnsecureError` are re-exported from this module (and from `unjwt`, `unjwt/jws`, `unjwt/jwe`, `unjwt/jwk`). Because `unsecure` is inlined into unjwt's dist, a consumer-installed `unsecure` exposes a _different_ class — `instanceof` only matches unjwt's re-export. These primitives throw `UnsecureError` directly; the JOSE operations (`verify`, `decrypt`, `importKey`, `unwrapKey`, `importPEM`, …) wrap it in a `JWTError` and keep the original as `cause`.

## Encoding / Decoding

unjwt's own base64 helpers, built on [`unsecure`](https://github.com/sandros94/unsecure)'s `base64Stringify`/`base64Parse` with the alphabet and padding policy fixed. Strict: decoding accepts only the canonical encoding of a byte string and throws `UnsecureError` (`code: "MALFORMED"`; `"INVALID_TYPE"` for a non text/bytes input) otherwise. `{ loose: true }` drops what cannot be used — application data only, never token material; `verify`/`decrypt` have no such option.

### `base64UrlStringify(data)` / `base64UrlParse(data, options?)`

base64url per RFC 7515 §2: URL-safe alphabet, **no `=` padding** (padded input is rejected), no whitespace. `data`: `string | ArrayBuffer | ArrayBufferView`.

- Without `options` the return type **mirrors the input**: `string` → `string` (must be valid UTF-8), `Uint8Array` → `Uint8Array<ArrayBuffer>`.
- `{ returnAs: "uint8array" }` (alias `"bytes"`) forces bytes, `{ returnAs: "string" }` forces a UTF-8 string.

```ts
base64UrlParse("SGVsbG8"); // → "Hello"
base64UrlParse("SGVsbG8", { returnAs: "uint8array" }); // → Uint8Array<ArrayBuffer>
base64UrlParse(bytesInput); // → Uint8Array<ArrayBuffer>
base64UrlParse("SGVsbG8="); // throws UnsecureError MALFORMED
```

### `base64Stringify(data)` / `base64Parse(data, options?)`

Standard base64 per RFC 4648 §4: `+/` alphabet, **`=` padding required**. Same options as the URL-safe pair.

### `secureRandomBytes(length)`

Returns a cryptographically secure `Uint8Array<ArrayBuffer>` of the specified length via `crypto.getRandomValues`.

> Re-exported from `unsecure/random`. There is no `randomBytes` alias — use `secureRandomBytes`.

### `digestUrl(data, hash?)`

Base64url digest of text (UTF-8) or `Uint8Array` under `hash: "SHA-256" | "SHA-384" | "SHA-512"` (`DigestHash`, default `"SHA-256"`); the last step of `thumbprint()`. DPoP proof creation and verification are available through `unjwt/dpop`; see [dpop.md](dpop.md). `cnf.jkt` is the public key thumbprint; `ath` is the exact access token digest.

### `concatUint8Arrays(...arrays)`

Concatenates multiple `Uint8Array<ArrayBuffer>` instances into one contiguous buffer.

## Constants

- `textEncoder` — singleton `TextEncoder`
- `textDecoder` — singleton `TextDecoder`

## Type Guards

| Function | Returns | Checks |
| --- | --- | --- |
| `isJWK(key)` | `key is JWK` | Modelled JWK (`kty` is `oct`/`RSA`/`EC`/`OKP`) |
| `isJWKSet(key)` | `key is JWKSet` | Object with `keys` array |
| `isCryptoKey(key)` | `key is CryptoKey` | CryptoKey instance |
| `isCryptoKeyPair(key)` | `key is CryptoKeyPair` | Object with `publicKey` + `privateKey` CryptoKeys |
| `isSymmetricJWK(key)` | `key is JWK_oct` | JWK with `kty: "oct"` and `k` property |
| `isAsymmetricJWK(key)` | `key is JWK_Asymmetric` | JWK that is not `oct` |
| `isPrivateJWK(key)` | `key is JWK_Private` | **Asymmetric** JWK with `d` (returns `false` for `oct`) |
| `isPublicJWK(key)` | `key is JWK_Public` | Asymmetric JWK with its public members, without `d` or `k` |
| `assertCryptoKey(key)` | assertion | Throws if not CryptoKey |

> **Sharing keys safely.** `!isPrivateJWK(key)` is _not_ a "safe to publish" check — `isPrivateJWK` only detects asymmetric `d`, so it returns `false` for every `oct` key, whose `k` is always secret. Use `isPublicJWK(key)` (true only for asymmetric public keys) to filter keys that are safe to share; treat any `isSymmetricJWK(key)` as secret.

## JWT Utilities

### `computeDurationInSeconds(duration)`

Converts a `Duration` (integer seconds or shorthand string) into a positive integer number of seconds. Throws if `duration <= 0`.

- `Duration` accepts: `number` (already seconds), or string with unit — `"30s"`, `"10m"`, `"2h"`, `"7D"`, `"1W"`, `"3M"`, `"1Y"` (also long forms: `"minutes"`, `"hours"`, `"days"`, `"weeks"`, `"months"`, `"years"`).
- `ExpiresIn`, `NotBeforeIn`, and `MaxTokenAge` are all aliases of `Duration`.

### `validateJwtClaims(claims, options?)`

Validates JWT claims against `JWTClaimValidationOptions`. Throws `JWTError` on failure. Checks: `exp`, `nbf`, `iat`, `iss`, `sub`, `aud`, `maxTokenAge`, `requiredClaims`.

Each expectation is checked when it is set (`!== undefined`), never skipped for being empty: `audience` / `issuer` are a non-empty string or an array of non-empty strings, `subject` a non-empty string, `requiredClaims` an array of strings and `maxTokenAge` a positive duration — anything else throws `ERR_INVALID_OPTION`. An empty `audience` or `issuer` list is a check no token satisfies.

`exp`, `nbf`, and `iat` are strictly validated per RFC 7519 §4.1 — if the claim is present but not a finite number (string, `null`, `NaN`, etc.) the function throws `ERR_JWT_CLAIM_INVALID` rather than silently skipping the comparison.

```ts
interface JWTClaimValidationOptions {
  /** Expected `aud` value(s). Presence becomes required. The claim is checked
   * only when this option is set: a token carrying `aud` is accepted by a
   * caller that configures none. */
  audience?: string | string[];
  /** Expected `iss` value(s). Presence becomes required. */
  issuer?: string | string[];
  /** Expected `sub` value. Presence becomes required. */
  subject?: string;
  /** Maximum token age, measured from the `iat` claim. Accepts `Duration`. */
  maxTokenAge?:
    | number
    | `${number}`
    | `${number}${"s" | "second" | "seconds" | "m" | "minute" | "minutes" | "h" | "hour" | "hours" | "D" | "day" | "days" | "W" | "week" | "weeks" | "M" | "month" | "months" | "Y" | "year" | "years"}`;
  /** Clock skew tolerance for `nbf` / `exp` / `iat`: seconds, or a `Duration`. Defaults to 0. */
  clockTolerance?: number | Duration;
  /** Expected `typ` header value. */
  typ?: string;
  /** Reference moment for NumericDate comparisons. Defaults to `new Date()`. */
  currentDate?: Date;
  /** Additional required claim names beyond those implied by the options above. */
  requiredClaims?: string[];
  /**
   * Critical header parameters this caller understands and has processed.
   * Verification fails if the token's `crit` header lists a parameter not
   * in this list (per RFC 7515 §4.1.11 / RFC 7516 §4.1.13).
   */
  recognizedHeaders?: string[];
}
```

### `inferJWSAllowedAlgorithms(key)`

Returns the set of JWS signing algorithms a given key can unambiguously produce, or `undefined` when inference is not possible. Used by `verify()` as the default allowlist when `options.algorithms` is omitted. Returns `undefined` for raw `Uint8Array` keys, JWKs without `alg` or whose `alg` is not a JWS algorithm, lookup functions, or an HMAC/RSA `CryptoKey` whose hash is not SHA-256/384/512 — callers with those shapes must pass `algorithms` explicitly.

### `inferJWEAllowedAlgorithms(key)`

Returns the set of JWE key-management algorithms a given key can unambiguously handle, or `undefined` when inference is not possible. Used by `decrypt()` as the default allowlist when `options.algorithms` is omitted.

- A password `string` infers the three PBES2 variants.
- A raw `Uint8Array` infers nothing — bytes carry no role, so the caller names the algorithm.
- An `oct` JWK infers its own `alg` alone, except that an `alg` naming a content encryption algorithm (`A*GCM`, `A*CBC-HS*`) is a CEK and infers `"dir"`; an `alg` that is not a key management algorithm (an `HS*` key) infers nothing.
- An EC or OKP JWK without an `alg` infers the four ECDH-ES variants from its `crv`.

## Helper Functions

### `maybeArray(item)`

Wraps a value in an array if it isn't one already.

### `isJWTContent(header)`

Returns `true` when headers indicate JWT/JSON content: a `typ` naming JWT, or a JSON `cty`. A non-string `typ`/`cty` indicates nothing (returns `false`, never throws). Informational only — `verify()` and `decrypt()` read the payload under the caller's `payload` option and never consult `typ`/`cty`.

## Internal plumbing (`unjwt/internal`)

**Internal: for tests and tooling only. No semver guarantee — any export may change or disappear in any release. Not for production use.** Production code uses `unjwt/jws`, `unjwt/jwe`, `unjwt/utils`. Not re-exported from the root `unjwt`.

Import: `import { ... } from "unjwt/internal"`

- `applyTypDefault(header, payload)` — sets `typ: "JWT"` on an object payload's header when it has none; never adds a `cty`; mutates the header in place.
- `parsePayloadBytes(bytes, options?)` / `parsePayloadSegment(segment, options?)` — a verified/decrypted payload under a declared mode; the return type follows `options.payload` (`parsePayloadBytes<MyClaims>(bytes)` names the JSON shape, as `verify<MyClaims>` does). `options.payload?: "json" | "string" | "bytes"` — `"json"` (default) requires UTF-8 JSON naming a non-null, non-array object; `"string"` requires valid UTF-8; `"bytes"` returns the input. `options.family?: "JWS" | "JWE"` picks the rejection code (`ERR_JWS_INVALID` by default). Options type: `ParsePayloadOptions`.
- `parsePayloadText(bytes, options?)` — payload bytes as UTF-8 text, `options.family` as above.
- `getPlaintextBytes(payload)` — `string | Uint8Array | object` to bytes; a non-serializable object is `ERR_INVALID_OPTION`.
- `computeJwtTimeClaims(payload, options?)` — `iat` plus `exp`/`nbf` from `issuedAt`/`expiresIn`/`expiresAt`/`notBeforeIn`/`notBeforeAt` (`ComputeJwtTimeClaimsOptions`, an alias of `JWTTimeClaimOptions` — the base `JWSSignOptions` and `JWEEncryptOptions` extend).
- `validateCriticalHeadersJWS(header, recognized?)` / `validateCriticalHeadersJWE(header, recognized?)` — RFC 7515 §4.1.11 / RFC 7516 §4.1.13 `crit` processing.
- `assertCritShape(crit, { family, code? })` — `crit` is a non-empty string array naming no registered header parameter.
- `expiredClaimMessage(exp)` — the `ERR_JWT_EXPIRED` message for an `exp` (NumericDate, seconds) that has passed; the session adapters raise the same text for an in-memory expiry.

## Utility Types

`JWTClaims` types `iss`, `sub`, `aud`, `exp`, `nbf`, `iat`, `jti` and `cnf` (`JWTConfirmation`, RFC 7800 §3.1: `jwk`, `jwe`, `kid`, `jku`, plus `jkt` of RFC 9449 and `x5t#S256` of RFC 8705); `cnf` is never validated, the application compares it to the presented key.

```ts
// Strict version of Omit. `K` accepts real keys of `T` plus arbitrary string /
// number / symbol literals so future-proofing against renames stays type-safe.
type StrictOmit<T, K extends keyof T | (string & {}) | (number & {}) | (symbol & {})> = {
  [P in keyof T as P extends K ? never : P]: T[P];
};
```
