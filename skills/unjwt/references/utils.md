# Utils Reference (unjwt/utils)

Encoding, type guards, JWT claim validation, and sanitization utilities.

Import: `import { ... } from "unjwt/utils"`

These primitives are re-exported from the [`unsecure`](https://github.com/sandros94/unsecure) package. Typings and options listed here match the current re-exports.

## Encoding / Decoding

### `base64UrlEncode(data)`

Encodes `Uint8Array<ArrayBuffer> | string` to Base64URL (no padding). Returns `string`. Empty inputs return `""`. Throws `TypeError` on `null` / `undefined`.

### `base64UrlDecode(data, options?)`

Decodes a Base64URL string (or raw bytes). The second argument is an options object, **not** a boolean.

- When `options` is omitted the return type **mirrors the input**: `string` input decodes to `string`, `Uint8Array<ArrayBuffer>` input decodes to `Uint8Array<ArrayBuffer>`.
- Pass `{ returnAs: "uint8array" }` (or `"bytes"`) to always get raw bytes, or `{ returnAs: "string" }` to always get a UTF-8 string.

```ts
base64UrlDecode("SGVsbG8"); // → "Hello"
base64UrlDecode("SGVsbG8", { returnAs: "uint8array" }); // → Uint8Array<ArrayBuffer>
base64UrlDecode(bytesInput); // → Uint8Array<ArrayBuffer>
base64UrlDecode(bytesInput, { returnAs: "string" }); // → "Hello"
```

### `base64Encode(data)` / `base64Decode(data, options?)`

Standard (non-URL-safe) Base64 variants. Same shape as the URL-safe versions above.

### `secureRandomBytes(length)`

Returns a cryptographically secure `Uint8Array<ArrayBuffer>` of the specified length via `crypto.getRandomValues`.

> Re-exported from `unsecure/random`. There is no `randomBytes` alias — use `secureRandomBytes`.

### `concatUint8Arrays(...arrays)`

Concatenates multiple `Uint8Array<ArrayBuffer>` instances into one contiguous buffer.

## Constants

- `textEncoder` — singleton `TextEncoder`
- `textDecoder` — singleton `TextDecoder`

## Type Guards

| Function               | Returns                 | Checks                                            |
| ---------------------- | ----------------------- | ------------------------------------------------- |
| `isJWK(key)`           | `key is JWK`            | Valid JWK structure with `kty`                    |
| `isJWKSet(key)`        | `key is JWKSet`         | Object with `keys` array                          |
| `isCryptoKey(key)`     | `key is CryptoKey`      | CryptoKey instance                                |
| `isCryptoKeyPair(key)` | `key is CryptoKeyPair`  | Object with `publicKey` + `privateKey` CryptoKeys |
| `isSymmetricJWK(key)`  | `key is JWK_oct`        | JWK with `kty: "oct"` and `k` property            |
| `isAsymmetricJWK(key)` | `key is JWK_Asymmetric` | JWK that is not `oct`                             |
| `isPrivateJWK(key)`    | `key is JWK_Private`    | Asymmetric JWK with `d` component                 |
| `isPublicJWK(key)`     | `key is JWK_Public`     | Asymmetric JWK without `d` component              |
| `assertCryptoKey(key)` | assertion               | Throws if not CryptoKey                           |

## JWT Utilities

### `computeDurationInSeconds(duration)`

Converts a `Duration` (integer seconds or shorthand string) into a positive integer number of seconds. Throws if `duration <= 0`.

- `Duration` accepts: `number` (already seconds), or string with unit — `"30s"`, `"10m"`, `"2h"`, `"7D"`, `"1W"`, `"3M"`, `"1Y"` (also long forms: `"minutes"`, `"hours"`, `"days"`, `"weeks"`, `"months"`, `"years"`).
- `ExpiresIn`, `NotBeforeIn`, and `MaxTokenAge` are all aliases of `Duration`.
- `computeMaxTokenAgeSeconds(duration)` is the deprecated former name, kept for backward-compat — prefer `computeDurationInSeconds` in new code.
- `computeExpiresInSeconds(duration)` is the deprecated former name, kept for backward-compat — prefer `computeDurationInSeconds` in new code.

### `validateJwtClaims(claims, options?)`

Validates JWT claims against `JWTClaimValidationOptions`. Throws `JWTError` on failure. Checks: `exp`, `nbf`, `iat`, `iss`, `sub`, `aud`, `maxTokenAge`, `requiredClaims`.

`exp`, `nbf`, and `iat` are strictly validated per RFC 7519 §4.1 — if the claim is present but not a finite number (string, `null`, `NaN`, etc.) the function throws `ERR_JWT_CLAIM_INVALID` rather than silently skipping the comparison.

```ts
interface JWTClaimValidationOptions {
  /** Expected `aud` value(s). Presence becomes required. */
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
  /** Clock skew tolerance (seconds) for `nbf` / `exp` / `iat`. Defaults to 0. */
  clockTolerance?: number;
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

Returns the set of JWS signing algorithms a given key can unambiguously produce, or `undefined` when inference is not possible. Used by `verify()` as the default allowlist when `options.algorithms` is omitted. Returns `undefined` for raw `Uint8Array` keys, JWKs without `alg`, or lookup functions — callers with those shapes must pass `algorithms` explicitly.

### `inferJWEAllowedAlgorithms(key)`

Returns the set of JWE key-management algorithms a given key can unambiguously handle, or `undefined` when inference is not possible. Used by `decrypt()` as the default allowlist when `options.algorithms` is omitted. Passwords (`string` / `Uint8Array`) infer to the three PBES2 variants plus `"dir"`; symmetric keys infer to their specific wrap alg plus `"dir"`.

## Helper Functions

### `maybeArray(item)`

Wraps a value in an array if it isn't one already.

### `applyTypCtyDefaults(header, payload)`

Sets `typ: "JWT"` for object payloads when `typ` is undefined. Mutates the header in place (internal use only — always called on freshly constructed objects).

### `isJWTContent(header)`

Returns `true` when headers indicate JWT/JSON content.

### `getPlaintextBytes(payload)`

Converts `string | Uint8Array | Record<string, unknown>` to `Uint8Array` bytes.

## Utility Types

```ts
// Strict version of Omit. `K` accepts real keys of `T` plus arbitrary string /
// number / symbol literals so future-proofing against renames stays type-safe.
type StrictOmit<T, K extends keyof T | (string & {}) | (number & {}) | (symbol & {})> = {
  [P in keyof T as P extends K ? never : P]: T[P];
};
```
