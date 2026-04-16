# Utils Reference (unjwt/utils)

Encoding, type guards, JWT claim validation, and sanitization utilities.

Import: `import { ... } from "unjwt/utils"`

## Encoding / Decoding

### `base64UrlEncode(data)`

Encodes `Uint8Array | string` to Base64URL (no padding). Returns `string`.

### `base64UrlDecode(str?, toString?)`

Decodes Base64URL string. Returns `string` by default, `Uint8Array` if `toString: false`.

### `base64Encode(data)` / `base64Decode(str?, toString?)`

Standard Base64 variants of the above.

### `randomBytes(length)`

Returns a cryptographically secure `Uint8Array` of the specified length via `crypto.getRandomValues`.

### `concatUint8Arrays(...arrays)`

Concatenates multiple `Uint8Array` instances into one.

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

### `computeExpiresInSeconds(expiresIn)`

Converts `ExpiresIn` to seconds.

- `ExpiresIn` accepts: `number` (already seconds), or string with unit — `"30s"`, `"10m"`, `"2h"`, `"7D"`, `"1W"`, `"3M"`, `"1Y"` (also long forms: `"minutes"`, `"hours"`, `"days"`, `"weeks"`, `"months"`, `"years"`)

### `validateJwtClaims(claims, options?)`

Validates JWT claims against `JWTClaimValidationOptions`. Throws `JWTError` on failure. Checks: `exp`, `nbf`, `iat`, `iss`, `sub`, `aud`, `maxTokenAge`, `requiredClaims`.

`exp`, `nbf`, and `iat` are strictly validated per RFC 7519 §4.1 — if the claim is present but not a finite number (string, `null`, `NaN`, etc.) the function throws `ERR_JWT_CLAIM_INVALID` rather than silently skipping the comparison.

```ts
interface JWTClaimValidationOptions {
  audience?: string | string[];
  issuer?: string | string[];
  subject?: string;
  maxTokenAge?: MaxTokenAge; // ExpiresIn
  clockTolerance?: number; // seconds
  typ?: string;
  currentDate?: Date;
  requiredClaims?: string[];
  /**
   * Critical header parameters this caller understands and has processed.
   * Verification fails if the token's `crit` header lists a parameter not
   * in this list (per RFC 7515 §4.1.11 / RFC 7516 §4.1.13).
   */
  recognizedHeaders?: string[];
}
```

### `sanitizeObject(obj)`

Returns a **deep structural copy** of `obj` with prototype-pollution vectors (`__proto__`, `prototype`, `constructor`) stripped at every level. The input is never modified. Applied internally to all parsed JWT headers and user-supplied option objects.

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
// Strict version of Omit that constrains K to actual keys of T
type StrictOmit<T, K extends keyof T> = { [P in keyof T as P extends K ? never : P]: T[P] };
```
