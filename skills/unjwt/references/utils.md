# Utils Reference (unjwt/utils)

Encoding, type guards, JWT claim validation, and sanitization utilities.

Import: `import { ... } from "unjwt/utils"` — most symbols are also available from `"unjwt"` directly. The internal helpers (`applyTypCtyDefaults`, `computeJwtTimeClaims`, `validateCriticalHeadersJWS`, `validateCriticalHeadersJWE`, `decodePayloadFromBytes`, `decodePayloadFromB64UrlSegment`, `decodeMaybeJWTString`, `getPlaintextBytes`, `isJWTContent`) are only exported from `"unjwt/utils"`.

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
| `isJWKSet(key)`        | `key is JWKSet`         | Object with `keys` array of JWKs                  |
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

- `ExpiresIn` accepts: `number` (already seconds), or string with unit — `"30s"`, `"10m"`, `"2h"`, `"7D"`, `"1W"`, `"3M"`, `"1Y"` (also `"minutes"`, `"hours"`, `"days"`, `"weeks"`, `"months"`, `"years"`)

### `validateJwtClaims(claims, options?)`

Validates JWT claims. Throws on failure. Checks: `exp`, `nbf`, `iat`, `iss`, `sub`, `aud`, `maxTokenAge`, `requiredClaims`.

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
  requiredHeaders?: string[];
}
```

### `sanitizeObject(obj)`

Recursively removes prototype-pollution vectors (`__proto__`, `prototype`, `constructor`) from objects. Applied internally to all parsed JWT headers and JWK data. Returns the same reference.

## Helper Functions

### `maybeArray(item)`

Wraps a value in an array if it isn't one already.

### `applyTypCtyDefaults(header, payload)`

Sets `typ: "JWT"` for object payloads when `typ` is undefined.

### `isJWTContent(header)`

Returns `true` when headers indicate JWT/JSON content.

### `getPlaintextBytes(payload)`

Converts `string | Uint8Array | Record<string, any>` to `Uint8Array` bytes.

## Utility Types

```ts
// Strict version of Omit that constrains K to actual keys of T
type StrictOmit<T, K extends keyof T> = { [P in keyof T as P extends K ? never : P]: T[P] };
```
