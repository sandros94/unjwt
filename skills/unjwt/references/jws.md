# JWS Reference (unjwt/jws)

JSON Web Signature ([RFC 7515](https://www.rfc-editor.org/rfc/rfc7515.txt)) — sign and verify tokens.

Import: `import { sign, verify } from "unjwt/jws"` — or `from "unjwt"`

## Algorithms

| Family          | Identifiers               |
| --------------- | ------------------------- |
| HMAC            | `HS256`, `HS384`, `HS512` |
| RSA PKCS#1 v1.5 | `RS256`, `RS384`, `RS512` |
| RSA-PSS         | `PS256`, `PS384`, `PS512` |
| ECDSA           | `ES256`, `ES384`, `ES512` |
| EdDSA           | `Ed25519`, `EdDSA`        |

Type: `JWSAlgorithm`

## `sign(payload, key, options?)`

Creates a JWS Compact Serialization token.

**Parameters:**

- `payload` — `string | Uint8Array | Record<string, any>` (objects are JSON-serialized)
- `key` — `CryptoKey | JWK_Symmetric | JWK_Private | Uint8Array`
  - JWK keys infer `alg` automatically; CryptoKey/Uint8Array require `options.alg`
- `options?: JWSSignOptions`
  - `alg?: JWSAlgorithm` — required when key is CryptoKey or Uint8Array
  - `protectedHeader?: JWSHeaderParameters` — additional header params (`kid`, `typ`, `cty`, `crit`, `b64`)
  - `expiresIn?: ExpiresIn` — sets `exp` claim relative to `iat` (number in seconds, or string like `"1h"`, `"7D"`)
  - `currentDate?: Date` — override current time for `iat`/`exp` computation

**Returns:** `Promise<string>` — JWS compact token

**Behavior:**

- If payload is an object and `typ` is not set, defaults to `"JWT"`
- If `expiresIn` is set and `iat` is missing, `iat` is set to current time
- `b64: false` in header enables unencoded payload ([RFC 7797](https://www.rfc-editor.org/rfc/rfc7797.txt))
- When a JWK with a `kid` is used, the `kid` is added to the header as a fallback — an explicit `protectedHeader.kid` always takes precedence

```ts
import { sign } from "unjwt/jws";
import { generateJWK } from "unjwt/jwk";

// Symmetric (HMAC)
const hmacKey = await generateJWK("HS256");
const token = await sign({ sub: "user123" }, hmacKey);

// Asymmetric (RSA)
const rsaKeys = await generateJWK("RS256");
const token2 = await sign({ sub: "user123" }, rsaKeys.privateKey);

// With expiration
const token3 = await sign({ sub: "user123" }, hmacKey, { expiresIn: "1h" });
```

## `verify(jws, key, options?)`

Verifies a JWS token and returns its payload.

**Parameters:**

- `jws` — `string` — the JWS compact token
- `key` — `CryptoKey | JWK_Symmetric | JWK_Public | JWKSet | Uint8Array | JWKLookupFunction`
  - `JWKLookupFunction`: `(header, token) => key | JWKSet | Promise<key | JWKSet>` for dynamic key resolution
  - `JWKSet`: multi-key selection with automatic retry
    - Token has `kid` — only keys with that exact `kid` are tried (fast path, typically one key, no retry)
    - Token has no `kid` — all keys whose `alg` field is compatible are tried in order; the first to verify successfully wins
    - No matching candidates — throws `JWTError("ERR_JWK_KEY_NOT_FOUND")` before any crypto attempt
    - Same retry applies when a `JWKLookupFunction` returns a `JWKSet`

- `options?: JWSVerifyOptions`
  - `algorithms?: JWSAlgorithm[]` — allowlist of accepted algorithms
  - `validateJWT?: boolean` — parse as JWT and validate claims when `typ` is JWT-like
  - `forceUint8Array?: boolean` — force payload returned as `Uint8Array`
  - Inherits `JWTClaimValidationOptions`: `audience`, `issuer`, `subject`, `maxTokenAge`, `clockTolerance`, `typ`, `currentDate`, `requiredClaims`, `recognizedHeaders`

**Returns:** `Promise<JWSVerifyResult<T>>` — `{ payload: T, protectedHeader: JWSProtectedHeader }`

```ts
import { verify } from "unjwt/jws";

// With JWK
const { payload, protectedHeader } = await verify(token, hmacKey);

// With key lookup
const result = await verify(token, async (header) => fetchKeyByKid(header.kid), {
  algorithms: ["RS256"],
});

// With claim validation
const result2 = await verify(token, key, {
  issuer: "https://auth.example.com",
  audience: "my-app",
  maxTokenAge: "24h",
});
```

## Types

```ts
interface JWSSignOptions {
  alg?: JWSAlgorithm;
  protectedHeader?: JWSHeaderParameters;
  currentDate?: Date;
  expiresIn?: ExpiresIn;
}

interface JWSVerifyOptions extends JWTClaimValidationOptions {
  algorithms?: JWSAlgorithm[];
  forceUint8Array?: boolean;
  validateJWT?: boolean;
}

interface JWSVerifyResult<T> {
  payload: T;
  protectedHeader: JWSProtectedHeader; // alg is required
}

interface JWSHeaderParameters extends JoseHeaderParameters {
  alg?: JWSAlgorithm;
  b64?: boolean; // RFC 7797 unencoded payload
}

// JWSProtectedHeader is JWSHeaderParameters with alg required

// JWKLookupFunction is shared with JWE decrypt — imported from unjwt/jwk or unjwt
type JWKLookupFunction = (
  header: {
    kid?: string;
    alg?: string;
    enc?: string;
    typ?: string;
    crit?: string[];
    [key: string]: unknown;
  },
  token: string,
) => MaybePromise<CryptoKey | JWK | JWKSet | string | Uint8Array>;
```
