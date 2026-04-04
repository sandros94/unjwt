# JWK Reference (unjwt/jwk)

JSON Web Key ([RFC 7517](https://www.rfc-editor.org/rfc/rfc7517.txt)) — key generation, import/export, wrapping, and PEM conversion.

Import: `import { generateKey, generateJWK, importKey, exportKey, wrapKey, unwrapKey, importJWKFromPEM, exportJWKToPEM, deriveKeyFromPassword, deriveJWKFromPassword, getJWKFromSet } from "unjwt/jwk"` — or `from "unjwt"`

## Key Generation

Unless the user has specific key management needs, prefer to use `generateJWK()` for convenience and interoperability (e.g., JWK format provides ease of use for storage or transmission). Use `generateKey()` when they need more control over the output format or key generation parameters.

### `generateKey(alg, options?)`

Generates a cryptographic key as CryptoKey (or CryptoKeyPair, Uint8Array, or JWK depending on algorithm and options).

- `alg: GenerateKeyAlgorithm` — any JWS or JWE algorithm except `"none"`, `"dir"`, and PBES2
- `options?: GenerateKeyOptions`
  - `toJWK?: boolean | Partial<JWKParameters>` — return as JWK (optionally merge extra JWK params)
  - `extractable?: boolean` — default `true`
  - `keyUsage?: KeyUsage[]`
  - `modulusLength?: number` — RSA modulus length (default `2048`)
  - `namedCurve?` — `"P-256" | "P-384" | "P-521" | "X25519" | "Ed25519" | "Ed448"`

**Return type depends on `alg` and `toJWK`:**

- Symmetric + no toJWK → `CryptoKey` (or `Uint8Array` for AES-CBC-HS composite keys)
- Asymmetric + no toJWK → `CryptoKeyPair`
- Symmetric + toJWK → `JWK_oct`
- Asymmetric + toJWK → `{ privateKey: JWK_Private, publicKey: JWK_Public }`

### `generateJWK(alg, jwkParams?, options?)`

Convenience wrapper that always returns JWK format.

- `alg: GenerateKeyAlgorithm`
- `jwkParams?: Partial<JWKParameters>` — extra JWK fields (`kid`, `use`, etc.)
- `options?: GenerateJWKOptions` — same as `GenerateKeyOptions` minus `toJWK`

```ts
import { generateKey, generateJWK } from "unjwt/jwk";

const hmacCryptoKey = await generateKey("HS256");
const rsaKeyPair = await generateKey("RS256", { modulusLength: 4096 });
const aesJwk = await generateKey("A256GCM", { toJWK: true });

const ecKeys = await generateJWK("ES256", { kid: "ec-1" });
// → { privateKey: JWK_EC_Private, publicKey: JWK_EC_Public }
```

## Key Import/Export

### `importKey(key, alg?)`

Normalizes various key formats into CryptoKey or Uint8Array.

- `string` → encoded to `Uint8Array`
- `Uint8Array` → returned as-is
- `CryptoKey` → returned as-is
- `JWK_oct` → `k` decoded to `Uint8Array`
- Asymmetric `JWK` → imported to `CryptoKey` (requires `alg`)

### `exportKey(key, jwk?)`

Exports a CryptoKey to JWK format. Optional `jwk` param merges additional properties (e.g., `kid`, `use`).

Returns `Promise<JWK>`.

### `getJWKFromSet(jwkSet, kidOrHeader)`

Selects a key from a JWKSet by `kid` string or by matching a protected header object (`kid`, `alg`, `kty`).

## Key Wrapping

### `wrapKey(alg, keyToWrap, wrappingKey, options?)`

Wraps a Content Encryption Key.

- `alg: KeyManagementAlgorithm`
- `keyToWrap: CryptoKey | Uint8Array`
- `wrappingKey: CryptoKey | JWK | string | Uint8Array` — string/Uint8Array for PBES2 passwords
- `options?: WrapKeyOptions` — `{ iv?, p2s?, p2c?, epk?, apu?, apv? }`

Returns `Promise<WrapKeyResult>` — `{ encryptedKey, iv?, tag?, p2s?, p2c?, epk?, apu?, apv? }`

### `unwrapKey(alg, wrappedKey, unwrappingKey, options?)`

Unwraps a CEK.

- `options?: UnwrapKeyOptions`
  - `returnAs?: boolean` — `false` → `Uint8Array`, `true`/`undefined` → `CryptoKey`
  - `unwrappedKeyAlgorithm?`, `keyUsage?`, `extractable?` — for CryptoKey import
  - `iv?`, `tag?`, `p2s?`, `p2c?`, `epk?`, `apu?`, `apv?`, `enc?`

## PEM Conversion

### `importJWKFromPEM(pem, pemType, alg, importOptions?, jwkExtras?)`

- `pemType: "pkcs8" | "spki" | "x509"`
- `alg: JWKPEMAlgorithm` — algorithm for `crypto.subtle.importKey`
- `importOptions?: { extractable?, keyUsage? }`
- `jwkExtras?: Partial<JWK>` — merge extra fields (e.g., `kid`)

Returns `Promise<JWK>`.

### `exportJWKToPEM(jwk, pemFormat, alg?)`

- `pemFormat: "pkcs8" | "spki"`
- `alg?` — required if `jwk.alg` is undefined

Returns `Promise<string>` — PEM-encoded key.

## Password-Based Key Derivation

Unless the user has specific key management needs, prefer to use `deriveJWKFromPassword()` for convenience and interoperability. Use `deriveKeyFromPassword()` when they need the derived key as a CryptoKey.

### `deriveKeyFromPassword(password, alg, options)`

PBKDF2 derivation for PBES2 algorithms.

- `password: string | Uint8Array`
- `alg: JWK_PBES2` — `"PBES2-HS256+A128KW"` | `"PBES2-HS384+A192KW"` | `"PBES2-HS512+A256KW"`
- `options: DeriveKeyOptions` — `{ salt: Uint8Array, iterations: number, toJWK?, extractable?, keyUsage? }`

Returns `CryptoKey` or `JWK_oct` based on `toJWK`.

### `deriveJWKFromPassword(password, alg, options, jwkParams?)`

Convenience wrapper that always returns `JWK_oct`.

## JWK Types

```ts
// Symmetric
interface JWK_oct { kty: "oct"; k: string; alg?: string; kid?: string; ... }
type JWK_Symmetric = JWK_oct;

// EC
interface JWK_EC_Public { kty: "EC"; crv: string; x: string; y: string; ... }
interface JWK_EC_Private extends JWK_EC_Public { d: string; }

// RSA
interface JWK_RSA_Public { kty: "RSA"; e: string; n: string; ... }
interface JWK_RSA_Private extends JWK_RSA_Public { d, dp, dq, p, q, qi: string; }

// OKP (EdDSA, X25519)
interface JWK_OKP_Public { kty: "OKP"; crv: string; x: string; ... }
interface JWK_OKP_Private extends JWK_OKP_Public { d: string; }

// Unions
type JWK_Public = JWK_RSA_Public | JWK_EC_Public | JWK_OKP_Public;
type JWK_Private = JWK_RSA_Private | JWK_EC_Private | JWK_OKP_Private;
type JWK = JWK_oct | JWK_RSA | JWK_EC | JWK_OKP;

interface JWKSet { keys: JWK[]; }
```
