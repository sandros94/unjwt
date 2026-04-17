# JWK Reference (unjwt/jwk)

JSON Web Key ([RFC 7517](https://www.rfc-editor.org/rfc/rfc7517.txt)) — key generation, import/export, wrapping, PEM conversion, and cache control.

Import: `import { generateKey, generateJWK, importKey, exportKey, wrapKey, unwrapKey, deriveSharedSecret, importPEM, exportPEM, deriveKeyFromPassword, deriveJWKFromPassword, getJWKsFromSet, getJWKFromSet, configureJWKCache, clearJWKCache, WeakMapJWKCache } from "unjwt/jwk"`

Key lookup types (also from `unjwt/jwk`): `JWKLookupFunction`, `JWKLookupFunctionHeader` — or `from "unjwt"`

## Key Generation

Unless specific control over the output format is required, prefer `generateJWK()` — it always returns a ready-to-use JWK with a generated `kid`.

### `generateKey(alg, options?)`

Generates a cryptographic key. The return type is narrowed by `alg` and `options.toJWK`:

| Algorithm family                                  | `toJWK: false` (default)                               | `toJWK: true`                                                |
| ------------------------------------------------- | ------------------------------------------------------ | ------------------------------------------------------------ |
| `HS*`, `A*KW`, `A*GCM`, `A*GCMKW`                 | `CryptoKey`                                            | `JWK_oct`                                                    |
| `A128CBC-HS256`, `A192CBC-HS384`, `A256CBC-HS512` | `Uint8Array<ArrayBuffer>` (composite AES + HMAC bytes) | `JWK_oct` (composite bytes serialised as one `oct` key)      |
| `RS*`, `PS*`, `RSA-OAEP*`                         | `CryptoKeyPair`                                        | `{ privateKey: JWK_RSA_Private; publicKey: JWK_RSA_Public }` |
| `ES*`                                             | `CryptoKeyPair`                                        | `{ privateKey: JWK_EC_Private; publicKey: JWK_EC_Public }`   |
| `Ed25519`, `EdDSA`                                | `CryptoKeyPair`                                        | `{ privateKey: JWK_OKP_Private; publicKey: JWK_OKP_Public }` |
| `ECDH-ES*`                                        | `CryptoKeyPair`                                        | `JWK_EC` **or** `JWK_OKP` pair, depending on `namedCurve`    |

- `alg: GenerateKeyAlgorithm` — any JWS or JWE algorithm except `"dir"` and PBES2
- `options?: GenerateKeyOptions`
  - `toJWK?: boolean` — when `true`, returns JWK format instead of `CryptoKey` / `CryptoKeyPair` / `Uint8Array`
  - `extractable?: boolean` — default `true`
  - `keyUsage?: KeyUsage[]`
  - `modulusLength?: number` — RSA only, default `2048`
  - `publicExponent?: Uint8Array` — RSA only, default `0x010001`
  - `namedCurve?` — EC/OKP only. `"P-256" | "P-384" | "P-521" | "X25519" | "Ed25519" | "Ed448"`

PBES2 is not a key-generation algorithm — use `deriveKeyFromPassword` / `deriveJWKFromPassword`.

To return JWK with extra parameters (e.g. a custom `kid`), use `generateJWK()` instead of `toJWK: true`.

### `generateJWK(alg, options?)`

Always returns JWK format with a `kid` (auto-generated via `crypto.randomUUID()` when not supplied).

- `alg: GenerateKeyAlgorithm`
- `options?` — combined `GenerateKeyOptions` (minus `toJWK`) and JWK metadata (`kid`, `use`,
  `x5c`, etc.). `alg`, `kty`, `key_ops`, and `ext` are managed by the library and cannot be
  overridden here.

```ts
import { generateKey, generateJWK } from "unjwt/jwk";

const hmacCryptoKey = await generateKey("HS256");
const rsaKeyPair = await generateKey("RS256", { modulusLength: 4096 });

const ecKeys = await generateJWK("ES256", { kid: "ec-1" });
// → { privateKey: JWK_EC_Private, publicKey: JWK_EC_Public }

const rsaJwk = await generateJWK("RS256", { modulusLength: 2048, kid: "rsa-1", use: "sig" });
```

## Key Import/Export

### `importKey(key, algOrOptions?)`

Normalizes various key formats into `CryptoKey` or `Uint8Array`.

- `string` → encoded to `Uint8Array`
- `Uint8Array` → returned as-is
- `CryptoKey` → returned as-is (subject to `expect` validation if supplied)
- `JWK_oct` → `k` decoded to `Uint8Array` (default)
- `JWK_oct` + `{ asCryptoKey: true, algorithm, usage, extractable? }` → imported as non-extractable `CryptoKey`
- Asymmetric `JWK` → imported to `CryptoKey` (requires `alg`)

#### `expect` option

Pass `{ expect: "public" | "private" }` to validate the caller's intent against the key's
shape **before** the import. A private JWK or CryptoKey passed with `expect: "public"` throws
`ERR_JWK_INVALID` instead of silently importing the private material — and vice versa.
`expect` is a no-op for symmetric (`oct`) JWKs and `"secret"`-type CryptoKeys.

`verify` / `decrypt` pin `expect: "public"` and `expect: "private"` respectively, so the
common paths are correct by default. Callers using `importKey` directly opt in explicitly.

```ts
// Default: JWK_oct returns raw bytes
const bytes = await importKey(symJwk); // Uint8Array

// Opt-in: get a non-extractable CryptoKey from JWK_oct
const key = await importKey(symJwk, {
  asCryptoKey: true,
  algorithm: { name: "AES-GCM", length: 256 },
  usage: ["encrypt", "decrypt"],
}); // CryptoKey, extractable: false by default

// Assert intent on an asymmetric JWK before import
const recipientPub = await importKey(recipientJwk, { alg: "RSA-OAEP-256", expect: "public" });
```

### `exportKey(key, jwkParams?)`

Exports a `CryptoKey` to JWK format. `jwkParams` optionally merges metadata fields
(`kid`, `use`, `x5c`, etc.) onto the result. `alg`, `kty`, `key_ops`, and `ext` are
preserved from Web Crypto's authoritative export and cannot be overridden here.

Returns `Promise<JWK>`.

## Key Wrapping

### `wrapKey(alg, keyToWrap, wrappingKey, options?)`

Wraps a Content Encryption Key using the specified key management algorithm.

- `alg: KeyManagementAlgorithm` — including `"dir"` (returns empty `encryptedKey`)
- `keyToWrap: CryptoKey | Uint8Array`
- `wrappingKey: CryptoKey | JWK | string | Uint8Array` — string/Uint8Array only for PBES2
- `options?: WrapKeyOptions`
  - `iv?` — AES-GCMKW initialization vector
  - `p2s?`, `p2c?` — PBES2 salt and iteration count
  - `ecdh?` — ECDH-ES options:
    - `ephemeralKey?` — custom ephemeral key (CryptoKeyPair, JWK_EC_Private, etc.); generated automatically if omitted
    - `partyUInfo?`, `partyVInfo?` — agreement party info
    - `enc?` — content encryption algorithm, **required** for bare `"ECDH-ES"` (direct key agreement)

Returns `Promise<WrapKeyResult>` — `{ encryptedKey, iv?, tag?, p2s?, p2c?, epk?, apu?, apv? }`

For `"ECDH-ES"` (direct), `encryptedKey` is an empty `Uint8Array` per RFC 7516 §4.6.

```ts
// AES Key Wrap
const { encryptedKey } = await wrapKey("A256KW", cek, aesKey);

// ECDH-ES with key wrapping
const { encryptedKey, epk } = await wrapKey("ECDH-ES+A256KW", cek, recipientPublicKey);

// ECDH-ES direct (encryptedKey is empty — derived secret IS the CEK)
const { epk, apu, apv } = await wrapKey("ECDH-ES", rawCek, recipientPublicKey, {
  ecdh: { enc: "A256GCM" },
});
```

### `unwrapKey(alg, wrappedKey, unwrappingKey, options?)`

Unwraps a CEK.

- `options?: UnwrapKeyOptions`
  - `format?: "cryptokey" | "raw"` — `"cryptokey"` (default) returns `CryptoKey`; `"raw"` returns `Uint8Array`
  - `unwrappedKeyAlgorithm?`, `keyUsage?`, `extractable?` — for CryptoKey import
  - `iv?`, `tag?` — AES-GCMKW
  - `p2s?`, `p2c?` — PBES2
  - `minIterations?`, `maxIterations?` — PBES2 `p2c` bounds. Default floor `1000` (RFC 7518 §4.8.1.2), default ceiling `1_000_000`
  - `epk?`, `apu?`, `apv?`, `enc?` — ECDH-ES

```ts
// Returns CryptoKey by default
const cek = await unwrapKey("A256KW", encryptedKey, aesKey);

// Returns raw bytes
const raw = await unwrapKey("A256KW", encryptedKey, aesKey, { format: "raw" });
```

## ECDH-ES Shared Secret

### `deriveSharedSecret(publicKey, privateKey, alg, options?)`

Low-level ECDH-ES key derivation (Concat KDF, NIST SP 800-56A). Useful for multi-recipient JWE, custom hybrid protocols, and future JWE JSON Serialization.

- `publicKey: CryptoKey | JWK_EC_Public` — recipient's static public key (sender side), or sender's ephemeral public key (recipient side)
- `privateKey: CryptoKey | JWK_EC_Private` — sender's ephemeral private key (sender side), or recipient's static private key (recipient side)
- `alg: JWK_ECDH_ES | ContentEncryptionAlgorithm` — used as the `AlgorithmID` in the KDF info structure
- `options?`
  - `keyLength?: number` — derived key length in bits; required when `alg` is `"ECDH-ES"`, inferred otherwise
  - `partyUInfo?`, `partyVInfo?` — agreement party info

Returns `Promise<Uint8Array>` — the derived key material.

```ts
// Derive the same secret on both sides
const senderSecret = await deriveSharedSecret(
  recipientPublic,
  senderEphemeralPrivate,
  "ECDH-ES+A256KW",
);
const recipientSecret = await deriveSharedSecret(
  senderEphemeralPublic,
  recipientPrivate,
  "ECDH-ES+A256KW",
);
// senderSecret === recipientSecret ✓

// Multi-recipient: derive a KEK per recipient to wrap a shared CEK
const cek = crypto.getRandomValues(new Uint8Array(32));
for (const recipient of recipients) {
  const { encryptedKey, epk } = await wrapKey("ECDH-ES+A256KW", cek, recipient.publicKey);
  // store encryptedKey + epk per recipient
}
```

## PEM Conversion

### `importPEM(pem, alg, options?)`

Imports a PEM-encoded key and returns it as a JWK. The PEM type is inferred from the
`-----BEGIN <X>-----` label (`PRIVATE KEY` → `pkcs8`, `PUBLIC KEY` → `spki`, `CERTIFICATE` → `x509`).

- `alg: JWKPEMAlgorithm`
- `options?`
  - `pemType?: "pkcs8" | "spki" | "x509"` — inferred from the PEM label when omitted
  - `extractable?: boolean` — default `false` for private keys, `true` for public keys
  - `jwkParams?` — additional JWK properties merged into the result (e.g. `kid`, `use`)

Throws `ERR_JWK_INVALID` when the PEM has no recognisable label and `pemType` is not supplied,
or when the label does not match the requested/inferred type.

Returns `Promise<JWK>`.

### `exportPEM(jwk, options?)`

Exports a JWK to a PEM-encoded string. The PEM format is inferred from the JWK shape
(presence of `d` → `pkcs8`, otherwise `spki`). X.509 certificate export is intentionally not
supported: a certificate requires metadata and a CA signature that a JWK cannot provide.

- `options?`
  - `pemFormat?: "pkcs8" | "spki"` — inferred from the JWK shape when omitted
  - `alg?: JWKPEMAlgorithm` — algorithm hint used when `jwk.alg` is absent

Returns `Promise<string>`.

```ts
import { importPEM, exportPEM } from "unjwt/jwk";

const jwk = await importPEM(pemString, "RS256", { jwkParams: { kid: "rsa-1" } });
const pem = await exportPEM(jwk);
```

`importFromPEM(pem, pemType, alg, options?)` and `exportToPEM(jwk, pemFormat, alg?)` are retained
as `@deprecated` aliases with their original positional signatures — existing callers compile
unchanged and will see an IDE deprecation hint until they migrate.

## Password-Based Key Derivation

Prefer `deriveJWKFromPassword()` for most cases. Use `deriveKeyFromPassword()` when a raw `CryptoKey` output is needed.

### `deriveKeyFromPassword(password, alg, options)`

PBKDF2 derivation for PBES2 algorithms.

- `password: string | Uint8Array`
- `alg: JWK_PBES2` — `"PBES2-HS256+A128KW"` | `"PBES2-HS384+A192KW"` | `"PBES2-HS512+A256KW"`
- `options: DeriveKeyOptions` — `{ salt: Uint8Array, iterations: number, toJWK?: boolean, extractable?, keyUsage? }`

Returns `CryptoKey` or `JWK_oct` based on `toJWK`.

### `deriveJWKFromPassword(password, alg, options)`

Convenience wrapper that always returns `JWK_oct`. `options` combines the PBES2 derivation
knobs (`salt`, `iterations`, `extractable`, `keyUsage`) with JWK metadata fields (`kid`, `use`, …).
`alg`, `kty`, `key_ops`, and `ext` are managed by the library.

```ts
const jwk = await deriveJWKFromPassword("my-password", "PBES2-HS256+A128KW", {
  salt: crypto.getRandomValues(new Uint8Array(16)),
  iterations: 600_000,
  kid: "derived-key",
});
```

## Key Lookup Function

`JWKLookupFunction` and `JWKLookupFunctionHeader` are defined in `unjwt/jwk` and shared by both `verify` (JWS) and `decrypt` (JWE). Using a single unified type avoids the former `JWSKeyLookupFunction` / `JWEKeyLookupFunction` split.

```ts
type JWKLookupFunctionHeader = {
  kid?: string;
  alg?: string;
  enc?: string; // only present on JWE tokens
  typ?: string;
  crit?: string[];
  [propName: string]: unknown; // epk, p2s, p2c, apu, apv, ...
};

type JWKLookupFunction = (
  header: JWKLookupFunctionHeader,
  token: string,
) => MaybePromise<CryptoKey | JWK | JWKSet | string | Uint8Array>;
```

When a `JWKLookupFunction` returns a `JWKSet`, the same multi-key retry logic applies as when passing a `JWKSet` directly — see `getJWKsFromSet` for the selection behaviour.

## JWK Set Utilities

### `getJWKsFromSet(jwkSet, filter?)`

Returns all JWKs from a set, optionally narrowed by a predicate `(jwk: JWK) => boolean`. No filter returns all keys. Useful for multi-key verification retry, key rotation, and multi-recipient JWE construction.

```ts
const allKeys = getJWKsFromSet(jwkSet);
const hmacKeys = getJWKsFromSet(jwkSet, (k) => k.kty === "oct");
const recentKeys = getJWKsFromSet(jwkSet, (k) => k.kid?.endsWith("-2025") ?? false);
```

## JWK Import Cache

By default, `importKey()` caches imported `CryptoKey` results in a module-level `WeakMap` keyed by the JWK object reference. A cache hit requires passing the **exact same object variable** — a spread copy (`{ ...jwk }`) will miss.

### `configureJWKCache(cache)`

Replace or disable the active cache.

- Pass a `JWKCacheAdapter` to use a custom implementation (LRU, Redis-backed, etc.)
- Pass `false` to disable caching entirely

```ts
import { configureJWKCache } from "unjwt/jwk";

// Custom kid-keyed cache
const map = new Map<string, CryptoKey>();
configureJWKCache({
  get: (jwk, alg) => map.get(`${jwk.kid}:${alg}`),
  set: (jwk, alg, key) => map.set(`${jwk.kid}:${alg}`, key),
});

// Disable caching
configureJWKCache(false);
```

### `clearJWKCache()`

Resets the cache to a fresh `WeakMapJWKCache`. Useful in test environments.

### `WeakMapJWKCache`

The default cache implementation. Uses `WeakMap<JWK, Record<string, CryptoKey>>` — the inner plain object is faster than `Map` for the typical 1–2 algorithm entries per key (V8 hidden-class optimization).

```ts
interface JWKCacheAdapter {
  get(jwk: JWK, alg: string): CryptoKey | undefined;
  set(jwk: JWK, alg: string, key: CryptoKey): void;
}
```

## JWK Types

```ts
interface JWKParameters {
  kty: string;
  alg?: string;
  kid?: string;
  use?: string;
  key_ops?: KeyUsage[];
  ext?: boolean;
  enc?: ContentEncryptionAlgorithm; // non-standard hint for "dir" algorithm
  // ...x5c, x5t, x5u, x5t#S256
}

// Symmetric
interface JWK_oct extends JWKParameters {
  kty: "oct";
  k: string;
}
type JWK_Symmetric = JWK_oct;

// EC
interface JWK_EC_Public extends JWKParameters {
  kty: "EC";
  crv: string;
  x: string;
  y: string;
}
interface JWK_EC_Private extends JWK_EC_Public {
  d: string;
}

// RSA
interface JWK_RSA_Public extends JWKParameters {
  kty: "RSA";
  e: string;
  n: string;
}
interface JWK_RSA_Private extends JWK_RSA_Public {
  d;
  dp;
  dq;
  p;
  q;
  qi: string;
}

// OKP (EdDSA, X25519)
interface JWK_OKP_Public extends JWKParameters {
  kty: "OKP";
  crv: string;
  x: string;
}
interface JWK_OKP_Private extends JWK_OKP_Public {
  d: string;
}

// Unions
type JWK_Public = JWK_RSA_Public | JWK_EC_Public | JWK_OKP_Public;
type JWK_Private = JWK_RSA_Private | JWK_EC_Private | JWK_OKP_Private;
type JWK = JWK_oct | JWK_RSA | JWK_EC | JWK_OKP;

interface JWKSet {
  keys: JWK[];
  [key: string]: unknown;
}
```
