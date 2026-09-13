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
  - `extractable?: boolean` — default `true`; ignored when `toJWK: true` (the JWK output requires exporting the intermediate key)
  - `keyUsage?: KeyUsage[]`
  - `modulusLength?: number` — RSA only, default `2048`. Values below `2048` bits throw
    `ERR_INVALID_OPTION` (RFC 7518 §3.3 / §3.5 set 2048 as the floor for `RS*`, `PS*` and `RSA-OAEP*`)
  - `publicExponent?: Uint8Array` — RSA only, default `0x010001`
  - `namedCurve?` — EC/OKP only. `"P-256" | "P-384" | "P-521" | "X25519" | "Ed25519" | "Ed448"`

PBES2 is not a key-generation algorithm — use `deriveKeyFromPassword` / `deriveJWKFromPassword`.

To return JWK with extra parameters (e.g. a custom `kid`), use `generateJWK()` instead of `toJWK: true`.

> **Extractability.** Generated keys default to `extractable: true` (the JWK-first model needs
> export). For long-lived asymmetric private keys that should never leave the runtime — a
> signing key held in a server process — generate a `CryptoKey` with `extractable: false`
> (omit `toJWK`, which forces extractable). The key still signs/decrypts via Web Crypto, but
> its material can no longer be exported, so a compromised process cannot exfiltrate it.

### `generateJWK(alg, options?)`

Always returns JWK format with a `kid` (auto-generated via `crypto.randomUUID()` when not supplied).

- `alg: GenerateKeyAlgorithm`
- `options?` — combined `GenerateKeyOptions` (minus `toJWK`) and JWK metadata (`kid`, `use`,
  `x5c`, etc.). `alg`, `kty`, `key_ops`, and `ext` are managed by the library and cannot be
  overridden here — the generated key wins over anything passed in.

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

- `string` → throws `ERR_JWK_INVALID`, see below
- `Uint8Array` → returned as-is
- `CryptoKey` → returned as-is (subject to `expect` validation if supplied)
- `JWK_oct` → `k` decoded to `Uint8Array` (default)
- `JWK_oct` + `{ asCryptoKey: true, algorithm, usage, extractable? }` → imported as non-extractable `CryptoKey`
- Asymmetric `JWK` → imported to `CryptoKey` (requires `alg`; `{ extractable?: boolean }` overrides
  the default of non-extractable for private key material, extractable for public)

For `EC` and `OKP` keys the JWK's `crv` decides the Web Crypto algorithm — it is never assumed
from `alg`. `EC` + `ECDH-ES*` accepts `P-256` / `P-384` / `P-521`; `OKP` + `Ed25519` / `EdDSA`
accepts `Ed25519` / `Ed448`; `OKP` + `ECDH-ES*` accepts `X25519` / `X448`. Any other `crv`
throws `ERR_JWK_INVALID` before Web Crypto is reached. The same rule applies to `importPEM`,
which reads the curve OID out of the key body.

`oct` key lengths are validated against the algorithm of the operation (the positional hint or
`options.alg`, falling back to the JWK's own `alg`) at import: HS\* require at least the hash
output size (32/48/64 bytes, RFC 7518 §3.2); A\*KW, A\*GCMKW, A\*GCM, and A\*CBC-HS\* require their
exact key size. `asCryptoKey` with an HMAC `algorithm` enforces the same minimum. Throws
`ERR_JWK_INVALID`; algorithms whose key size cannot be known from `alg` alone (e.g. `"dir"`,
absent `alg`) are not checked — for `"dir"` the length is checked against the token's `enc`
during decryption instead.

#### The JWK's `alg` is authoritative

When the JWK carries an `alg` and the operation asks for a different one, the import throws
`JWTError('JWK "alg" is "<jwk.alg>" but the operation requires "<alg>".', "ERR_JWK_INVALID")`
— neither side silently wins. The single exception is the JWE symmetric role mapping: an `oct`
JWK whose `alg` is a content encryption algorithm (`A*GCM`, `A*CBC-HS*`) is the CEK that
`alg: "dir"` consumes, and `decrypt` additionally requires the token's `enc` to equal that `alg`
(see `jwe.md`).

#### `key_ops` and `ext`

A JWK's `key_ops` is intersected with the usages the operation needs — it narrows them, never
widens them — and a `key_ops` permitting none of them throws
`JWTError('JWK "key_ops" does not permit <usage>.', "ERR_JWK_INVALID")` rather than importing a
key that fails inside Web Crypto. `ext` follows the caller: private key material imports
non-extractable unless `{ extractable: true }` is passed, and a JWK's `ext: false` may lower
extractability but never raises it.

#### Strings are rejected

`importKey` takes no `string`. A string reaches it as one of three different things and
guessing between them is how PEM armour became a valid HMAC secret:

```
String keys are not accepted: pass an oct JWK or a Uint8Array secret,
or import PEM text with importPEM().   // ERR_JWK_INVALID
```

- PEM text → `importPEM(pem, alg)`
- Shared secret → an `oct` JWK (`generateJWK("HS256")`) or a `Uint8Array`
- Password → `deriveJWKFromPassword()`, or pass it straight to `encrypt`/`decrypt`, where
  PBES2 derives a key from it (the only place JOSE accepts a string as key material)

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
(`kid`, `use`, `x5c`, etc.) onto the result.

`jwkParams` may only decorate the key, never redescribe it: passing `kty`, `alg`, `key_ops`,
`ext`, or any key-material member (`k`, `d`, `n`, `e`, `p`, `q`, `dp`, `dq`, `qi`, `x`, `y`,
`crv`) throws `ERR_INVALID_OPTION` naming the offending members. The key's own values come
from Web Crypto's authoritative export.

Returns `Promise<JWK>`.

## Key Wrapping

### `wrapKey(keyToWrap, wrappingKey, { alg, ...options })`

Wraps a Content Encryption Key using the specified key management algorithm.

- `keyToWrap: CryptoKey | Uint8Array`
- `wrappingKey: CryptoKey | JWK | string | Uint8Array` — a `string` is a PBES2 password and is
  rejected with `ERR_JWK_INVALID` under any other `alg`
- `options: WrapKeyOptions`
  - `alg: KeyManagementAlgorithm` — **required**; including `"dir"` (returns empty `encryptedKey`)
  - `iv?` — AES-GCMKW initialization vector; auto-generated when omitted (always omit in
    production — reusing an IV under the same key breaks AES-GCM; intended only for tests
    and known-vector reproduction, never derive it from external input)
  - `p2s?`, `p2c?` — PBES2 salt and iteration count
  - `ecdh?` — ECDH-ES options:
    - `ephemeralKey?` — custom ephemeral key (CryptoKeyPair, JWK_EC_Private, etc.); generated automatically if omitted
    - `partyUInfo?`, `partyVInfo?` — agreement party info
    - `enc?` — content encryption algorithm, **required** for bare `"ECDH-ES"` (direct key agreement)

Returns `Promise<WrapKeyResult<TAlg>>`, narrowed by `alg`:

| `alg` family                     | Result shape                        |
| -------------------------------- | ----------------------------------- |
| `"dir"`, `"A*KW"`, `"RSA-OAEP*"` | `{ encryptedKey }`                  |
| `"PBES2-*"`                      | `{ encryptedKey, p2s, p2c }`        |
| `"A*GCMKW"`                      | `{ encryptedKey, iv, tag }`         |
| `"ECDH-ES"`, `"ECDH-ES+A*KW"`    | `{ encryptedKey, epk, apu?, apv? }` |

For `"ECDH-ES"` (direct), `encryptedKey` is an empty `Uint8Array` per RFC 7516 §4.6.

```ts
// AES Key Wrap
const { encryptedKey } = await wrapKey(cek, aesKey, { alg: "A256KW" });

// ECDH-ES with key wrapping
const { encryptedKey, epk } = await wrapKey(cek, recipientPublicKey, { alg: "ECDH-ES+A256KW" });

// ECDH-ES direct (encryptedKey is empty — derived secret IS the CEK)
const { epk, apu, apv } = await wrapKey(rawCek, recipientPublicKey, {
  alg: "ECDH-ES",
  ecdh: { enc: "A256GCM" },
});
```

### `unwrapKey(wrappedKey, unwrappingKey, { alg, ...options })`

Unwraps a CEK.

- `options: UnwrapKeyOptions`
  - `alg: KeyManagementAlgorithm` — **required**
  - `format?: "cryptokey" | "raw"` — `"cryptokey"` (default) returns `CryptoKey`; `"raw"` returns `Uint8Array`
  - `unwrappedKeyAlgorithm?`, `keyUsage?`, `extractable?` — for CryptoKey import
  - `iv?`, `tag?` — AES-GCMKW
  - `p2s?`, `p2c?` — PBES2
  - `minIterations?`, `maxIterations?` — PBES2 `p2c` bounds. Default floor `1000` (RFC 7518 §4.8.1.2), default ceiling `1_000_000`
  - `epk?`, `apu?`, `apv?`, `enc?` — ECDH-ES

```ts
// Returns CryptoKey by default
const cek = await unwrapKey(encryptedKey, aesKey, { alg: "A256KW" });

// Returns raw bytes
const raw = await unwrapKey(encryptedKey, aesKey, { alg: "A256KW", format: "raw" });
```

## ECDH-ES Shared Secret

### `deriveSharedSecret(publicKey, privateKey, { enc, ...options })`

Low-level ECDH-ES key derivation (Concat KDF, NIST SP 800-56A). Useful for multi-recipient JWE, custom hybrid protocols, and future JWE JSON Serialization.

- `publicKey: CryptoKey | JWK_EC_Public` — recipient's static public key (sender side), or sender's ephemeral public key (recipient side)
- `privateKey: CryptoKey | JWK_EC_Private` — sender's ephemeral private key (sender side), or recipient's static private key (recipient side)
- `options`
  - `enc: JWK_ECDH_ES | ContentEncryptionAlgorithm` — **required**; used as the `AlgorithmID` in the KDF info structure
  - `keyLength?: number` — derived key length in bits; required when `enc` is `"ECDH-ES"`, inferred
    otherwise. Must be a positive multiple of 8 no greater than 8192, else `ERR_INVALID_OPTION`
  - `partyUInfo?`, `partyVInfo?` — agreement party info

Returns `Promise<Uint8Array>` — the derived key material.

```ts
// Derive the same secret on both sides
const senderSecret = await deriveSharedSecret(recipientPublic, senderEphemeralPrivate, {
  enc: "ECDH-ES+A256KW",
});
const recipientSecret = await deriveSharedSecret(senderEphemeralPublic, recipientPrivate, {
  enc: "ECDH-ES+A256KW",
});
// senderSecret === recipientSecret ✓

// Multi-recipient: derive a KEK per recipient to wrap a shared CEK
const cek = crypto.getRandomValues(new Uint8Array(32));
for (const recipient of recipients) {
  const { encryptedKey, epk } = await wrapKey(cek, recipient.publicKey, { alg: "ECDH-ES+A256KW" });
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
  - `jwkParams?` — additional JWK properties merged into the result (e.g. `kid`, `use`); the
    reserved members listed under `exportKey` throw `ERR_INVALID_OPTION`

The returned JWK always contains the key material in plain JavaScript. To obtain a
non-extractable `CryptoKey`, pass the result to `importKey(jwk, { extractable: false })`.

**Exactly one armoured block.** The input must contain a single `-----BEGIN <LABEL>-----` /
`-----END <LABEL>-----` pair. Text before it is ignored (RFC 7468 §2); nothing but whitespace may
follow it. A bundle of two blocks, or trailing data, is `ERR_JWK_INVALID` instead of silently
importing the first key.

Throws `ERR_JWK_INVALID` when the PEM has no recognisable label and `pemType` is not supplied,
when the label does not match the requested/inferred type, or when the body is not a key the
requested `alg` can import (a truncated certificate included).

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

### `deriveKeyFromPassword(password, { alg, ...options })`

PBKDF2 derivation for PBES2 algorithms.

- `password: string | Uint8Array`
- `options: DeriveKeyOptions` — `{ alg: JWK_PBES2, salt: Uint8Array, iterations: number, toJWK?: boolean, extractable?, keyUsage? }`
  - `alg` is **required**: `"PBES2-HS256+A128KW"` | `"PBES2-HS384+A192KW"` | `"PBES2-HS512+A256KW"`
  - `extractable` is ignored when `toJWK: true` — the JWK output requires exporting the derived key

Returns `CryptoKey` or `JWK_oct` based on `toJWK`.

### `deriveJWKFromPassword(password, { alg, ...options })`

Convenience wrapper that always returns `JWK_oct`. `options` combines the PBES2 algorithm and
derivation knobs (`alg`, `salt`, `iterations`, `keyUsage`) with JWK metadata fields (`kid`,
`use`, …). The resulting JWK's `alg`, `kty`, `key_ops`, and `ext` are managed by the library.

```ts
const jwk = await deriveJWKFromPassword("my-password", {
  alg: "PBES2-HS256+A128KW",
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
) =>
  | CryptoKey
  | JWK
  | JWKSet
  | string
  | Uint8Array<ArrayBuffer>
  | Promise<CryptoKey | JWK | JWKSet | string | Uint8Array<ArrayBuffer>>;
```

When a `JWKLookupFunction` returns a `JWKSet`, the same multi-key retry logic applies as when passing a `JWKSet` directly — see `jws.md` / `jwe.md` for the candidate rules.

## JWK Set Utilities

### `getJWKsFromSet(jwkSet, filter?)`

Returns all JWKs from a set, optionally narrowed by a predicate `(jwk: JWK) => boolean`. Entries that are not JWKs are dropped first — `keys` arrives over the wire and may hold `null`, strings or junk objects. No filter returns every JWK. Useful for multi-key verification retry, key rotation, and multi-recipient JWE construction.

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

## Errors

Every JOSE operation in this module throws `JWTError` — a single `instanceof` is enough. When the root cause is one of the bundled [`unsecure`](https://github.com/sandros94/unsecure) primitives (base64url codec, JSON parse), it is preserved as `cause`:

```ts
import { importKey, isJWTError, isUnsecureError } from "unjwt/jwk";

const error = await importKey(jwk).catch((e) => e);
if (isJWTError(error, "ERR_JWK_INVALID") && isUnsecureError(error.cause, "MALFORMED")) {
  // a segment of the wire format is not canonical base64url
}
```

`unsecure` is inlined into unjwt's dist, so `instanceof` against a consumer-installed `unsecure` never matches. Use the `UnsecureError` / `isUnsecureError` that unjwt re-exports. The `unjwt/utils` primitives themselves still throw `UnsecureError` directly — only the JOSE operations wrap.

## JWK Types

Every concrete JWK interface takes an optional `Alg` type parameter that constrains the JWK's
`alg` field to the algorithm family legal for that key type — `(string & {})` preserves
autocomplete without blocking custom / forward-compat algorithm names. The default `string`
keeps existing `JWK_oct`, `JWK_RSA_Public`, etc. usages unchanged. Sign/verify/encrypt/decrypt
accept the narrowed union aliases (`JWSSignJWK`, `JWEEncryptJWK`, …) — see the JWS/JWE
references for those.

```ts
interface JWKParameters<Alg extends string = string> {
  "kty": string;
  "alg"?: Alg;
  "key_ops"?: KeyUsage[];
  "ext"?: boolean;
  "use"?: string;
  "x5c"?: string[];
  "x5t"?: string;
  "x5t#S256"?: string;
  "x5u"?: string;
  "kid"?: string;
  "enc"?: ContentEncryptionAlgorithm; // non-standard hint for `alg: "dir"`
}

// Symmetric — admits every symmetric / password alg + "dir"
interface JWK_oct<
  Alg extends
    | JWK_HMAC
    | JWK_AES_KW
    | JWK_AES_GCM
    | JWK_AES_GCM_KW
    | JWK_AES_CBC_HMAC
    | JWK_PBES2
    | "dir"
    | (string & {}) = string,
> extends JWKParameters<Alg> {
  kty: "oct";
  k: string;
}

type JWK_Symmetric<Alg extends string = string> = JWK_oct<Alg>;

// EC — ECDSA (sign) or ECDH-ES (encrypt)
interface JWK_EC_Public<
  Alg extends JWK_ECDSA | JWK_ECDH_ES | (string & {}) = string,
> extends JWKParameters<Alg> {
  kty: "EC";
  crv: string;
  x: string;
  y: string;
}

interface JWK_EC_Private<
  Alg extends JWK_ECDSA | JWK_ECDH_ES | (string & {}) = string,
> extends JWK_EC_Public<Alg> {
  d: string;
}

type JWK_EC<Alg extends JWK_ECDSA | JWK_ECDH_ES | (string & {}) = string> =
  JWK_EC_Public<Alg> | JWK_EC_Private<Alg>;

// RSA — RS*, PS*, RSA-OAEP*
interface JWK_RSA_Public<
  Alg extends JWK_RSA_SIGN | JWK_RSA_PSS | JWK_RSA_ENC | (string & {}) = string,
> extends JWKParameters<Alg> {
  kty: "RSA";
  e: string;
  n: string;
  oth?: RsaOtherPrimesInfo[];
}

interface JWK_RSA_Private<
  Alg extends JWK_RSA_SIGN | JWK_RSA_PSS | JWK_RSA_ENC | (string & {}) = string,
> extends JWK_RSA_Public<Alg> {
  d: string;
  dp: string;
  dq: string;
  p: string;
  q: string;
  qi: string;
}

type JWK_RSA<Alg extends JWK_RSA_SIGN | JWK_RSA_PSS | JWK_RSA_ENC | (string & {}) = string> =
  JWK_RSA_Public<Alg> | JWK_RSA_Private<Alg>;

// OKP — Ed signing or ECDH-ES (X25519 / X448)
interface JWK_OKP_Public<
  Alg extends JWK_OKP_SIGN | JWK_ECDH_ES | (string & {}) = string,
> extends JWKParameters<Alg> {
  kty: "OKP";
  crv: string;
  x: string;
}

interface JWK_OKP_Private<
  Alg extends JWK_OKP_SIGN | JWK_ECDH_ES | (string & {}) = string,
> extends JWK_OKP_Public<Alg> {
  d: string;
}

type JWK_OKP<Alg extends JWK_OKP_SIGN | JWK_ECDH_ES | (string & {}) = string> =
  JWK_OKP_Public<Alg> | JWK_OKP_Private<Alg>;

// Unions
type JWK_Public<Alg extends string = string> =
  JWK_RSA_Public<Alg> | JWK_EC_Public<Alg> | JWK_OKP_Public<Alg>;
type JWK_Private<Alg extends string = string> =
  JWK_RSA_Private<Alg> | JWK_EC_Private<Alg> | JWK_OKP_Private<Alg>;
type JWK_Asymmetric<Alg extends string = string> = JWK_RSA<Alg> | JWK_EC<Alg> | JWK_OKP<Alg>;
type JWK<Alg extends string = string> = JWK_oct<Alg> | JWK_RSA<Alg> | JWK_EC<Alg> | JWK_OKP<Alg>;

// Narrowed by `Alg` when that uniquely identifies the family:
//   JWK_Pair<"RS256">           → RSA pair only
//   JWK_Pair<"ES256">           → EC pair only
//   JWK_Pair<"ECDH-ES+A256KW">  → EC pair | OKP pair (curve decides at runtime)
//   JWK_Pair<"Ed25519">         → OKP pair only
// `Alg = string` (default) and unknown/custom algs fall through to the full three-branch union,
// preserving the permissive behavior of the original `JWK_Pair`.
type JWK_Pair<Alg extends string = string> = Alg extends JWK_RSA_SIGN | JWK_RSA_PSS | JWK_RSA_ENC
  ? { publicKey: JWK_RSA_Public<Alg>; privateKey: JWK_RSA_Private<Alg> }
  : Alg extends JWK_ECDSA
    ? { publicKey: JWK_EC_Public<Alg>; privateKey: JWK_EC_Private<Alg> }
    : Alg extends JWK_ECDH_ES
      ? | { publicKey: JWK_EC_Public<Alg>; privateKey: JWK_EC_Private<Alg> }
        | { publicKey: JWK_OKP_Public<Alg>; privateKey: JWK_OKP_Private<Alg> }
      : Alg extends JWK_OKP_SIGN
        ? { publicKey: JWK_OKP_Public<Alg>; privateKey: JWK_OKP_Private<Alg> }
        : | { publicKey: JWK_RSA_Public<Alg>; privateKey: JWK_RSA_Private<Alg> }
          | { publicKey: JWK_EC_Public<Alg>; privateKey: JWK_EC_Private<Alg> }
          | { publicKey: JWK_OKP_Public<Alg>; privateKey: JWK_OKP_Private<Alg> };

// `T` preserves the precise key tuple when constructed in TS
// — e.g. JWKSet<[JWK_oct<"HS256">, JWK_EC_Public<"ES256">]>
// — while the default `JWK[]` keeps permissive semantics for JWKS wires.
interface JWKSet<T extends readonly JWK[] = JWK[]> {
  keys: T;
  [parameter: string]: unknown;
}

interface JWKCacheAdapter {
  get(jwk: JWK, alg: string): CryptoKey | undefined;
  set(jwk: JWK, alg: string, key: CryptoKey): void;
}

type JWKLookupFunctionHeader = {
  kid?: string;
  alg?: string;
  enc?: string;
  typ?: string;
  crit?: string[];
  [propName: string]: unknown;
};

// Optional TReturn lets callers who always hand back a specific shape
// preserve narrowing; the default stays fully permissive.
type JWKLookupFunction<TReturn = CryptoKey | JWK | JWKSet | string | Uint8Array<ArrayBuffer>> = (
  header: JWKLookupFunctionHeader,
  token: string,
) => TReturn | Promise<TReturn>;
```

### Algorithm mapped types

Used by `wrapKey` / `unwrapKey` to narrow their `wrappingKey` / `unwrappingKey` parameter
against the selected `alg`:

```ts
type WrappingKeyFor<Alg extends KeyManagementAlgorithm> = Alg extends JWK_RSA_ENC
  ? CryptoKey | JWK_RSA_Public<Alg>
  : Alg extends JWK_ECDH_ES
    ? CryptoKey | JWK_EC_Public<Alg> | JWK_OKP_Public<Alg>
    : Alg extends JWK_PBES2
      ? string | Uint8Array<ArrayBuffer> | JWK_oct<Alg>
      : Alg extends JWK_AES_KW
        ? CryptoKey | JWK_oct<Alg>
        : Alg extends JWK_AES_GCM_KW
          ? CryptoKey | JWK_oct<Alg>
          : Alg extends "dir"
            ? CryptoKey | JWK_oct | Uint8Array<ArrayBuffer>
            : never;

// `UnwrappingKeyFor<Alg>` has the same shape with the `_Private` counterparts
// on asymmetric branches.
```
