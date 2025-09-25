# unjwt

<!-- automd:badges bundlephobia style="flat" color="FFDC3B" -->

[![npm version](https://img.shields.io/npm/v/unjwt?color=FFDC3B)](https://npmjs.com/package/unjwt)
[![npm downloads](https://img.shields.io/npm/dm/unjwt?color=FFDC3B)](https://npm.chart.dev/unjwt)
[![bundle size](https://img.shields.io/bundlephobia/minzip/unjwt?color=FFDC3B)](https://bundlephobia.com/package/unjwt)

<!-- /automd -->

A collection of low-level JWT ([RFC 7519](https://datatracker.ietf.org/doc/html/rfc7519)) utilities using the Web Crypto API. Supports:

- **JWS (JSON Web Signature, [RFC 7515](https://datatracker.ietf.org/doc/html/rfc7515))**: sign and verify tokens using HMAC, RSA (RSASSA-PKCS1-v1_5 & RSA-PSS), and ECDSA algorithms.
- **JWE (JSON Web Encryption, [RFC 7516](https://datatracker.ietf.org/doc/html/rfc7516))**: encrypt and decrypt data using various key management algorithms (AES Key Wrap, AES-GCM Key Wrap, RSA-OAEP, PBES2, ECDH-ES) and content encryption algorithms (AES-GCM, AES-CBC HMAC-SHA2).
- **JWK (JSON Web Key, [RFC 7517](https://datatracker.ietf.org/doc/html/rfc7517))**: generate, import, export, wrap, and unwrap keys in JWK format or as `CryptoKey` objects.

> [!WARNING]
> Please do note that some algorithms are not fully working out-of-the-box yet, such as:
>
> - ECDH-ES algorithms with AES Key Wrap (e.g., ECDH-ES+A128KW)
> - RSA algorithms in combination with some bigger CBC encodings (for example RSA-OAEP-256 with A256CBC-HS512)
>
> For these algorithms, you should be able to provide your own keys. Although I do plan to study and simplify this.

## Usage

Install the package:

```sh
# ✨ Auto-detect (supports npm, yarn, pnpm, deno and bun)
npx nypm install unjwt
```

Import:

**ESM** (Node.js, Bun, Deno)

```js
import { jws, jwe, jwk } from "unjwt";
// JWS functions
import { sign, verify } from "unjwt/jws";
// JWE functions
import { encrypt, decrypt } from "unjwt/jwe";
// JWK functions
import {
  generateKey,
  importKey,
  exportKey,
  wrapKey,
  unwrapKey,
  getJWKFromSet,
  importJWKFromPEM,
  exportJWKToPEM,
  deriveKeyFromPassword,
} from "unjwt/jwk";
// Utility functions
import {
  isJWK,
  isJWKSet,
  isCryptoKey,
  isCryptoKeyPair,
  base64UrlEncode,
  base64UrlDecode,
  randomBytes,
} from "unjwt/utils";
```

**CDN** (Deno, Bun and Browsers)

```js
import { jws, jwe, jwk } from "https://esm.sh/unjwt";
// JWS functions
import { sign, verify } from "https://esm.sh/unjwt/jws";
// JWE functions
import { encrypt, decrypt } from "https://esm.sh/unjwt/jwe";
// JWK functions
import {
  generateKey,
  importKey,
  exportKey,
  wrapKey,
  unwrapKey,
  getJWKFromSet,
  importJWKFromPEM,
  exportJWKToPEM,
  deriveKeyFromPassword,
} from "https://esm.sh/unjwt/jwk";
// Utility functions
import {
  isJWK,
  isJWKSet,
  isCryptoKey,
  isCryptoKeyPair,
  base64UrlEncode,
  base64UrlDecode,
  randomBytes,
} from "https://esm.sh/unjwt/utils";
```

---

### JWS (JSON Web Signature, [RFC 7515](https://datatracker.ietf.org/doc/html/rfc7515))

Functions to sign and verify data according to the JWS specification.

#### `sign(payload, key, options)`

Creates a JWS token.

- `payload`: The data to sign (`string`, `Uint8Array`, or a JSON-serializable `object`).
- `key`: The signing key (`CryptoKey`, `JWK`, or `Uint8Array` for symmetric keys).
- `options`:
  - `alg`: (Required) The JWS algorithm (e.g., `"HS256"`, `"RS256"`, `"ES256"`, `"PS256"`).
  - `protectedHeader`: An object for additional JWS Protected Header parameters (e.g., `kid`, `typ`, `cty`, `crit`, `b64`). If `payload` is an object and `typ` is not set, it defaults to `"JWT"`. The `b64` parameter ([RFC7797 section-3](https://datatracker.ietf.org/doc/html/rfc7797#section-3)) controls payload encoding (defaults to `true`, meaning Base64URL encoded).
  - `expiresIn`: Sets an expiration time in seconds (e.g., `3600` for 1 hour). If `iat` is missing it will be set to the current time. If `exp` is missing it will be set to `iat + expiresIn`. This is only applied if `payload` is a JWT.
  - `currentDate`: The current date for computing `expiresIn` option. Defaults to `new Date()`.

Returns a `Promise<string>` resolving to the JWS token in Compact Serialization format.

**Example (HS256 with string secret):**

```ts
import { sign } from "unjwt/jws";

const payload = { message: "My important data" }; // Object payload
const secret = "supersecretkey"; // String secret, will be imported (length depends on choosen alg)

const token = await sign(payload, secret, { alg: "HS256" });

console.log(token);
// eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
```

**Example (RS256 with CryptoKey):**

```ts
import { sign } from "unjwt/jws";
import { generateKey } from "unjwt/jwk";

const payload = { userId: 123, permissions: ["read"] };
const { privateKey } = await generateKey("RS256"); // Generates a CryptoKeyPair

const token = await sign(payload, privateKey, { alg: "RS256" });

console.log(token);
// eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...
```

#### `verify(jws, key, options?)`

Verifies a JWS token.

- `jws`: The JWS token string.
- `key`: The verification key (`CryptoKey`, `JWK`, `JWKSet`, `Uint8Array`, or a `KeyLookupFunction`).
  A `KeyLookupFunction` has the signature `(header: JWSProtectedHeader, jws: string) => Promise<CryptoKey | JWK | JWKSet | Uint8Array> | CryptoKey | JWK | JWKSet | Uint8Array`.
- `options` (optional):
  - `algorithms`: An array of allowed JWS `alg` values. If not provided, the `alg` from the JWS header is used.
  - `validateJWT`: Unless false, will parse payload as JWT and validate claims if applicable (typ includes "jwt", case insensitive). Default `undefined`.
  - `critical`: An array of JWS header parameter names that the application understands and processes.

Returns a `Promise<JWSVerifyResult<T>>` which is an object `{ payload: T, protectedHeader: JWSProtectedHeader }`.
The `payload` type `T` can be `JWTClaims` (object), `string`, or `Uint8Array` depending on the JWS content and headers.

**Example (HS256):**

```ts
import { verify } from "unjwt/jws";

const token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."; // From HS256 sign example
const secret = "supersecretkey";

const { payload, protectedHeader } = await verify(token, secret);
console.log(payload); // { message: "My important data" }
console.log(protectedHeader); // { alg: "HS256", typ: "JWT" }
```

**Example (RS256 with key lookup):**

```ts
import { verify } from "unjwt/jws";
import { generateKey } from "unjwt/jwk";

const token = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9..."; // From RS256 sign example

// Example: using a key lookup function
const { publicKey: rsaPublicKey } = await generateKey("RS256"); // For example purposes, assume publicKey is stored/fetched during lookup

const keyLookup = async (header) => {
  if (header.alg === "RS256" /* && header.kid === 'expected-kid' */) {
    return rsaPublicKey;
  }
  throw new Error("Unsupported algorithm or key not found");
};

const { payload } = await verify(token, keyLookup, { algorithms: ["RS256"] });
console.log(payload); // { userId: 123, permissions: ["read"] }
```

---

### JWE (JSON Web Encryption, [RFC 7516](https://datatracker.ietf.org/doc/html/rfc7516))

Functions to encrypt and decrypt data according to the JWE specification.

#### `encrypt(payload, key, options)`

Encrypts data to produce a JWE token.

- `payload`: The data to encrypt (`string`, `Uint8Array`, or a JSON-serializable `object`).
- `key`: The Key Encryption Key (KEK) or password (`CryptoKey`, `JWK`, `string`, or `Uint8Array`).
- `options`:
  - `alg`: (Required) The JWE Key Management algorithm (e.g., `"A128KW"`, `"RSA-OAEP-256"`, `"PBES2-HS256+A128KW"`, `"ECDH-ES+A128KW"`), defaults depends on the key provided.
  - `enc`: (Required) The JWE Content Encryption algorithm (e.g., `"A128GCM"`, `"A256CBC-HS512"`), defaults depends on the key provided.
  - `protectedHeader`: An object for JWE Protected Header parameters (e.g., `kid`, `typ`, `cty`, `crit`, `apu`, `apv`, `p2s`, `p2c`). If `payload` is an object and `typ` is not set, it defaults to `"JWT"`.
  - `cek`: (Optional) Provide your own Content Encryption Key (`CryptoKey` or `Uint8Array`).
  - `contentEncryptionIV`: (Optional) Provide your own Initialization Vector for content encryption (`Uint8Array`).
  - Other algorithm-specific options like `p2s`, `p2c` (for PBES2), `keyManagementIV`, `ecdhPartyUInfo`, `ecdhPartyVInfo`.

Returns a `Promise<string>` resolving to the JWE token in Compact Serialization format.

**Example (PBES2 password-based encryption):**

```ts
import { encrypt } from "unjwt/jwe";

const plaintext = "Secret message for password protection";
const password = "myVeryStrongPassword123!";

// Fallback to PBES2-HS256+A128KW and A128GCM if no `alg` and `end` are provided
const jweToken = await encrypt(plaintext, password);
console.log(jweToken);
// JWE token string...
```

**Example (A128KW with A128GCM):**

```ts
import { encrypt } from "unjwt/jwe";
import { generateKey } from "unjwt/jwk";

const payload = { data: "sensitive information" };
const kek = await generateKey("A128KW"); // AES Key Wrap key

const jweToken = await encrypt(payload, kek, {
  alg: "A128KW",
  enc: "A128GCM",
  protectedHeader: { kid: "aes-key-1" },
});

console.log(jweToken);
// eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4R0NNIiwia2lkIjoiYWVzLWtleS0xIn0...
```

#### `decrypt(jwe, key, options?)`

Decrypts a JWE token.

- `jwe`: The JWE token string.
- `key`: The Key Decryption Key (KDK) or password (`CryptoKey`, `JWK`, `string`, `Uint8Array`, or a `JWEKeyLookupFunction`).
  A `JWEKeyLookupFunction` has the signature `(header: JWEHeaderParameters) => Promise<CryptoKey | JWK | string | Uint8Array> | CryptoKey | JWK | string | Uint8Array`.
- `options` (optional):
  - `algorithms`: Array of allowed JWE Key Management `alg` values.
  - `validateJWT`: Unless false, will parse payload as JWT and validate claims if applicable (typ includes "jwt", case insensitive). Default `undefined`.
  - `encryptionAlgorithms`: Array of allowed JWE Content Encryption `enc` values.
  - `critical`: Array of JWE header parameter names that the application understands.
  - `unwrappedKeyAlgorithm`: (For `unwrapKey` internally) Algorithm details for the CEK after unwrapping.
  - `keyUsage`: (For `unwrapKey` internally) Intended usages for the unwrapped CEK.

Returns a `Promise<JWEDecryptResult<T>>` which is an object `{ payload: T, protectedHeader: JWEHeaderParameters, cek: Uint8Array, aad: Uint8Array }`.
The `payload` type `T` can be `JWTClaims` (object) or `string`.

**Example (PBES2 password-based decryption):**

```ts
import { decrypt } from "unjwt/jwe";
// const jweToken = ...; // From PBES2 encrypt example
// const password = "myVeryStrongPassword123!";

const { payload } = await decrypt(jweToken, password);
```

**Example (A128KW with A128GCM):**

```ts
import { decrypt } from "unjwt/jwe";
// const jweToken = "eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4R0NNIiwia2lkIjoiYWVzLWtleS0xIn0...";
// const kek = ...; // The same AES Key Wrap key used for encryption

async function decryptData(jweToken: string, kek: CryptoKey) {
  try {
    const { payload, protectedHeader, cek } = await decrypt(jweToken, kek, {
      algorithms: ["A128KW"],
      encryptionAlgorithms: ["A128GCM"],
    });
    console.log("Decrypted Plaintext:", payload);
    console.log("Protected Header:", protectedHeader);
    // console.log("CEK (Content Encryption Key):", cek);
  } catch (error) {
    console.error("Decryption failed:", error);
  }
}
```

---

### JWK (JSON Web Key, [RFC 7517](https://datatracker.ietf.org/doc/html/rfc7517))

Utilities for working with JSON Web Keys.

#### `generateKey(alg, options?)`

Generates a cryptographic key.

- `alg`: The JWA algorithm identifier for the key to be generated (e.g., `"HS256"`, `"RS256"`, `"ES256"`, `"A128KW"`, `"A128GCM"`, `"A128CBC-HS256"`).
- `options` (optional):
  - `toJWK`: If `true`, returns the key(s) in JWK format. Otherwise, returns `CryptoKey`(s) or `Uint8Array` (for composite keys like AES-CBC-HS\*). Default `false`.
  - `extractable`: Boolean, whether the generated `CryptoKey` can be exported. Default `true`.
  - `keyUsage`: Array of `KeyUsage` strings. Defaults are algorithm-specific.
  - `modulusLength`: For RSA keys (e.g., `2048`, `4096`). Default `2048`.
  - `publicExponent`: For RSA keys. Default `new Uint8Array([0x01, 0x00, 0x01])`.

Returns a `Promise` resolving to `CryptoKey`, `CryptoKeyPair`, `Uint8Array` (for composite keys), `JWK`, or `{ privateKey: JWK, publicKey: JWK }` depending on `alg` and `options.toJWK`.

**Examples:**

```ts
import { generateKey } from "unjwt/jwk";

// Generate an HS256 CryptoKey
const hmacKey = await generateKey("HS256");
console.log(hmacKey); // CryptoKey

// Generate an RS256 CryptoKeyPair
const rsaKeyPair = await generateKey("RS256", { modulusLength: 2048 });
console.log(rsaKeyPair.publicKey); // CryptoKey
console.log(rsaKeyPair.privateKey); // CryptoKey

// Generate an ES384 key pair as JWKs
const ecJwks = await generateKey("ES384", { toJWK: true });
console.log(ecJwks.publicKey); // JWK
console.log(ecJwks.privateKey); // JWK

// Generate a composite key for A128CBC-HS256 as Uint8Array
const aesCbcHsKeyBytes = await generateKey("A128CBC-HS256");
console.log(aesCbcHsKeyBytes); // Uint8Array (32 bytes: 16 for AES, 16 for HMAC)

// Generate an A256GCM key as a JWK
const aesGcmJwk = await generateKey("A256GCM", { toJWK: true });
console.log(aesGcmJwk); // JWK
```

#### `deriveKeyFromPassword(password, alg, options)`

Derives a key from a password using PBKDF2 for PBES2 algorithms.

- `password`: The password (`string` or `Uint8Array`).
- `alg`: The PBES2 algorithm (e.g., `"PBES2-HS256+A128KW"`).
- `options`:
  - `salt`: The salt (`Uint8Array`, at least 8 octets).
  - `iterations`: The iteration count (positive integer).
  - `toJWK`: If `true`, returns a `JWK_oct`. Otherwise, `CryptoKey`. Default `false`.
  - `extractable`: Boolean for `CryptoKey`. Default `false` unless `toJWK` is true.
  - `keyUsage`: For `CryptoKey`. Default `["wrapKey", "unwrapKey"]`.

Returns a `Promise` resolving to `CryptoKey` or `JWK_oct`.

**Example:**

```ts
import { deriveKeyFromPassword } from "unjwt/jwk";
import { randomBytes, textEncoder } from "unjwt/utils";

const password = "mySecretPassword";
const salt = randomBytes(16);
const iterations = 4096;

const derivedKey = await deriveKeyFromPassword(password, "PBES2-HS384+A192KW", {
  salt,
  iterations,
});
console.log(derivedKey); // CryptoKey for AES-KW (192-bit)

const derivedJwk = await deriveKeyFromPassword(password, "PBES2-HS512+A256KW", {
  salt,
  iterations,
  toJWK: true,
});
console.log(derivedJwk); // JWK_oct { kty: "oct", k: "...", alg: "A256KW" }
```

#### `importKey(keyMaterial, alg?)`

Imports a key from various formats. This is a flexible wrapper.

- `keyMaterial`: The key to import. Can be:
  - `CryptoKey`: Returned directly.
  - `Uint8Array`: Returned directly (treated as raw symmetric key bytes).
  - `string`: Encoded to `Uint8Array` and returned.
  - `JWK_oct` (symmetric JWK with `k` property): The `k` value is Base64URL decoded and returned as `Uint8Array`.
  - Other `JWK` types (asymmetric): Imported into a `CryptoKey`.
- `alg` (optional): The JWA algorithm string. **Required** when importing asymmetric JWKs (e.g., RSA, EC) to provide context for `crypto.subtle.importKey`.

Returns a `Promise` resolving to `CryptoKey` or `Uint8Array`.

**Examples:**

```ts
import { importKey } from "unjwt/jwk";
import { textEncoder, base64UrlDecode } from "unjwt/utils";

// Import raw symmetric key bytes
const rawBytes = textEncoder.encode("a-32-byte-long-secret-key-123"); // 32 bytes for AES-256 or HS256
const symmetricKeyBytes = await importKey(rawBytes);
console.log(symmetricKeyBytes); // Uint8Array

// Import a symmetric JWK (kty: "oct")
const octJwk = {
  kty: "oct",
  k: "AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr0", // Example key
};
const importedOctBytes = await importKey(octJwk); // Returns Uint8Array
console.log(importedOctBytes); // Uint8Array (decoded from k)

// Import an RSA Public Key JWK
const rsaPublicJwk = {
  kty: "RSA",
  n: "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3ok92YEnjsADC4Ue87zwRzH2J-TCwlcQrY3E9gGZJZL2g_2_5QjLhL0gR0xYj04_N4M",
  e: "AQAB",
  alg: "RS256",
  kid: "rsa-pub-1",
};
const rsaPublicKey = await importKey(rsaPublicJwk, "RS256"); // 'alg' is crucial here
console.log(rsaPublicKey); // CryptoKey
```

#### `exportKey(key, jwk?)`

Exports a `CryptoKey` to JWK format.

- `key`: The `CryptoKey` to export (must be `extractable`).
- `jwk` (optional): A partial `JWK` object to merge with the exported properties (e.g., to add `kid`, `use`, or override `alg`).

Returns a `Promise<JWK>`.

**Example:**

```ts
import { generateKey, exportKey } from "unjwt/jwk";

const { publicKey } = await generateKey("ES256"); // Generates an extractable CryptoKey

const jwk = await exportKey(publicKey, { kid: "ec-key-001", use: "sig" });
console.log(jwk);
// {
//   kty: 'EC',
//   crv: 'P-256',
//   x: '...',
//   y: '...',
//   ext: true,
//   key_ops: [ 'verify' ], // or as per generation
//   kid: 'ec-key-001',
//   use: 'sig'
// }
```

#### `wrapKey(alg, keyToWrap, wrappingKey, options?)`

Wraps a Content Encryption Key (CEK).

- `alg`: The JWA key management algorithm (e.g., `"A128KW"`, `"RSA-OAEP"`).
- `keyToWrap`: The CEK to wrap (`CryptoKey` or `Uint8Array`).
- `wrappingKey`: The Key Encryption Key (KEK) (`CryptoKey`, `JWK`, or password `string`/`Uint8Array` for PBES2).
- `options` (optional): Algorithm-specific options (e.g., `p2s`, `p2c` for PBES2; `iv` for AES-GCMKW).

Returns a `Promise<WrapKeyResult>` containing `encryptedKey` and other parameters like `iv`, `tag`, `epk`, `p2s`, `p2c` as needed by the algorithm.

**Example (AES Key Wrap):**

```ts
import { wrapKey, generateKey } from "unjwt/jwk";
import { randomBytes } from "unjwt/utils";

const cekToWrap = randomBytes(32); // e.g., a 256-bit AES key as Uint8Array
const kek = await generateKey("A128KW"); // 128-bit AES Key Wrap key

const { encryptedKey } = await wrapKey("A128KW", cekToWrap, kek);
console.log("Wrapped CEK:", encryptedKey); // Uint8Array
```

#### `unwrapKey(alg, wrappedKey, unwrappingKey, options?)`

Unwraps a Content Encryption Key (CEK).

- `alg`: The JWA key management algorithm.
- `wrappedKey`: The encrypted CEK (`Uint8Array`).
- `unwrappingKey`: The Key Decryption Key (KDK).
- `options` (optional):
  - `returnAs`: If `false`, returns `Uint8Array`. If `true` (default) or undefined, returns `CryptoKey`.
  - `unwrappedKeyAlgorithm`: `AlgorithmIdentifier` for the imported CEK if `returnAs` is `true`.
  - `keyUsage`: `KeyUsage[]` for the imported CEK if `returnAs` is `true`.
  - `extractable`: Boolean for the imported CEK.
  - Other algorithm-specific options (e.g., `p2s`, `p2c`, `iv`, `tag`, `epk`).

Returns a `Promise` resolving to the unwrapped CEK as `CryptoKey` or `Uint8Array`.

**Example (AES Key Unwrap):**

```ts
import { unwrapKey, generateKey } from "unjwt/jwk";
// const encryptedKey = ...; // From wrapKey example
// const kdk = ...; // Same KEK used for wrapping

async function unwrapMyKey(encryptedKey: Uint8Array, kdk: CryptoKey) {
  const unwrappedCekBytes = await unwrapKey("A128KW", encryptedKey, kdk, {
    returnAs: false, // Get raw bytes
  });
  console.log("Unwrapped CEK (bytes):", unwrappedCekBytes); // Uint8Array

  const unwrappedCekCryptoKey = await unwrapKey("A128KW", encryptedKey, kdk, {
    returnAs: true, // Get CryptoKey
    unwrappedKeyAlgorithm: { name: "AES-GCM", length: 256 }, // Specify CEK's intended alg
    keyUsage: ["encrypt", "decrypt"],
  });
  console.log("Unwrapped CEK (CryptoKey):", unwrappedCekCryptoKey); // CryptoKey
}
```

#### `importJWKFromPEM(pem, pemType, alg, importOptions?, jwkExtras?)`

Imports a key from a PEM-encoded string and converts it to a JWK.

- `pem`: The PEM-encoded string (including `-----BEGIN ...-----` and `-----END ...-----` markers).
- `pemType`: The type of PEM encoding:
  - `"pkcs8"`: For private keys in PKCS#8 format.
  - `"spki"`: For public keys in SPKI format.
  - `"x509"`: For X.509 certificates (extracts the public key).
- `alg`: The JWA algorithm identifier (e.g., `"RS256"`, `"ES256"`). This is crucial for `crypto.subtle.importKey` to understand the key's intended algorithm and for setting the `'alg'` field in the resulting JWK.
- `importOptions` (optional): Options for the underlying `crypto.subtle.importKey` call:
  - `extractable`: Boolean, whether the imported `CryptoKey` should be extractable. Defaults to `true`.
  - `keyUsage`: Array of `KeyUsage` strings for the imported `CryptoKey`.
- `jwkExtras` (optional): An object containing additional properties to merge into the resulting JWK (e.g., `"kid"`, `"use"`).

Returns a `Promise<JWK>` resolving to the imported key as a JWK.

**Example:**

```ts
import { importJWKFromPEM } from "unjwt/jwk";

const rsaPublicJwk = await importJWKFromPEM(
  provess.env.RSA_PEM_SPKI, // PEM string
  "spki",
  "RS256",
  { extractable: false },
  { kid: "my-rsa-key" }, // Additional properties to add to the JWK
);
console.log(rsaPublicJwk);
// {
//   kty: 'RSA',
//   alg: 'RS256',
//   kid: 'my-rsa-key',
//   n: '...',
//   e: 'AQAB',
//   ext: false,
//   key_ops: [ 'verify' ]
// }
```

#### exportJWKToPEM(jwk, pemFormat, algForCryptoKeyImport?)

Exports a JWK to a PEM-encoded string.

- jwk: The JWK to export.
- pemFormat: The desired PEM format:
  - "pkcs8": For private keys in PKCS#8 format.
  - "spki": For public keys in SPKI format.
- algForCryptoKeyImport (optional): If the JWK does not have an 'alg' property, this algorithm hint is required to correctly convert it to a CryptoKey first. This is only needed if the JWK lacks an alg property.

Returns a `Promise<string>` resolving to the PEM-encoded key string.

Example:

```ts
import { exportJWKToPEM } from "unjwt/jwk";
import { rsaJWK } from "./keys"; // Assuming you have JWKs in keys.ts

const rsaPrivatePem = await exportJWKToPEM(rsaJWK.private, "pkcs8");
console.log(rsaPrivatePem);
// -----BEGIN PRIVATE KEY-----
// MII...
// -----END PRIVATE KEY-----

const rsaPublicSpki = await exportJWKToPEM(
  rsaJWK.public,
  "spki",
  "RS256", // this is required if `rsaJWK.public.alg` is undefined
);
console.log(rsaPublicSpki);
// -----BEGIN PUBLIC KEY-----
// MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQE...
// -----END PUBLIC KEY-----
```

---

### Utility Functions

`unjwt/utils` exports several helpful functions:

- `base64UrlEncode(data: Uint8Array | string): string`
- `base64UrlDecode(str?: string, toString?: boolean): Uint8Array | string` (Decodes to string by default, or `Uint8Array` if `toString` is `false`)
- `randomBytes(length: number): Uint8Array`
- `textEncoder: TextEncoder`
- `textDecoder: TextDecoder`
- Type guards: `isJWK(key)`, `isCryptoKey(key)`, `isCryptoKeyPair(keyPair)`

## Development

<details>

<summary>local development</summary>

- Clone this repository
- Install latest LTS version of [Node.js](https://nodejs.org/en/)
- Enable [Corepack](https://github.com/nodejs/corepack) using `corepack enable`
- Install dependencies using `pnpm install`
- Run interactive tests using `pnpm dev`

</details>

## Credits

Originally developed by [Johann Schopplich](https://github.com/johannschopplich/unjwt).
Heavily inspired by [Filip Skokan's work](https://github.com/panva/jose).

## License

<!-- automd:contributors license=MIT -->

Published under the [MIT](https://github.com/sandros94/unjwt/blob/main/LICENSE) license.
Made by [community](https://github.com/sandros94/unjwt/graphs/contributors) 💛
<br><br>
<a href="https://github.com/sandros94/unjwt/graphs/contributors">
<img src="https://contrib.rocks/image?repo=sandros94/unjwt" />
</a>

<!-- /automd -->

<!-- automd:with-automd -->

---

_🤖 auto updated with [automd](https://automd.unjs.io)_

<!-- /automd -->
