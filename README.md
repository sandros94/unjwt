# unjwt

<!-- automd:badges color=yellow -->

[![npm version](https://img.shields.io/npm/v/unjwt?color=yellow)](https://npmjs.com/package/unjwt)
[![npm downloads](https://img.shields.io/npm/dm/unjwt?color=yellow)](https://npm.chart.dev/unjwt)

<!-- /automd -->

Low-level JWT utilities using the Web Crypto API. Currently supports:

- JWE (JSON Web Encryption) with password-based key derivation (PBES2).
- JWS (JSON Web Signature) with symmetric keys (HMAC).
- JWK (JSON Web Key) generation, import, and export for symmetric keys (`oct`).

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
import { seal, unseal } from "unjwt/jwe";
import { sign, verify } from "unjwt/jws";
import { generateKey, exportKey, importKey } from "unjwt/jwk";
```

**CDN** (Deno, Bun and Browsers)

```js
import { jws, jwe, jwk } from "https://esm.sh/unjwt";
import { seal, unseal } from "https://esm.sh/unjwt/jwe";
import { sign, verify } from "https://esm.sh/unjwt/jws";
import { generateKey, exportKey, importKey } from "https://esm.sh/unjwt/jwk";
```

### JWE (JSON Web Encryption)

This library provides functions to encrypt (seal) and decrypt (unseal) data according to the JWE specification using password-based encryption.

#### `seal(data, password, options?)`

Encrypts the provided data using a password.

- `data`: The data to encrypt (string or `Uint8Array`).
- `password`: The password to use for encryption (string or `Uint8Array`).
- `options` (optional):
  - `iterations`: Number of PBKDF2 iterations (default: `2048`).
  - `saltSize`: Size of the random salt in bytes (default: `16`).
  - `protectedHeader`: An object containing JWE header parameters to include.
    - `alg`: Key Wrapping Algorithm (default: `PBES2-HS256+A128KW`). Supported: `PBES2-HS256+A128KW`, `PBES2-HS384+A192KW`, `PBES2-HS512+A256KW`.
    - `enc`: Content Encryption Algorithm (default: `A256GCM`). Supported: `A128GCM`, `A192GCM`, `A256GCM`, `A128CBC-HS256`, `A192CBC-HS384`, `A256CBC-HS512`.
    - Other standard JWE or custom header parameters can be added here.

Returns a Promise resolving to the JWE token string in Compact Serialization format.

**Example:**

```ts
import { seal } from "unjwt/jwe";

const plaintext = "My secret data";
const password = "strongpassword";

const token = await seal(plaintext, password, {
  protectedHeader: {
    alg: "PBES2-HS512+A256KW",
    enc: "A256GCM",
  },
});

console.log(token);
// eyJhbGciOiJQQkVTMi1IUzUxMitBMjU2S1ciLCJlbmMiOiJBMjU2R0NNIiwicDJzIjoi...
```

#### `unseal(token, password, options?)`

Decrypts a JWE token using a password.

- `token`: The JWE token string (Compact Serialization).
- `password`: The password used for encryption (string or `Uint8Array`).
- `options` (optional):
  - `textOutput`: If `false`, returns the decrypted data as a `Uint8Array` instead of a string (default: `true`).

Returns a Promise resolving to the decrypted data (string or `Uint8Array`).

**Example:**

```ts
import { unseal } from "unjwt/jwe";

const token =
  "eyJhbGciOiJQQkVTMi1IUzUxMitBMjU2S1ciLCJlbmMiOiJBMjU2R0NNIiwicDJzIjoi..."; // From seal example
const password = "strongpassword";

// Decrypt as string (default)
const decryptedString = await unseal(token, password);
console.log(decryptedString); // "My secret data"

// Decrypt as Uint8Array
const decryptedBytes = await unseal(token, password, { textOutput: false });
console.log(decryptedBytes); // Uint8Array [ 77, 121, 32, ... ]
```

### JWS (JSON Web Signature)

This library provides functions to sign (sign) and verify (verify) data according to the JWS specification using HMAC with symmetric keys.

#### `sign(data, secret, options?)`

Signs the provided payload using a symmetric secret.

- `payload`: The data to sign (string or `Uint8Array`).
- `secret`: The symmetric secret key to use for signing. Can be:
  - A `string`.
  - A `Uint8Array` containing the raw key bytes.
  - A symmetric JSON Web Key (`JWK`) object (with `kty: "oct"`).
- `options` (optional):
  - `protectedHeader`: An object containing JWS header parameters to include.
    - alg: Signing Algorithm (default: `HS256`). Supported: `HS256`, `HS384`, `HS512`.
    - Other standard JWS or custom header parameters can be added here.

Returns a Promise resolving to the JWS token string in Compact Serialization format.

**Example (using string secret):**

```ts
import { sign } from "unjwt/jws";

const payload = JSON.stringify({ message: "My important data" });
const secret = "supersecretkey";

const token = await sign(payload, secret, {
  protectedHeader: {
    alg: "HS512",
  },
});

console.log(token);
// eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9...
```

**Example (using JWK secret):**

```ts
import { sign } from "unjwt/jws";
import { generateKey } from "unjwt/jwk";

const payload = JSON.stringify({ message: "Data signed with JWK" });
// Generate a JWK suitable for HS256
const secretJwk = await generateKey("oct", 256, { alg: "HS256" });

const token = await sign(payload, secretJwk); // alg defaults to HS256

console.log(token);
// eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
```

#### `verify(token, secret, options?)`

Verifies a JWS token using a symmetric secret.

- `token`: The JWS token string (Compact Serialization).
- `secret`: The symmetric secret key used for signing. Can be:
  - A `string`.
  - A `Uint8Array` containing the raw key bytes.
  - A symmetric JSON Web Key (`JWK`) object (with `kty: "oct"`).
- `options` (optional):
  - `textOutput`: If `false`, returns the verified payload as a `Uint8Array` instead of a string (default: `true`).

Returns a Promise resolving to the verified payload (string or `Uint8Array`). Throws an error if the signature is invalid or the token is malformed.

**Example (using string secret):**

```ts
import { verify } from "unjwt/jws";

const token = "eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9..."; // From sign example
const secret = "supersecretkey";

// Verify as string (default)
const verifiedString = await verify(token, secret);
console.log(verifiedString); // {"message":"My important data"}

// Verify as Uint8Array
const verifiedBytes = await verify(token, secret, { textOutput: false });
console.log(verifiedBytes); // Uint8Array [ 123, 34, ... ]
```

**Example (using JWK secret):**

```ts
import { verify } from "unjwt/jws";
import { generateKey } from "unjwt/jwk";

const token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."; // From sign example
const secretJwk = { kty: "oct", k: "...", alg: "HS256" }; // Load or use the generated JWK

const verifiedPayload = await verify(token, secretJwk);
console.log(verifiedPayload); // {"message":"Data signed with JWK"}
```

### JWK (JSON Web Key)

This library provides functions to generate (`generateKey`), export (`exportKey`), and import (`importKey`) symmetric keys (`kty: "oct"`) using the Web Crypto API.

#### `generateKey(type, length, jwk?)`

Generates a new key as a JWK object.

- `type`: The key type. Currently only supports `"oct"` (symmetric).
- `length`(for `"oct"`): Key length in bits (e.g., `128`, `192`, `256`, `512`). Choose a length appropriate for the intended algorithm (e.g., >= 256 for HS256, >= 384 for HS384, >= 512 for HS512).
- `jwk` (optional, for `"oct"`): Any valid JWK param such as a JWA algorithm identifier (e.g., `HS256`, `A128KW`) to include in the generated JWK.

Returns a Promise resolving to the generated key as a JWK object (`{ kty: "oct", k: "...", ... }`).

**Example:**

```ts
import { generateKey } from "unjwt/jwk";

// Generate a 512-bit key suitable for HS512
const jwk = await generateKey("oct", 512, { alg: "HS512" });

console.log(jwk);
// {
//   kty: 'oct',
//   k: '...', // base64url encoded key material
//   ext: true,
//   alg: 'HS512'
// }
```

#### `exportKey(key)`

Exports a symmetric `CryptoKey` to JWK format.

- `key`: The `CryptoKey` to export. It must be `extractable` and currently only of type `"secret"`.

Returns a Promise resolving to the exported key as a JWK object. The JWK will include `kty`, `k`, `key_ops`, `ext`, and potentially `alg` based on the `CryptoKey`'s algorithm.

**Example:**

```ts
import { importKey, exportKey } from "unjwt/jwk";

// First, import or generate a CryptoKey
const rawKeyBytes = new TextEncoder().encode(
  "a-very-secure-secret-key-for-hmac",
);
const cryptoKey = await importKey(
  rawKeyBytes,
  { name: "HMAC", hash: "SHA-256" },
  true, // Must be extractable to export
  ["sign", "verify"],
);

// Now export the CryptoKey to JWK
const jwk = await exportKey(cryptoKey);

console.log(jwk);
// {
//   kty: 'oct',
//   k: 'YS12ZXJ5LXNlY3VyZS1zZWNyZXQta2V5LWZvci1obWFj',
//   alg: 'HS256',
//   key_ops: [ 'sign', 'verify' ],
//   ext: true
// }
```

#### `importKey(key, algorithm, extractable, keyUsages)`

Imports a symmetric key from various formats into a `CryptoKey` object.

- `key`: The key material to import. Can be:
  - A symmetric JSON Web Key (`JWK`) object (with `kty: "oct"` and a `k` property).
  - A `string` representing the raw secret.
  - A `Uint8Array` containing the raw key bytes.
- `algorithm`: The Web Crypto `AlgorithmIdentifier` object specifying the algorithm the key will be used for (e.g., `{ name: "HMAC", hash: "SHA-256" }`, `{ name: "AES-GCM", length: 256 }`).
- `extractable`: A boolean indicating whether the generated `CryptoKey` can be exported later (using `exportKey` or `crypto.subtle.exportKey`).
- `keyUsages`: An array of strings indicating the allowed operations for the key (e.g., `["sign", "verify"]`, `["encrypt", "decrypt"]`, `["wrapKey", "unwrapKey"]`).

Returns a Promise resolving to the imported `CryptoKey` object.

**Example (importing a JWK):**

```ts
import { importKey } from "unjwt/jwk";

const jwk = {
  kty: "oct",
  k: "AyMee--70a4a4xED9qS4sN0KxBas6KTMx7_Q9Gf6nvM", // Example base64url key
  alg: "HS256", // Optional hint, but algorithm param below is definitive
};

const cryptoKey = await importKey(
  jwk,
  { name: "HMAC", hash: "SHA-256" }, // Algorithm for the CryptoKey
  false, // Make this key non-extractable
  ["verify"], // Allow only verification usage
);

console.log(cryptoKey);
// CryptoKey { type: 'secret', extractable: false, algorithm: { ... }, usages: [ 'verify' ] }
```

**Example (importing a raw string):**

```ts
import { importKey } from "unjwt/jwk";

const rawSecret = "my-raw-password-string";

const cryptoKey = await importKey(
  rawSecret,
  { name: "HMAC", hash: "SHA-384" },
  true,
  ["sign"],
);

console.log(cryptoKey);
// CryptoKey { type: 'secret', extractable: true, algorithm: { ... }, usages: [ 'sign' ] }
```

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
