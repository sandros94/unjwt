# unjwt

<!-- automd:badges color=yellow -->

[![npm version](https://img.shields.io/npm/v/unjwt?color=yellow)](https://npmjs.com/package/unjwt)
[![npm downloads](https://img.shields.io/npm/dm/unjwt?color=yellow)](https://npm.chart.dev/unjwt)

<!-- /automd -->

Low-level JWT utilities. Currently supports:

- JWE (JSON Web Encryption) with password-based key derivation (PBES2).
- JWS (JSON Web Signature) with symmetric keys (HMAC).
- JWK (JSON Web Key) generation and import/export for symmetric keys (`oct`).

## Usage

Install the package:

```sh
# ✨ Auto-detect (supports npm, yarn, pnpm, deno and bun)
npx nypm install unjwt
```

Import:

**ESM** (Node.js, Bun, Deno)

```js
import { seal, unseal } from "unjwt/jwe";
import { sign, verify } from "unjwt/jws";
import { generateKey, exportKey, importKey } from "unjwt/jwk";
```

**CDN** (Deno, Bun and Browsers)

```js
import { seal, unseal } from "https://esm.sh/unjwt/jwe";
import { sign, verify } from "https://esm.sh/unjwt/jws";
import { generateKey, exportKey, importKey } from "https://esm.sh/unjwt/jwk";
```

### JWE (JSON Web Encryption)

This library provides functions to encrypt (`seal`) and decrypt (`unseal`) data according to the JWE specification using password-based encryption.

#### `seal(data, password, options?)`

Encrypts the provided data using a password.

- `data`: The data to encrypt (string or `Uint8Array`).
- `password`: The password to use for encryption (string or `Uint8Array`).
- `options` (optional):
  - `iterations`: Number of PBKDF2 iterations (default: `2048`).
  - `saltSize`: Size of the random salt in bytes (default: `16`).
  - `protectedHeader`: An object containing JWE header parameters to include.
    - `alg`: Key Wrapping Algorithm (default: `"PBES2-HS256+A128KW"`). Supported: `PBES2-HS256+A128KW`, `PBES2-HS384+A192KW`, `PBES2-HS512+A256KW`.
    - `enc`: Content Encryption Algorithm (default: `"A256GCM"`). Supported: `A128GCM`, `A192GCM`, `A256GCM`.
    - Other standard JWE or custom header parameters can be added here.

Returns a Promise resolving to the JWE token string in Compact Serialization format.

**Example:**

```typescript
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

```typescript
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

This library provides functions to sign (`sign`) and verify (`verify`) data according to the JWS specification using HMAC.

#### `sign(data, key, options?)`

Signs the provided data using a symmetric key.

- `data`: The data to sign (string or `Uint8Array`).
- `key`: The symmetric key to use for signing (string or `Uint8Array`).
- `options` (optional):
  - `protectedHeader`: An object containing JWS header parameters to include.
    - `alg`: Signing Algorithm (default: `"HS256"`). Supported: `HS256`, `HS384`, `HS512`.
    - Other standard JWS or custom header parameters can be added here.

Returns a Promise resolving to the JWS token string in Compact Serialization format.

**Example:**

```typescript
import { sign } from "unjwt/jws";

const data = "My important data";
const key = "supersecretkey";

const token = await sign(data, key, {
  protectedHeader: {
    alg: "HS512",
  },
});

console.log(token);
// eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9...
```

#### `verify(token, key, options?)`

Verifies a JWS token using a symmetric key.

- `token`: The JWS token string (Compact Serialization).
- `key`: The symmetric key used for signing (string or `Uint8Array`).
- `options` (optional):
  - `textOutput`: If `false`, returns the verified data as a `Uint8Array` instead of a string (default: `true`).

Returns a Promise resolving to the verified data (string or `Uint8Array`).

**Example:**

```typescript
import { verify } from "unjwt/jws";

const token = "eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9..."; // From sign example
const key = "supersecretkey";

// Verify as string (default)
const verifiedString = await verify(token, key);
console.log(verifiedString); // "My important data"

// Verify as Uint8Array
const verifiedBytes = await verify(token, key, { textOutput: false });
console.log(verifiedBytes); // Uint8Array [ 77, 121, 32, ... ]
```

### JWK (JSON Web Key)

This library provides functions to generate (`generateKey`), export (`exportKey`), and import (`importKey`) symmetric keys according to the JWK specification.

#### `generateKey(options?)`

Generates a new symmetric key.

- `options` (optional):
  - `alg`: Algorithm for the key (default: `"HS256"`). Supported: `HS256`, `HS384`, `HS512`.
  - `keySize`: Size of the key in bits (default: `256`).

Returns a Promise resolving to the generated key as a `Uint8Array`.

**Example:**

```typescript
import { generateKey } from "unjwt/jwk";

const key = await generateKey({
  alg: "HS512",
  keySize: 512,
});

console.log(key);
// Uint8Array [ 123, 45, 67, ... ]
```

#### `exportKey(key, options?)`

Exports a symmetric key to JWK format.

- `key`: The symmetric key to export (`Uint8Array`).
- `options` (optional):
  - `alg`: Algorithm for the key (default: `"HS256"`). Supported: `HS256`, `HS384`, `HS512`.

Returns a Promise resolving to the exported key as a JWK object.

**Example:**

```typescript
import { exportKey } from "unjwt/jwk";

const key = new Uint8Array([123, 45, 67 /*...*/]);

const jwk = await exportKey(key, {
  alg: "HS512",
});

console.log(jwk);
// { kty: "oct", alg: "HS512", k: "eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9..." }
```

#### `importKey(jwk)`

Imports a symmetric key from JWK format.

- `jwk`: The JWK object to import.

Returns a Promise resolving to the imported key as a `Uint8Array`.

**Example:**

```typescript
import { importKey } from "unjwt/jwk";

const jwk = {
  kty: "oct",
  alg: "HS512",
  k: "eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9...",
};

const key = await importKey(jwk);

console.log(key);
// Uint8Array [ 123, 45, 67, ... ]
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
