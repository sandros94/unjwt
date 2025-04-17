# unjwt

<!-- automd:badges color=yellow -->

[![npm version](https://img.shields.io/npm/v/unjwt?color=yellow)](https://npmjs.com/package/unjwt)
[![npm downloads](https://img.shields.io/npm/dm/unjwt?color=yellow)](https://npm.chart.dev/unjwt)

<!-- /automd -->

Low-level JWT utilities. Currently supports JWE (JSON Web Encryption) with password-based key derivation (PBES2).

## Usage

Install the package:

```sh
# ✨ Auto-detect (supports npm, yarn, pnpm, deno and bun)
npx nypm install unjwt
```

Import:

<!-- automd:jsimport cdn name="unjwt" imports="seal,unseal" -->

**ESM** (Node.js, Bun, Deno)

```js
import { seal, unseal } from "unjwt";
```

**CDN** (Deno, Bun and Browsers)

```js
import { seal, unseal } from "https://esm.sh/unjwt";
```

<!-- /automd -->

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
import { seal } from "unjwt";

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
import { unseal } from "unjwt";

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
