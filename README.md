# unjwt

[![npm version](https://npmx.dev/api/registry/badge/version/unjwt?name=true)](https://npmx.dev/package/unjwt)
[![npm downloads](https://npmx.dev/api/registry/badge/downloads/unjwt)](https://npmx.dev/package/unjwt)
[![bundle size](https://npmx.dev/api/registry/badge/size/unjwt)](https://npmx.dev/package/unjwt)

A collection of low-level JWT ([RFC 7519](https://datatracker.ietf.org/doc/html/rfc7519)) utilities using the Web Crypto API. Supports:

- **JWS** ([RFC 7515](https://datatracker.ietf.org/doc/html/rfc7515)) — sign and verify tokens using HMAC, RSA, RSA-PSS, ECDSA, and EdDSA algorithms
- **JWE** ([RFC 7516](https://datatracker.ietf.org/doc/html/rfc7516)) — encrypt and decrypt data using AES Key Wrap, AES-GCM KW, RSA-OAEP, PBES2, and ECDH-ES key management with AES-GCM or AES-CBC+HMAC-SHA2 content encryption
- **JWK** ([RFC 7517](https://datatracker.ietf.org/doc/html/rfc7517)) — generate, import, export, wrap, and unwrap keys (CryptoKey, JWK, PEM)
- **Framework adapters** for cookie-based JWT sessions:
  - [H3 v1](./skills/unjwt/references/adapters-h3.md) (Nuxt v4, Nitro v2)
  - [H3 v2](./skills/unjwt/references/adapters-h3.md) (Nuxt v5, Nitro v3)

Zero runtime dependencies for core. Optional peer deps for adapters (`h3`, `cookie-es`, `rou3`).

## Install

```sh
# Auto-detect package manager (npm, yarn, pnpm, deno, bun)
npx nypm install unjwt
```

If you would like to install the agent skill you can run:

```sh
npx skills add sandros94/unjwt
```

## Usage

### JWS — Sign & Verify

> Full reference: [skills/unjwt/references/jws.md](./skills/unjwt/references/jws.md)

```ts
import { sign, verify } from "unjwt/jws";
import { generateJWK } from "unjwt/jwk";
// or import both from the root: import { sign, verify, generateJWK } from "unjwt";

// Generate a key (HMAC, RSA, ECDSA, EdDSA, etc.)
const key = await generateJWK("HS256");

// Sign a JWT
const token = await sign(
  { sub: "user123", role: "admin" },
  key,
  { expiresIn: "1h" }, // supports: number (seconds), "30s", "10m", "2h", "7D", "1Y"
);

// Verify and extract payload
const { payload, protectedHeader } = await verify(token, key);
console.log(payload); // { sub: "user123", role: "admin", iat: ..., exp: ... }
```

**Asymmetric keys (RS256, ES256, PS256, Ed25519, etc.):**

```ts
const keys = await generateJWK("RS256");
const token = await sign({ sub: "user123" }, keys.privateKey);
const { payload } = await verify(token, keys.publicKey);
```

**Key lookup function for dynamic key resolution:**

```ts
const { payload } = await verify(
  token,
  async (header) => {
    // Resolve key by kid, alg, or any header field
    return await fetchPublicKeyByKid(header.kid);
  },
  { algorithms: ["RS256"] },
);
```

### JWE — Encrypt & Decrypt

> Full reference: [skills/unjwt/references/jwe.md](./skills/unjwt/references/jwe.md)

```ts
import { encrypt, decrypt } from "unjwt/jwe";
// or: import { encrypt, decrypt } from "unjwt";

// Password-based encryption (simplest — uses PBES2)
const token = await encrypt({ secret: "sensitive data" }, "my-password");
const { payload } = await decrypt(token, "my-password");
```

**With explicit key management:**

```ts
import { generateJWK } from "unjwt/jwk";

// AES Key Wrap
const aesKey = await generateJWK("A256KW");
const token = await encrypt({ data: "secret" }, aesKey);

// RSA-OAEP
const rsaKeys = await generateJWK("RSA-OAEP-256");
const token2 = await encrypt({ data: "secret" }, rsaKeys.publicKey);
const { payload } = await decrypt(token2, rsaKeys.privateKey);

// ECDH-ES
const ecKeys = await generateJWK("ECDH-ES+A256KW");
const token3 = await encrypt({ data: "secret" }, ecKeys.publicKey);
```

### JWK — Key Management

> Full reference: [skills/unjwt/references/jwk.md](./skills/unjwt/references/jwk.md)

```ts
import {
  generateKey,
  generateJWK,
  importKey,
  exportKey,
  importJWKFromPEM,
  exportJWKToPEM,
  wrapKey,
  unwrapKey,
  deriveKeyFromPassword,
} from "unjwt/jwk";
// All of the above are also importable from "unjwt" directly.

// Generate keys as CryptoKey or JWK
const hmacKey = await generateKey("HS256"); // CryptoKey
const rsaPair = await generateKey("RS256"); // CryptoKeyPair
const ecJwk = await generateJWK("ES256", { kid: "k1" }); // { privateKey: JWK, publicKey: JWK }

// PEM conversion
const jwk = await importJWKFromPEM(pemString, "spki", "RS256", undefined, { kid: "rsa-1" });
const pem = await exportJWKToPEM(jwk, "spki");

// Key wrapping
const cek = crypto.getRandomValues(new Uint8Array(32));
const { encryptedKey } = await wrapKey("A256KW", cek, aesKey);
const unwrapped = await unwrapKey("A256KW", encryptedKey, aesKey, { returnAs: false });
```

### Utility Functions

> Full reference: [skills/unjwt/references/utils.md](./skills/unjwt/references/utils.md)

```ts
import {
  base64UrlEncode,
  base64UrlDecode,
  randomBytes,
  isJWK,
  isJWKSet,
  isSymmetricJWK,
  isPrivateJWK,
  isPublicJWK,
  isCryptoKey,
  textEncoder,
  textDecoder,
} from "unjwt/utils";
// Most of the above are also importable from "unjwt" directly.

const bytes = randomBytes(32);
const encoded = base64UrlEncode(bytes);
const decoded = base64UrlDecode(encoded, false); // Uint8Array
```

### H3 Session Adapters

> Full reference: [skills/unjwt/references/adapters-h3.md](./skills/unjwt/references/adapters-h3.md)

Cookie-based JWT session management for H3 applications. Sessions are stored as encrypted (JWE) or signed (JWS) tokens in chunked cookies.

> **Note:** Sessions are lazy — `session.id` is `undefined` until `session.update()` is called. This is intentional for OAuth/spec-compliant flows where sessions should only be created upon valid operations.

#### JWE Session (encrypted, recommended for sensitive data)

```ts
import { useJWESession, generateJWK } from "unjwt/adapters/h3v2";

app.get("/profile", async (event) => {
  const session = await useJWESession(event, {
    key: process.env.SESSION_SECRET!, // password string, symmetric JWK, or asymmetric keypair
    maxAge: "7D",
  });

  if (!session.id) {
    // No active session — create one
    await session.update({ userId: "123", email: "user@example.com" });
  }

  return { user: session.data };
});
```

#### JWS Session (signed, readable by client)

```ts
import { useJWSSession, generateJWK } from "unjwt/adapters/h3v2";

const keys = await generateJWK("RS256"); // persist these!

app.get("/preferences", async (event) => {
  const session = await useJWSSession(event, {
    key: keys,
    maxAge: "24h",
  });

  return { theme: session.data.theme };
});
```

#### Session features

- **Cookie chunking** — large tokens are automatically split across multiple cookies
- **Header-based tokens** — read from `Authorization: Bearer <token>` or custom headers via `sessionHeader`
- **Lifecycle hooks** — `onRead`, `onUpdate`, `onClear`, `onExpire`, `onError` for logging, refresh logic, etc.
- **Key lookup hooks** — `onUnsealKeyLookup` (JWE) / `onVerifyKeyLookup` (JWS) for key rotation
- **TypeScript generics** — strongly-typed session data via `useJWESession<MyData>(event, config)`

#### Refresh token pattern

```ts
import {
  type SessionConfigJWE,
  type SessionConfigJWS,
  useJWESession,
  useJWSSession,
  getJWESession,
  updateJWSSession,
  generateJWK,
} from "unjwt/adapters/h3v2";

const atKeys = await generateJWK("RS256");

const refreshConfig = {
  key: process.env.REFRESH_SECRET!,
  name: "refresh_token",
} satisfies SessionConfigJWE;

const accessConfig = {
  key: atKeys,
  name: "access_token",
  maxAge: "15m",
  hooks: {
    async onExpire({ event, config }) {
      const refresh = await getJWESession(event, refreshConfig);
      if (refresh.data.sub) {
        await updateJWSSession(event, config, {
          sub: refresh.data.sub,
          scope: refresh.data.scope,
        });
      }
    },
  },
} satisfies SessionConfigJWS;
```

## Development

<details>

<summary>local development</summary>

- Clone this repository
- Install latest LTS version of [Node.js](https://nodejs.org/en/)
- Enable [Corepack](https://github.com/nodejs/corepack) using `corepack enable`
- Install dependencies using `pnpm install`
- Run tests using `pnpm test`

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
