# unjwt

[![npm version](https://npmx.dev/api/registry/badge/version/unjwt?name=true)](https://npmx.dev/package/unjwt)
[![npm downloads](https://npmx.dev/api/registry/badge/downloads/unjwt)](https://npmx.dev/package/unjwt)
[![bundle size](https://npmx.dev/api/registry/badge/size/unjwt)](https://npmx.dev/package/unjwt)

Low-level JWT toolkit built on the Web Crypto API. Sign, verify, encrypt, decrypt, and manage keys — JWS, JWE, and JWK in a single zero-dependency package.

> **📖 Documentation — [unjwt.s94.dev](https://unjwt.s94.dev)**

## Features

- **JWS** ([RFC 7515](https://datatracker.ietf.org/doc/html/rfc7515)) — HMAC, RSA, RSA-PSS, ECDSA, EdDSA. Compact + General/Flattened JSON Serialization (multi-signature).
- **JWE** ([RFC 7516](https://datatracker.ietf.org/doc/html/rfc7516)) — `dir`, AES-KW, AES-GCM-KW, RSA-OAEP, PBES2, ECDH-ES. AES-GCM and AES-CBC-HMAC-SHA2 content encryption. Compact + General/Flattened JSON Serialization (multi-recipient).
- **JWK** ([RFC 7517](https://datatracker.ietf.org/doc/html/rfc7517)) — generate, import, export, wrap, unwrap. `CryptoKey` ↔ JWK ↔ PEM conversion. ECDH-ES shared-secret derivation. JWKS fetching, lookup, and rotation.
- **Framework adapters** — cookie-based JWT sessions for [H3 v1](https://unjwt.s94.dev/adapters) (Nuxt v4 / Nitro v2) and [H3 v2](https://unjwt.s94.dev/adapters) (Nuxt v5 / Nitro v3).
- **Runtime-agnostic** — Node 22+, Deno, Bun, Cloudflare Workers, browsers. Anywhere Web Crypto runs.
- **Zero runtime dependencies** for core; optional peer deps for adapters (`h3`, `cookie-es`, `rou3`).

## Install

```sh
# Auto-detect package manager (npm, yarn, pnpm, deno, bun)
npx nypm install unjwt
```

Agent skill for Claude Code (and compatible harnesses):

```sh
npx skills add sandros94/unjwt
```

## Quickstart

```ts
// Sign and verify a JWT (JWS)
import { sign, verify } from "unjwt/jws";
import { generateJWK } from "unjwt/jwk";

const key = await generateJWK("HS256");
const token = await sign({ sub: "user_1" }, key, { expiresIn: "1h" });
const { payload } = await verify(token, key);
// { sub: "user_1", iat: ..., exp: ... }

// Encrypt and decrypt (JWE)
import { encrypt, decrypt } from "unjwt/jwe";

const jwe = await encrypt({ secret: "data" }, "my-password");
const { payload: p } = await decrypt(jwe, "my-password");
```

Full walkthroughs, recipes, and the complete API reference live at **[unjwt.s94.dev](https://unjwt.s94.dev)**:

- [Getting started →](https://unjwt.s94.dev/getting-started)
- [JWS — signing and verifying →](https://unjwt.s94.dev/jwt/jws)
- [JWE — encrypting and decrypting →](https://unjwt.s94.dev/jwt/jwe)
- [JWK — key management →](https://unjwt.s94.dev/jwk)
- [H3 session adapters →](https://unjwt.s94.dev/adapters)
- [Examples →](https://unjwt.s94.dev/examples) — authentication, JWKS endpoints, refresh tokens, end-to-end encryption, signed receipts.

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

Originally visioned by [Johann Schopplich](https://github.com/johannschopplich/unjwt), heavily inspired by [Filip Skokan's `jose`](https://github.com/panva/jose) internal cryptographic primitives, and initially sponsored by [JAMflow](https://jamflow.cloud) — thanks to all three for making this project possible.

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
