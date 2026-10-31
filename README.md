# unjwt

[![npm version](https://npmx.dev/api/registry/badge/version/unjwt?name=true)](https://npmx.dev/package/unjwt) [![npm downloads](https://npmx.dev/api/registry/badge/downloads/unjwt)](https://npmx.dev/package/unjwt) [![bundle size](https://npmx.dev/api/registry/badge/size/unjwt)](https://npmx.dev/package/unjwt)

A collection of JWT utilities based on the Web Crypto API, in a single zero-dependency package.

> **📖 Documentation — [unjwt.s94.dev](https://unjwt.s94.dev)**

## Features

- **JWS** ([RFC 7515](https://www.rfc-editor.org/rfc/rfc7515)): HMAC, RSA, RSA-PSS, ECDSA, EdDSA. Compact and General/Flattened JSON serialization (several signatures over one payload).
- **JWE** ([RFC 7516](https://www.rfc-editor.org/rfc/rfc7516)): `dir`, AES-KW, AES-GCM-KW, RSA-OAEP, PBES2, ECDH-ES, with AES-GCM and AES-CBC-HMAC-SHA2 content encryption. Compact and General/Flattened JSON serialization (several recipients for one ciphertext).
- **JWK** ([RFC 7517](https://www.rfc-editor.org/rfc/rfc7517)): generate, import, export, wrap and unwrap keys; `CryptoKey`, JWK and PEM conversion; thumbprints as key IDs; JWK Set lookup and rotation.
- **DPoP** ([RFC 9449](https://www.rfc-editor.org/rfc/rfc9449)): create and verify proofs with [`unjwt/dpop`](https://unjwt.s94.dev/dpop). Your application owns HTTP and replay storage.
- **Sessions**: signed or encrypted cookie sessions with [`unjwt/session`](https://unjwt.s94.dev/sessions) over a Web `Request`, on [h3](https://unjwt.s94.dev/examples/h3), [Nitro](https://unjwt.s94.dev/examples/nitro), [Nuxt](https://unjwt.s94.dev/examples/nuxt), [Hono and Workers](https://unjwt.s94.dev/examples/hono), Bun and Deno, or on a token in hand; a [driver](https://unjwt.s94.dev/sessions/drivers) for any other framework.
- **One typed error**: every failure is a `JWTError` with a `code` to branch on.
- **Runtime-agnostic**: Node.js 22+, Bun, Deno, Cloudflare Workers and browsers, anywhere Web Crypto runs.
- **Zero runtime dependencies**, no peer dependencies.

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
// Sign with the private half, verify with the public one (JWS)
import { sign, verify } from "unjwt/jws";
import { generateJWK } from "unjwt/jwk";

const { privateKey, publicKey } = await generateJWK("ES256");
const token = await sign({ sub: "user_1a2b" }, privateKey, { expiresIn: "15m" });
const { payload } = await verify(token, publicKey);
// { sub: "user_1a2b", iat: …, exp: … }

// Encrypt for a recipient's public key, decrypt with its private key (JWE)
import { encrypt, decrypt } from "unjwt/jwe";

const recipient = await generateJWK("ECDH-ES+A256KW");
const jwe = await encrypt({ invoice: "inv_2026_0042" }, recipient.publicKey);
const opened = await decrypt(jwe, recipient.privateKey);

// Keep a session in a cookie on any Web Request
import { defineJWESession } from "unjwt/session";

const appSession = defineJWESession({ key: await generateJWK("A256GCM"), maxAge: "7D" });
const headers = new Headers();
const session = await appSession.use({ req: request, res: { headers } });
await session.update({ user: "user_1a2b" }); // Set-Cookie lands on `headers`
```

Walkthroughs, recipes and the full API live at **[unjwt.s94.dev](https://unjwt.s94.dev)**:

- [Getting started →](https://unjwt.s94.dev/getting-started)
- [Sign and verify (JWS) →](https://unjwt.s94.dev/jws)
- [Encrypt and decrypt (JWE) →](https://unjwt.s94.dev/jwe)
- [Keys (JWK) →](https://unjwt.s94.dev/jwk)
- [Sessions →](https://unjwt.s94.dev/sessions)
- [Safety: errors, claims and limits →](https://unjwt.s94.dev/safety)
- [DPoP proofs →](https://unjwt.s94.dev/dpop)
- [Recipes →](https://unjwt.s94.dev/examples): sessions on h3, Nitro, Nuxt, Hono and Workers, CDN imports, custom drivers.
- [Migration guides →](https://unjwt.s94.dev/getting-started/migration)

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

Published under the [MIT](https://github.com/sandros94/unjwt/blob/main/LICENSE) license. Made by [community](https://github.com/sandros94/unjwt/graphs/contributors) 💛 <br><br> <a href="https://github.com/sandros94/unjwt/graphs/contributors"> <img src="https://contrib.rocks/image?repo=sandros94/unjwt" /> </a>

<!-- /automd -->

<!-- automd:with-automd -->

---

_🤖 auto updated with [automd](https://automd.unjs.io)_

<!-- /automd -->
