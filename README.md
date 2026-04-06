# unjwt

[![npm version](https://npmx.dev/api/registry/badge/version/unjwt?name=true)](https://npmx.dev/package/unjwt)
[![npm downloads](https://npmx.dev/api/registry/badge/downloads/unjwt)](https://npmx.dev/package/unjwt)
[![bundle size](https://npmx.dev/api/registry/badge/size/unjwt)](https://npmx.dev/package/unjwt)

A collection of low-level JWT ([RFC 7519](https://datatracker.ietf.org/doc/html/rfc7519)) utilities using the Web Crypto API. Supports:

- **JWS** ([RFC 7515](https://datatracker.ietf.org/doc/html/rfc7515)) — sign and verify tokens using HMAC, RSA, RSA-PSS, ECDSA, and EdDSA algorithms
- **JWE** ([RFC 7516](https://datatracker.ietf.org/doc/html/rfc7516)) — encrypt and decrypt data using Direct (`dir`), AES Key Wrap, AES-GCM KW, RSA-OAEP, PBES2, and ECDH-ES key management with AES-GCM or AES-CBC+HMAC-SHA2 content encryption
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

**JWKSet for key rotation and JWKS endpoint consumption:**

When a `JWKSet` is passed (directly or returned from a lookup function), `verify` tries each matching key in order until one succeeds. If the token carries a `kid`, only keys with that exact `kid` are tried — no retry. If `kid` is absent, all keys in the set whose `alg` is compatible become candidates. This makes transparent key rotation possible without any retry logic in userland.

```ts
// Fetch all public keys from a JWKS endpoint — library picks the right one
const jwks = await fetch("https://auth.example.com/.well-known/jwks.json").then((r) => r.json());
const { payload } = await verify(token, jwks);

// Rotation window: old tokens (no kid) are tried against all keys automatically
const rotatingSet = { keys: [newKey, legacyKey] };
const { payload: p } = await verify(oldToken, rotatingSet);
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

### ECDH-ES — End-to-End Encrypted Messaging

In end-to-end encryption (E2EE), each participant holds a **key pair**: the **private key** never leaves the owner's system; the **public key** is distributed freely. A sender encrypts a message using the recipient's public key, producing a token that only the recipient — holding the matching private key — can decrypt.

#### One-time key setup

Each participant generates a key pair once and persists it. The public key is shared out-of-band — published to a server endpoint, written to a config file, exchanged at registration, etc.:

```ts
import { generateJWK } from "unjwt/jwk";

const myKeys = await generateJWK("ECDH-ES+A256KW", { kid: "alice-2025" });
// → { privateKey: JWK_EC_Private, publicKey: JWK_EC_Public }

// Keep myKeys.privateKey in secure storage — never expose it
// Share myKeys.publicKey freely (e.g., publish at /.well-known/jwks.json)
```

#### Sending to one recipient

For two-party communication, `encrypt` and `decrypt` handle everything. Pass the recipient's public key — a one-time ephemeral key pair is generated internally per message:

```ts
import { encrypt, decrypt } from "unjwt/jwe";

// Sender (Alice) ————————————————————————————————————
// Fetch Bob's public key (from his public endpoint, shared config, etc.)
const bobPublicKey = /* ... */;

const token = await encrypt({ message: "Hello Bob!" }, bobPublicKey);
// Send `token` to Bob over any channel — only Bob can decrypt it

// Recipient (Bob) ————————————————————————————————————
const { payload } = await decrypt(token, bobPrivateKey);
console.log(payload.message); // "Hello Bob!"
```

Each token carries a fresh ephemeral public key (`epk`) in its header. Bob uses that `epk` together with his private key to re-derive the same shared secret Alice used, then unwraps the Content Encryption Key. At no point does Alice have Bob's private key, and Bob cannot forge a message appearing to come from Alice.

#### Sending to multiple recipients

**Simple — one token per recipient.** Encrypt the payload independently for each party. Each token is decryptable only by its intended recipient:

```ts
const recipients = [
  { name: "bob", publicKey: bobPublicKey },
  { name: "charlie", publicKey: charliePublicKey },
];

const tokens = await Promise.all(
  recipients.map(({ publicKey }) => encrypt({ message: "Hello everyone!" }, publicKey)),
);
// Deliver tokens[0] to Bob, tokens[1] to Charlie
```

This is the right choice for most use cases. The only trade-off is proportional size: N recipients produce N tokens.

**Shared ciphertext — one payload, N wrapped keys.** When the payload is large or bandwidth matters, encrypt the payload once with a random Content Encryption Key (`dir`), then wrap that key separately per recipient. Everyone receives the same ciphertext, each with their own individually wrapped key:

```ts
import { wrapKey, unwrapKey } from "unjwt/jwk";
import { randomBytes } from "unjwt/utils";
import { encrypt, decrypt } from "unjwt/jwe";

const enc = "A256GCM";

// 1. Generate a random CEK once for this message (32 bytes = 256-bit for A256GCM)
const cek = randomBytes(32);

// 2. Encrypt the payload ONCE using the CEK directly (alg: "dir")
const ciphertext = await encrypt({ message: "Hello everyone!" }, cek, { alg: "dir", enc });

// 3. Wrap the CEK individually for each recipient
const wrappedKeys = await Promise.all(
  recipients.map(async ({ name, publicKey }) => {
    const { encryptedKey, epk } = await wrapKey("ECDH-ES+A256KW", cek, publicKey);
    return { name, encryptedKey, epk };
  }),
);
// Deliver `ciphertext` (same for all) + each recipient's own { encryptedKey, epk }

// Recipient side ——————————————————————————————————————————————
const mine = wrappedKeys.find((w) => w.name === myName)!;
const rawCek = await unwrapKey("ECDH-ES+A256KW", mine.encryptedKey, myPrivateKey, {
  format: "raw",
  epk: mine.epk,
  enc,
});
const { payload } = await decrypt(ciphertext, rawCek);
console.log(payload.message); // "Hello everyone!"
```

> This pattern is the manual foundation of [JWE JSON Serialization](https://www.rfc-editor.org/rfc/rfc7516#section-3.3) (RFC 7516 §3.3), which packages the ciphertext and all wrapped keys into a single `recipients[]` JSON structure. Full JWE JSON Serialization support is planned for a future release; `wrapKey` and `unwrapKey` provide the building blocks for those who need to construct or consume the JSON form today.

#### `deriveSharedSecret` — raw key material

`wrapKey` and `unwrapKey` already handle the full ECDH Concat KDF + AES-KW cycle internally. `deriveSharedSecret` exposes the KDF step alone, returning the raw derived bytes before any key-wrapping step:

```ts
import { deriveSharedSecret } from "unjwt/jwk";

// Both sides independently derive the exact same bytes
const aliceView = await deriveSharedSecret(
  bobPublicKey,
  aliceEphemeralPrivateKey,
  "ECDH-ES+A256KW",
);
const bobView = await deriveSharedSecret(aliceEphemeralPublicKey, bobPrivateKey, "ECDH-ES+A256KW");
// aliceView and bobView are identical Uint8Arrays
```

Use `deriveSharedSecret` when you need the shared secret itself rather than a wrapped key: custom hybrid protocols that use the derived bytes directly, non-standard wrapping schemes, or verifying the key agreement step in isolation.

### JWK — Key Management

> Full reference: [skills/unjwt/references/jwk.md](./skills/unjwt/references/jwk.md)

```ts
import {
  generateKey,
  generateJWK,
  importKey,
  exportKey,
  importFromPEM,
  exportToPEM,
  wrapKey,
  unwrapKey,
  deriveKeyFromPassword,
  getJWKsFromSet,
  deriveSharedSecret,
  configureJWKCache,
} from "unjwt/jwk";
// All of the above are also importable from "unjwt" directly.

// Generate keys as CryptoKey or JWK
const hmacKey = await generateKey("HS256"); // CryptoKey
const rsaPair = await generateKey("RS256"); // CryptoKeyPair
const ecJwk = await generateJWK("ES256", { kid: "k1" }); // { privateKey: JWK, publicKey: JWK }

// PEM conversion
const jwk = await importFromPEM(pemString, "spki", "RS256", { jwkParams: { kid: "rsa-1" } });
const pem = await exportToPEM(jwk, "spki");

// Key wrapping
const cek = crypto.getRandomValues(new Uint8Array(32));
const { encryptedKey } = await wrapKey("A256KW", cek, aesKey);
const unwrapped = await unwrapKey("A256KW", encryptedKey, aesKey, { format: "raw" });

// ECDH-ES shared secret (e.g. for multi-recipient JWE)
const secret = await deriveSharedSecret(
  recipientPublicKey,
  senderEphemeralPrivate,
  "ECDH-ES+A256KW",
);
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
