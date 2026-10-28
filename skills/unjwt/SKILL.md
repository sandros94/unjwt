---
name: unjwt
description: "Working with unjwt, a zero-dependency JWT library on the Web Crypto API: signing and verifying (JWS), encrypting and decrypting (JWE), key generation, import, export, wrapping and JWK Sets (JWK), cookie or header sessions over a Web Request, and DPoP proofs. Use whenever code imports from `unjwt` or `unjwt/*`, or the user asks how to issue, check, encrypt or store a JWT, rotate keys, or keep a session without a database in Node, Bun, Deno, Workers or a browser."
metadata:
  version: 0.9.0
  library: unjwt
  org: sandros94
  documentation: https://unjwt.s94.dev
  repository: https://github.com/sandros94/unjwt
---

# unjwt

The documentation site is the single source of truth, and every page is also served as Markdown. Read the page for the task before writing code; do not rely on memory of the API.

- Index of every page: https://unjwt.s94.dev/llms.txt
- One page as Markdown: `https://unjwt.s94.dev/raw/<path>.md`, e.g. https://unjwt.s94.dev/raw/jws/verify.md
- Start with https://unjwt.s94.dev/raw/getting-started/concepts.md when the user is new to tokens, keys, JWK Sets or claims.

## Which page

| Task | Page |
| --- | --- |
| Sign a token, set its expiry and header | `/raw/jws/sign.md` |
| Verify a token against a key, a JWK Set or a lookup, check its claims | `/raw/jws/verify.md`, `/raw/safety/claims.md` |
| Several signatures on one payload | `/raw/jws/multi.md` |
| Pick a signing algorithm | `/raw/jws/algorithms.md` |
| Encrypt or decrypt a payload (keys, passwords, key agreement) | `/raw/jwe/encrypt.md`, `/raw/jwe/decrypt.md` |
| Encrypt for several recipients | `/raw/jwe/multi.md` |
| Pick encryption algorithms | `/raw/jwe/algorithms.md` |
| Generate, name and store keys | `/raw/jwk/generate.md` |
| Import or export keys, CryptoKey and JWK, thumbprints, public halves | `/raw/jwk/import-export.md` |
| PEM key files | `/raw/jwk/pem.md` |
| Wrap keys, agree on a shared secret | `/raw/jwk/wrap.md` |
| Keys from a password (PBES2) | `/raw/jwk/password.md` |
| JWK Sets, `kid`, rotation, lookups | `/raw/jwk/sets.md` |
| Sessions: what they are, which framework | `/raw/sessions.md` |
| Configure a session (key, lifetime, cookie, header) | `/raw/sessions/configure.md` |
| Read, update, clear, issue and open sessions | `/raw/sessions/use.md` |
| Session hooks, revocation, key rotation | `/raw/sessions/hooks.md` |
| Sessions without cookies: the session header, CLI and service-account clients, tokens in links | `/raw/sessions/api-clients.md` |
| A session driver for another framework | `/raw/sessions/drivers.md`, recipe `/raw/examples/custom-driver.md` |
| Sessions on h3, Nitro, Nuxt, Hono or Workers | `/raw/examples/h3.md`, `/raw/examples/nitro.md`, `/raw/examples/nuxt.md`, `/raw/examples/hono.md` |
| Use the library from a CDN in a browser | `/raw/examples/cdn-import.md` |
| DPoP proofs (create, verify, nonce, replay) | `/raw/dpop.md` |
| Errors and their codes | `/raw/safety/errors.md` |
| Limits on signatures, recipients, key trials, PBES2 work | `/raw/safety/limits.md` |
| base64url, random bytes, type guards | `/raw/safety/utils.md` |
| Install, subpaths, types, migration | `/raw/getting-started/installation.md`, `/raw/getting-started/migration/to-0.9.md` |

## Rules that hold everywhere

- Import from the subpath (`unjwt/jws`, `unjwt/jwe`, `unjwt/jwk`, `unjwt/utils`, `unjwt/error`, `unjwt/session`, `unjwt/dpop`); the root `unjwt` re-exports the core modules for bundlers.
- Keys are JWKs first: `generateJWK(alg)` returns an `oct` JWK or a `{ privateKey, publicKey }` pair with `alg` and a thumbprint `kid`; `sign`/`encrypt` read the algorithm from the key, `verify`/`decrypt` accept only that algorithm unless `algorithms` pins a list.
- Every failure throws a `JWTError` with a `code` (`ERR_JWT_EXPIRED`, `ERR_JWS_SIGNATURE_INVALID`, `ERR_JWK_KEY_NOT_FOUND`, …); nothing returns `false`. Branch on `code`, never on the message. The base64url codecs throw `UnsecureError` instead.
- Claims are validated by default; an option that cannot be honoured (`audience` with a non-JSON payload, time options on a string payload) is `ERR_INVALID_OPTION`.
- Limits fail closed: signatures and recipients per token, key candidates from a set, key trials per multi call, PBES2 iterations.
- Sessions: `defineJWSSession`/`defineJWESession` throw at definition for a config they cannot use; `use({ req, res })`, `use({ headers })`, `use({ token })`; `id` is `undefined` until `update()`; a JWE session key is symmetric; a key without `alg` (any `CryptoKey`) needs the pin (`jws.signOptions.alg`, `jwe.encryptOptions.alg` + `enc`), and a session reads what its keys serve plus `verifyOptions`/`decryptOptions.algorithms`; rotation is a JWK Set `key`, newest first (the first entry issues, every entry opens, each checked at definition like a lone key; a `kid` on every entry), `onKeyLookup` only for keys fetched per request (it replaces `key` for reading, so it returns the issuing key too); default cookie names start with `__Host-`; `sessionHeader` is opt-in, a header holding the cookie's token is a cookie session, and a header or `{ token }` session (`session.source`) writes nothing and never rolls.
- The library holds no state and does no HTTP: JWK Set fetching, nonce issuance, replay storage and revocation lists are the application's.
