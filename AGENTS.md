<!-- NOTE: Keep this file updated as the project evolves. When making architectural changes, adding new patterns, or discovering important conventions, update the relevant sections. -->

# unjwt - Agent Guide

`unjwt` is a low-level JWT library using the Web Crypto API. It implements JWS (RFC 7515), JWE (RFC 7516), and JWK (RFC 7517) with framework adapters for H3 v1/v2 (Nuxt/Nitro). Zero runtime dependencies for core; optional peer deps for adapters (`h3`, `cookie-es`, `rou3`).

## Commands

- **Build:** `pnpm build` (uses obuild/rolldown)
- **Test:** `pnpm test` (vitest)
- **Single test file:** `pnpm vitest run test/jws.test.ts`
- **Type check:** `pnpm typecheck` (uses tsgo)
- **Lint:** `pnpm lint` (oxlint + oxfmt --check)
- **Format:** `pnpm format` (automd + oxlint --fix + oxfmt)
- **Benchmarks:** `pnpm bench`
- **Dev playground:** `pnpm dev` (runs `playground/main.ts` with bun)

## Architecture

### Module structure (each is a separate export path)

- `unjwt` — barrel re-export of `jws`, `jwe`, `jwk`, `utils` namespaces
- `unjwt/jws` — `sign()`, `verify()` (JWS Compact Serialization)
- `unjwt/jwe` — `encrypt()`, `decrypt()` (JWE Compact Serialization)
- `unjwt/jwk` — key generation, import/export (CryptoKey, JWK, PEM), wrap/unwrap, PBES2 derivation
- `unjwt/utils` — base64url encode/decode, type guards (`isJWK`, `isJWKSet`, `isPrivateJWK`, etc.), randomBytes
- `unjwt/adapters/h3v1` and `unjwt/adapters/h3v2` — `useJWSSession()`, `useJWESession()` for cookie-based JWT sessions

### Source layout

```
src/
  index.ts              # barrel: re-exports core modules as namespaces
  core/
    jws.ts              # sign/verify implementation
    jwe.ts              # encrypt/decrypt implementation
    jwk.ts              # key management (generateKey, importKey, exportKey, wrapKey, unwrapKey, PEM conversion)
    types/              # TypeScript types for JWK, JWS, JWE, JWT
    utils/              # encoding, type guards, JWT claim validation, sanitization
    jose/               # low-level crypto primitives forked from panva/jose (sign-verify, encrypt-decrypt, key conversion, ECDH, PBES2, RSA, AES-GCM KW, ASN.1)
  adapters/
    h3v1/               # H3 v1 session adapter (useJWSSession, useJWESession)
    h3v2/               # H3 v2 session adapter (same API, different h3 import)
```

### Key design patterns

- **Dual-version peer deps:** H3 v1 and v2 are installed as `h3v1`/`h3v2` aliases in devDependencies. Cookie-es similarly as `cookie-esv1`/`cookie-esv2`. The build config (`build.config.ts`) replaces these aliases with the real package names (`h3`, `cookie-es`) in dist output.
- **`src/core/jose/`** is an internal fork of [`panva/jose`](https://github.com/panva/jose) primitives — excluded from test coverage. Do not add tests for files in this directory.
- **Algorithm inference:** When `alg`/`enc` aren't provided, `sign`/`encrypt` try to infer them from JWK properties. Password strings default to PBES2 in JWE.
- **JWK-first key model:** Functions accept JWK objects directly; `importKey()` normalizes CryptoKey/JWK/Uint8Array/string inputs.
- **Session adapters** store JWT tokens in chunked cookies (via h3's `getChunkedCookie`/`setChunkedCookie`). Sessions are lazy — `id` is `undefined` until `session.update()` is called.

## Conventions

- **ESM-only**, `"type": "module"` in package.json
- **Node 22** required (uses `Uint8Array.prototype.toBase64`/`fromBase64` when available)
- **pnpm** as package manager (v10)
- **Strict TypeScript** with `verbatimModuleSyntax`, `noUncheckedIndexedAccess`, `noImplicitAny`; type-checked via `tsgo` (native TypeScript compiler)
- Linting via **oxlint** (OXC); formatting via **oxfmt** (OXC)
- Type-only exports use `export type *` pattern
- `sanitizeObject()` is applied to parsed headers/JWK data to strip prototype pollution vectors
