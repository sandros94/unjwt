<!-- NOTE: Keep this file updated as the project evolves. When making architectural changes, adding new patterns, or discovering important conventions, update the relevant sections. -->

# unjwt - Agent Guide

`unjwt` is a low-level JWT library using the Web Crypto API. It implements JWS (RFC 7515), JWE (RFC 7516), and JWK (RFC 7517) with framework adapters for H3 v1/v2 (Nuxt/Nitro). Zero runtime dependencies for core; optional peer deps for adapters (`h3`, `cookie-es`, `rou3`).

## Core Principle — Ask First

**When in doubt, ask before acting.** It is always more important to understand the vision and the request than to assume. There is no shame or wasted time in asking clarifying questions — this applies to every conversation and every task in this project.

### Q&A Sessions

When a task involves design decisions, ambiguity, or changes to the project vision, run a structured Q&A session before implementing. Format each question with **2–4 concrete options** the user can pick from, mix, or override with a custom answer. This keeps sessions concise and efficient:

- **Number questions** (Q1, Q2, …) so answers can reference them quickly.
- **Each option** should be a short, self-contained description (1–2 sentences) with a label (A, B, C, D).
- **Avoid open-ended questions** — always propose options. If genuinely unsure, provide your best guesses as options.
- **Group related questions** in a single message rather than asking one at a time.
- After answers, **synthesize** the decisions into a summary and confirm before implementing.
- If the answers reveal further ambiguity, do another focused round — don't assume.

## Commands

- **Build:** `pnpm build` (uses obuild/rolldown)
- **Test:** `pnpm test` (vitest)
- **Single test file:** `pnpm vitest run test/jws.test.ts`
- **Type check:** `pnpm typecheck` (uses tsgo)
- **Lint:** `pnpm lint` (oxlint + oxfmt --check)
- **Format:** `pnpm fmt` (automd + oxlint --fix + oxfmt)
- **Benchmarks:** `pnpm bench`
- **Dev playground:** `pnpm dev` (runs `playground/main.ts` with bun)

## Architecture

### Module structure (each is a separate export path)

- `unjwt` — barrel re-export of `jws`, `jwe`, `jwk`, `utils` namespaces
- `unjwt/jws` — `sign()`, `verify()` (Compact) plus `signMulti()`/`verifyMulti()`/`verifyMultiAll()` (General/Flattened)
- `unjwt/jwe` — `encrypt()`, `decrypt()` (Compact) plus `encryptMulti()`/`decryptMulti()` (General/Flattened)
- `unjwt/jwk` — key generation, import/export (CryptoKey, JWK, PEM), wrap/unwrap, PBES2 derivation
- `unjwt/utils` — base64url encode/decode, type guards (`isJWK`, `isJWKSet`, `isPrivateJWK`, etc.), `secureRandomBytes`
- `unjwt/adapters/h3v1` and `unjwt/adapters/h3v2` — `useJWSSession()`, `useJWESession()` for cookie-based JWT sessions

### Source layout

```
src/
  index.ts              # barrel: re-exports core modules as namespaces
  core/
    jws.ts              # sign/verify (compact); re-exports the multi-recipient API
    jwe.ts              # encrypt/decrypt (compact); re-exports the multi-recipient API
    jws-multi.ts        # signMulti/verifyMulti/verifyMultiAll (General/Flattened JWS)
    jwe-multi.ts        # encryptMulti/decryptMulti (General/Flattened JWE)
    jwk.ts              # key management (generateKey, importKey, exportKey, wrapKey, unwrapKey, PEM conversion)
    _internal.ts        # shared signing-key resolver + JWKSet candidate filter for jws/jwe
    error.ts            # JWTError class + error codes (ERR_JWT_EXPIRED, …)
    types/              # TypeScript types for JWK, JWS, JWE, JWT
    utils/              # encoding, type guards, JWT claim validation, sanitization
    _crypto/            # low-level crypto primitives — independently-maintained fork of panva/jose
                        # (_sign-verify, _aes, _ecdh, _pbes2, _rsa, _key-codec, _key-encryption, _pem)
  adapters/
    h3v1/               # H3 v1 session adapter (useJWSSession, useJWESession)
    h3v2/               # H3 v2 session adapter (same API, different h3 import)
```

### Key design patterns

- **Dual-version peer deps:** H3 v1 and v2 are installed as `h3v1`/`h3v2` aliases in devDependencies. Cookie-es similarly as `cookie-esv1`/`cookie-esv3`. The build config (`build.config.ts`) replaces these aliases with the real package names (`h3`, `cookie-es`) in dist output.
- **`src/core/_crypto/`** is an internal, independently-maintained fork of [`panva/jose`](https://github.com/panva/jose) primitives — excluded from test coverage. Do not add tests for files in this directory.
- **Bundled `unsecure` dependency:** core imports primitives from [`unsecure`](https://github.com/sandros94/unsecure) (`base64UrlEncode`/`base64UrlDecode`, `secureRandomBytes`, `sanitizeObjectCopy`/`safeJsonParse`). It is a devDependency inlined into dist at build time (not marked external in `build.config.ts`), so the published package keeps zero runtime dependencies.
- **Algorithm inference:** When `alg`/`enc` aren't provided, `sign`/`encrypt` try to infer them from JWK properties. Password strings default to PBES2 in JWE.
- **JWK-first key model:** Functions accept JWK objects directly; `importKey()` normalizes CryptoKey/JWK/Uint8Array/string inputs.
- **Session adapters** store JWT tokens in chunked cookies (via h3's `getChunkedCookie`/`setChunkedCookie`). Sessions are lazy — `id` is `undefined` until `session.update()` is called.

## Testing conventions

- **No dynamic imports in tests.** Do not use `await import(...)` inside `it()`/`describe()` blocks. All module imports must be static top-level `import` statements. Dynamic imports defeat tree-shaking, make the module graph opaque to the type checker (inferred `any` types instead of the real ones), hide missing-import errors until runtime, and slow down vitest's transform phase. The only legitimate reasons to use a dynamic import in a test are (a) testing actual code-splitting / lazy-loading behaviour or (b) resetting module state between tests with `vi.resetModules()` — neither applies here. If an identifier is needed in a newly written test and it is not yet in the static imports, add it there instead.
- **No tests for `src/core/_crypto/`** — that directory is an internal fork of panva/jose and is excluded from coverage (at the time of writing).

## Planning & design docs

- **`.agents/vision/`** — working space for drafting **new** features before implementation. Empty when no design is in flight; it is not a historical archive — completed designs live in the code and git history.
- **`.agents/TODO.md`** — deferred backlog (e.g. deprecated-alias removals slated for a future major version).

## Code Conventions

- Use **ESM** and modern JavaScript, with a type-first approach.
- Before adding new code, study surrounding patterns, naming conventions, and architectural decisions.
- Keep runtime code minimal and fast.
- Prefer **Web APIs** over Node.js APIs where possible.
- Place non-exported/internal helpers at the end of the file.
- Do not add comments explaining what the line does unless prompted.
- Split logic across files; avoid long single-file modules (>200 LoC). Use `_*` prefix for internal files.
- For multi-arg functions, use an options object as the second parameter.
- Avoid barrel files (`index.ts` re-exports); import directly from specific modules.
- **`skills/unjwt/`** contains reference docs for the public API — keep these files updated when making architectural changes or modifying public-facing signatures/types
