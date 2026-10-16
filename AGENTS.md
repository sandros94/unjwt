<!-- NOTE: Keep this file updated as the project evolves. When making architectural changes, adding new patterns, or discovering important conventions, update the relevant sections. -->

# unjwt - Agent Guide

`unjwt` is a low-level JWT library using the Web Crypto API. It implements JWS (RFC 7515), JWE (RFC 7516), and JWK (RFC 7517) with framework adapters for H3 v1/v2 (Nuxt/Nitro) and Elysia, and Web standard sessions any framework can drive. Zero runtime dependencies for core; optional peer deps for adapters (`h3`, `elysia`).

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
- **Type check:** `pnpm typecheck` (uses `tsc` from TypeScript 7)
- **Lint:** `pnpm lint` (oxlint + oxfmt --check)
- **Format:** `pnpm fmt` (automd + oxlint --fix + oxfmt)
- **Benchmarks:** `pnpm bench`
- **Dev playground:** `pnpm dev` (runs `playground/main.ts` with bun)

## Architecture

### Module structure (each is a separate export path)

- `unjwt` — flat named exports of everything in `jws`, `jwe`, `jwk` and `utils` (no namespace objects)
- `unjwt/jws` — `sign()`, `verify()` (Compact) plus `signMulti()`/`verifyMulti()`/`verifyMultiAll()` (General/Flattened)
- `unjwt/jwe` — `encrypt()`, `decrypt()` (Compact) plus `encryptMulti()`/`decryptMulti()` (General/Flattened)
- `unjwt/jwk` — key generation, import/export (CryptoKey, JWK, PEM), wrap/unwrap, PBES2 derivation
- `unjwt/utils` — base64url encode/decode, type guards (`isJWK`, `isJWKSet`, `isPrivateJWK`, etc.), `secureRandomBytes`
- `unjwt/internal` — JOSE plumbing (`parsePayloadBytes`, `computeJwtTimeClaims`, `crit` checks, …) for tests and tooling; no semver guarantee, not re-exported from `unjwt`
- `unjwt/adapters/h3v1` and `unjwt/adapters/h3v2` — `defineJWSSession()`, `defineJWESession()` session definitions (`use`/`token`/`issue`/`open`) for cookie-based JWT sessions
- `unjwt/adapters/elysia` — `jwsSession()`/`jweSession()` Elysia plugins (ambient `ctx.session`, `requireSession` guard macro) over `defineJWSSession()`/`defineJWESession()` (the definition plus `plugin()`)
- `unjwt/session` (`src/adapters/web/`) — `defineJWSSession()`/`defineJWESession()` over a Web `Request` + response `Headers` or a token in hand, plus `defineSessionDriver()` and the `SessionDriver`/`CookieJar` types for a framework of your own (`{ driver }` option); no peer dependency

### Source layout

```
src/
  index.ts              # root entry: flat named re-exports of the core modules
  core/
    jws.ts              # sign/verify (compact); re-exports the multi-recipient API
    jwe.ts              # encrypt/decrypt (compact); re-exports the multi-recipient API
    jws-multi.ts        # signMulti/verifyMulti/verifyMultiAll (General/Flattened JWS)
    jwe-multi.ts        # encryptMulti/decryptMulti (General/Flattened JWE)
    jwk.ts              # key management (generateKey, importKey, exportKey, wrapKey, unwrapKey, PEM conversion)
    _internal.ts        # shared signing-key resolver + JWKSet candidate filter for jws/jwe
    _jwt-internal.ts    # JOSE plumbing: typ/cty defaults, payload parsing, time claims, crit checks
    internal.ts         # `unjwt/internal` entry point over _jwt-internal.ts
    error.ts            # JWTError class + error codes (ERR_JWT_EXPIRED, …)
    types/              # TypeScript types for JWK, JWS, JWE, JWT
    utils/              # encoding, type guards, JWT claim validation, sanitization
    _crypto/            # low-level crypto primitives — originally derived from panva/jose, now maintained in-tree
                        # (_sign-verify, _aes, _ecdh, _pbes2, _rsa, _key-codec, _key-encryption, _pem)
  adapters/
    _session.ts         # framework-agnostic session contract shared by every adapter
                        # (error factories, reserved-claim stripping, name/cookie/rolling checks, typ/exp helpers)
    _session-core.ts    # session state and the codec/store/binding contracts every session runs on
    _session-bind.ts    # bindSession: config checks, per-request name registry, store and transport of one session
    _session-read.ts    # load: token read, open, expiry, onRead/onExpire/onError, rolling
    _session-write.ts   # issue/drop/encode with rollback, onUpdate/onClear, the manager's lazy getters
    _session-definition.ts # SessionDefinition + defineSession: one config bound to a driver and a codec (use/token/issue/open)
    _driver.ts          # SessionDriver/CookieJar: the primitives a framework supplies (state, header, cookies, writable)
    _transport.ts       # core-owned cookie + header transports over a driver; sessionHeader rules
    _session-types.ts   # session types every adapter exposes (SessionClaims/Data/Update/Manager/Hooks)
    _session-codec.ts   # codec skeleton shared by both families: key checks, issue/open options, claims ↔ session
    _codec-jws.ts       # JWS half of a session: sign/verify, key resolution, JWS config + cookie defaults
    _codec-jwe.ts       # JWE half of a session: encrypt/decrypt, key resolution, JWE config + cookie defaults
    _chunked-cookie.ts  # framework-agnostic `__chunked__N` cookie layer (marker, 1-indexed parts, MAX_CHUNK_COUNT)
    _cookie-attributes.ts # CookieAttributes: the Set-Cookie attribute shape shared by the Elysia and Web entries
    h3v1/               # H3 v1 session adapter (defineJWSSession, defineJWESession)
      _cookie.ts        # cookie option type + the Node response's Set-Cookie list
      session/_shared.ts# driver: CompatEvent, context state, request headers/cookies, cookie jar
    h3v2/               # H3 v2 session adapter (same API, different h3 import)
      session/_shared.ts# driver: context state, request headers/cookies, cookie jar with res.errHeaders staging
    elysia/             # Elysia session adapter
      _cookie.ts        # chunked-cookie layer over Elysia's reactive cookie jar
      _plugin.ts        # SessionPlugin<> explicit return type, SessionPluginDefinition, guardName() helper
      session/          # defineJWSSession/defineJWESession, jwsSession/jweSession plugins, shared types
      session/_shared.ts# driver: per-request state keyed by the Request, request headers, reactive cookie jar
    web/                # `unjwt/session`: Web standard sessions and the public driver API
      _cookie.ts        # Web cookie jar: cookie-es parse of the Cookie header, Set-Cookie replace on Headers
      _define-driver.ts # defineSessionDriver(): the typed identity for a third-party driver
      session/          # defineJWSSession/defineJWESession (optional `{ driver }`), SessionContext
      session/_shared.ts# driver: WeakMap state keyed by the Request (or the token context), handed token
```

### Key design patterns

- **Dual-version peer deps:** H3 v1 and v2 are installed as `h3v1`/`h3v2` aliases in devDependencies. The build config (`build.config.ts`) replaces these aliases with the real package name (`h3`) in dist output. `elysia` has no dual-version aliasing (single major) — it's a plain optional peer dep, marked `external` in the build.
- **Single multi-input bundle:** all entry points (core subpaths + every adapter) are `input`s of one `type: "bundle"` in `build.config.ts`, so rolldown code-splits shared core into `dist/_chunks/*` (no per-adapter duplication). Adding an adapter = add its `index` input + any peer dep to `external`; `unjwt/session` (`./src/adapters/web/index`) has no peer dep, so nothing of its own is external. `unsecure` and `cookie-es` stay bundled (inlined → zero runtime deps).
- **`src/core/_crypto/`** originated as a fork of [`panva/jose`](https://github.com/panva/jose) primitives but is now maintained as part of this codebase — modify and fix it like any other module (bug fixes, lint, type-safety). It is excluded from test coverage; adding tests there is optional, not required.
- **Bundled `unsecure` dependency:** core imports primitives from [`unsecure`](https://github.com/sandros94/unsecure) (`base64UrlEncode`/`base64UrlDecode`, `secureRandomBytes`, `sanitizeObjectCopy`/`safeJsonParse`). It is a devDependency inlined into dist at build time (not marked external in `build.config.ts`), so the published package keeps zero runtime dependencies.
- **Bundled `cookie-es` dependency:** the H3 v1 adapter and `unjwt/session` parse request cookies with [`cookie-es`](https://github.com/unjs/cookie-es) v3 (`unjwt/session` also serializes and parses `Set-Cookie` with it), a devDependency inlined into dist the same way as `unsecure`. Its licence ships in obuild's `dist/THIRD-PARTY-LICENSES.md.gz`. The h3 adapters derive their cookie attribute type from their `h3` version's `setCookie`, and Elysia and `unjwt/session` share `CookieAttributes`, so no `cookie-es` type reaches the published declarations.
- **Algorithm inference:** When `alg`/`enc` aren't provided, `sign`/`encrypt` try to infer them from JWK properties. Password strings default to PBES2 in JWE.
- **JWK-first key model:** Functions accept JWK objects directly; `importKey()` normalizes CryptoKey/JWK/Uint8Array/string inputs.
- **Session adapters** store JWT tokens in chunked cookies — every adapter through the core's cookie transport (`src/adapters/_transport.ts` over `_chunked-cookie.ts`), which writes through the cookie jar each framework's driver supplies, all writing the same `__chunked__N` + `<name>.1…N` layout. Sessions are lazy — `id` is `undefined` until `session.update()` is called. `jti`/`iat`/`exp`/`nbf` are adapter-owned; the cookie is read before the session header; every adapter error is a `JWTError` (`ERR_SESSION_*`).
- **One session core, two codecs, four drivers:** the session core (`_session-core.ts`, `_session-bind.ts`, `_session-read.ts`, `_session-write.ts`) owns the whole session lifecycle (token read, expiry, hook dispatch, update with rollback, clear, the manager's lazy getters) and the transports (`_transport.ts`: the chunked cookie and the session header, the writable-response check). It works through two contracts: a _codec_ (`_codec-jws.ts` / `_codec-jwe.ts`, each a spec over `_session-codec.ts`) that issues and opens the token and carries the family's defaults, and a _driver_ (`_driver.ts`, implemented by each adapter's `session/_shared.ts`: h3 v1, h3 v2, Elysia, Web) that supplies the framework's primitives for one request _context_ — its state record, a request header, its cookie jar, and whether the response can still change. The hook argument name is not the driver's: each entry passes `hookArgs` to `defineSession`/`bindSession` (`{ event }` on h3, `{ context }` on Elysia and `unjwt/session`, whatever driver `unjwt/session` is given), so the hook types hold by construction. The same contract is public through `unjwt/session` (`SessionDriver`, `CookieJar`, `defineSessionDriver`), so a third-party driver binds to the codecs with `defineJWSSession(config, { driver })`. `_session-definition.ts` binds one config to a driver and a codec as a `SessionDefinition`; `src/adapters/<fw>/session/{jws,jwe}.ts` is then the public surface alone: the `define*Session` factories, the config/hook types, and the binding of driver to codec. New session logic belongs in the core, new token rules in a codec, how a token travels in the transport, and anything that touches a framework in its driver.
- **Handed token:** a driver's optional `handed(context)` returns `{ token }` when the context carries the token itself (`unjwt/session`'s `{ token }` shape). `resolveTransport` then returns a transport that reads that token, is always writable and has no `write`/`drop`: the full read lifecycle runs (hooks, expiry, `rolling`), `update()` re-mints onto `manager.token` and `clear()` empties the session, whatever `cookie`/`sessionHeader` the config sets. The h3 and Elysia drivers do not implement it.

## Testing conventions

- **No dynamic imports in tests.** Do not use `await import(...)` inside `it()`/`describe()` blocks. All module imports must be static top-level `import` statements. Dynamic imports defeat tree-shaking, make the module graph opaque to the type checker (inferred `any` types instead of the real ones), hide missing-import errors until runtime, and slow down vitest's transform phase. The only legitimate reasons to use a dynamic import in a test are (a) testing actual code-splitting / lazy-loading behaviour or (b) resetting module state between tests with `vi.resetModules()` — neither applies here. If an identifier is needed in a newly written test and it is not yet in the static imports, add it there instead.
- **`src/core/_crypto/` is excluded from coverage** — originally derived from panva/jose and kept out of the coverage report; tests there are optional, not required.

## Planning & design docs

- **`.agents/vision/`** — working space for drafting **new** features before implementation. Empty when no design is in flight; it is not a historical archive — completed designs live in the code and git history.
- **`.agents/TODO.md`** — deprecation ledger: every `@deprecated` symbol with its replacement, the release that deprecated it and the release that removes it.

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
