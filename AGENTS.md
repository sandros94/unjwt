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
- **Size:** `pnpm size` prints what each use case ships, minified and gzipped, against the sizes recorded in `test/bundle.test.ts` (3% slack); a deliberate change updates the row
- **Format:** `pnpm fmt` (automd + oxlint --fix + oxfmt)
- **Benchmarks:** `pnpm bench`
- **Example:** `pnpm dev` runs the h3 playground
- **Playgrounds:** `playgrounds/{h3,nuxt-4,nitro}/`, workspace packages on the root lockfile depending on `unjwt` as `workspace:*` (a link to the root, so `dist/` must exist: the `pnpm dev:prepare` stub runs from `src`, or `pnpm build`). All three run on `unjwt/session`, so no playground needs the library's `h3` resolved. `pnpm dev` runs the h3 one (h3 v2), `pnpm dev:nuxt` the Nuxt 4 one (h3 v1 under `nuxt/server`, `appSecret`-derived key, WebSockets), `pnpm dev:nitro` the Nitro 3 one (same routes on `unjwt/session`, a static `index.html`). They are usage examples, not tests: `test/` covers behaviour.

## Architecture

### Module structure (each is a separate export path)

- `unjwt` — flat named exports of everything in `jws`, `jwe`, `jwk` and `utils` (no namespace objects)
- `unjwt/jws` — `sign()`, `verify()` (Compact) plus `signMulti()`/`verifyMulti()`/`verifyMultiAll()` (General/Flattened)
- `unjwt/jwe` — `encrypt()`, `decrypt()` (Compact) plus `encryptMulti()`/`decryptMulti()` (General/Flattened)
- `unjwt/jwk` — key generation, import/export (CryptoKey, JWK, PEM), wrap/unwrap, PBES2 derivation
- `unjwt/utils` — base64url encode/decode, type guards (`isJWK`, `isJWKSet`, `isPrivateJWK`, etc.), `secureRandomBytes`
- `unjwt/error` — `JWTError`/`isJWTError`, `UnsecureError`/`isUnsecureError` and the error code types
- `unjwt/internal` — JOSE plumbing (`parsePayloadBytes`, `computeJwtTimeClaims`, `crit` checks, …) for tests and tooling; no semver guarantee, not re-exported from `unjwt`
- `unjwt/dpop` — RFC 9449 proof creation and verification; explicit key pair and verification policy, optional replay callback; no HTTP or storage, no root re-export
- `unjwt/adapters/h3` (= `h3v2`) and `unjwt/adapters/h3v1` — `defineJWSSession()`, `defineJWESession()` session definitions (`use`/`token`/`issue`/`open`) for cookie-based JWT sessions; both deprecated, removed in 0.9.0 in favour of `unjwt/session`
- `unjwt/adapters/elysia` — `jwsSession()`/`jweSession()` Elysia plugins (ambient `ctx.session`, `requireSession` guard macro) over `defineJWSSession()`/`defineJWESession()` (the definition plus `plugin()`)
- `unjwt/session` (`src/session/`) — `defineJWSSession()`/`defineJWESession()` over a Web `Request` + response `Headers` or a token in hand, plus `defineSessionDriver()` and the `SessionDriver`/`CookieJar` types for a framework of your own (`{ driver }` option); no peer dependency

### Source layout

```
src/
  index.ts              # root entry: flat named re-exports of the core modules
  error.ts              # `unjwt/error`: JWTError class + error codes (ERR_JWT_EXPIRED, …), UnsecureError
  utils/                # `unjwt/utils`: encoding, type guards, JWT claim validation, sanitization
    _internal/          # base64 codec, quoted-value text helper
  dpop/                 # `unjwt/dpop`: proof creation, verification, types
    _internal/          # key, URI, validation and verification checks
  core/
    internal.ts         # `unjwt/internal` entry point over _internal/jwt.ts
    types/              # TypeScript types for JWK, JWS, JWE, JWT
    _internal/          # plumbing shared by two or more of jws/jwe/jwk/dpop/session
      jwt.ts            # JOSE plumbing: typ/cty defaults, payload parsing, time claims, crit checks
      import-key.ts     # importKey + the JWK import cache + getJWKsFromSet: what jws/jwe need from the key module, without wrap/unwrap/PEM/generation
      limits.ts         # DEFAULT_JOSE_LIMITS, limit resolution, entry and JWK Set candidate bounds
      headers.ts        # protected header serialize/decode, crit/protected-only/producer checks, consumer options, typ, serialization shape
      keys.ts           # JWK Set filter, ECDH-ES agreement params, key-lookup and password key resolution, dir key role
      algorithms.ts     # alg allowlist checks (JWS_ALG_CTX), key/header match, supported-alg and enc checks
      errors.ts         # JWTError wrapping (key lookup, decryption), JSON object copy
      payload.ts        # payload mode resolution, JSON claim validation
    jws/
      index.ts          # `unjwt/jws`: sign/verify (compact); re-exports the multi-signature API
      multi.ts          # signMulti/verifyMulti/verifyMultiAll/generalToFlattenedJWS (General/Flattened JWS)
      _internal/        # sign-verify (protected header, key verification), keys (signing key, RSA modulus), b64 (RFC 7797), algorithms, multi helpers
    jwe/
      index.ts          # `unjwt/jwe`: encrypt/decrypt (compact); re-exports the multi-recipient API
      multi.ts          # encryptMulti/decryptMulti/generalToFlattened (General/Flattened JWE)
      _internal/        # encrypt-decrypt (key management params, unwrap + decrypt), keys (PBES2 budget, CEK, unwrap options), checks, algorithms (JWE_ALG_CTX), multi helpers
    jwk/
      index.ts          # `unjwt/jwk`: re-exports the files below + importKey, thumbprint, the JWK cache, errors
      generate.ts       # generateKey, generateJWK
      password.ts       # deriveKeyFromPassword, deriveJWKFromPassword
      export.ts         # exportJWK, toPublicJWK
      wrap.ts           # wrapKey, unwrapKey
      pem.ts            # importPEM, exportPEM
      ecdh.ts           # deriveSharedSecret
      _internal/        # generate (key params, usages), wrap (argument and segment checks), members (reserved params, kid, key_ops)
    _crypto/            # low-level crypto primitives — originally derived from panva/jose, now maintained in-tree
                        # (_sign-verify, _aes, _ecdh, _pbes2, _rsa, _key-codec, _key-encryption, _pem)
  session/              # `unjwt/session`: the session core, the Web driver, and the public driver API
    index.ts            # the entry: defineJWSSession/defineJWESession (optional `{ driver }`), defineSessionDriver, WebSessionEvent
    jws.ts, jwe.ts      # the two families' define*Session over the Web driver
    types.ts            # the public session types (SessionClaims/Data/Update/Manager/Hooks/State/Definition, WebSessionEvent = SessionRequestEvent | SessionHandedToken)
    _internal/
      web-driver.ts     # driver: event.context.sessions or WeakMap state, request headers/cookies, handed token
      cookie.ts         # Web cookie jar: cookie-es parse of the Cookie header, Set-Cookie replace on Headers
      define-driver.ts  # defineSessionDriver(): the typed identity for a third-party driver
      contract.ts       # framework-agnostic session contract (error factories, reserved-claim stripping, name/cookie/rolling checks, typ/exp helpers)
      core.ts           # session state and the codec/store/binding contracts every session runs on
      bind.ts           # bindSession: config checks, per-request name registry, store and transport of one session
      read.ts           # load: token read, open, expiry, onRead/onExpire/onError, rolling
      write.ts          # issue/drop/encode with rollback, onUpdate/onClear, the manager's lazy getters
      definition.ts     # SessionDefinition + defineSession: one config bound to a driver and a codec (use/token/issue/open)
      driver.ts         # SessionDriver/CookieJar: the primitives a framework supplies (state, header, cookies, writable)
      transport.ts      # core-owned cookie + header transports over a driver; sessionHeader rules
      types.ts          # internal contracts only (PendingSession/StoredSession, SessionCodec/Store/Actions/Binding, core config and hooks)
      codec.ts          # codec skeleton shared by both families: key checks, issue/open options, claims ↔ session
      codec-jws.ts      # JWS half of a session: sign/verify, key resolution, JWS config + cookie defaults
      codec-jwe.ts      # JWE half of a session: encrypt/decrypt, key resolution, JWE config + cookie defaults
      chunked-cookie.ts # framework-agnostic `__chunked__N` cookie layer (marker, 1-indexed parts, MAX_CHUNK_COUNT)
      cookie-attributes.ts # CookieAttributes: the Set-Cookie attribute shape shared by the Elysia and Web entries
  adapters/             # framework entries over `src/session/`: Elysia (plugin + guard macro), and the deprecated h3 ones
    h3v1/               # H3 v1 session adapter (defineJWSSession, defineJWESession)
      _internal/cookie.ts # cookie option type + the Node response's Set-Cookie list
      _internal/shared.ts # driver: CompatEvent, context state, request headers/cookies, cookie jar
    h3/                 # H3 v2 session adapter (`unjwt/adapters/h3`, also served as `h3v2`)
      _internal/cookie.ts # cookie option type
      _internal/shared.ts # driver: context state, request headers/cookies, cookie jar with res.errHeaders staging
    elysia/             # Elysia session adapter
      session/          # defineJWSSession/defineJWESession, jwsSession/jweSession plugins, shared types
      _internal/cookie.ts # chunked-cookie layer over Elysia's reactive cookie jar
      _internal/plugin.ts # SessionPlugin<> explicit return type, SessionPluginDefinition, guardName() helper
      _internal/shared.ts # driver: per-request state keyed by the Request, request headers, reactive cookie jar
```

### Key design patterns

- **Optional protocol modules:** DPoP imports core helpers; core and sessions never import DPoP. Downstream owns HTTP, access-token validation, nonce issuance and replay storage. `createDPoPProof` takes an explicit key pair and infers the signing algorithm from JWK metadata or an unambiguous key shape (explicit for CryptoKey pairs); proof ID defaults to a fresh UUID v4 and creation time to the current Unix second, both overridable. Optional `exp`/`nbf` are absolute Unix timestamps with no defaults. `createDPoPProof(target, options)` and `verifyDPoPProof(proof, target, options)` both accept an `accessToken` object (`{ token }` for creation, `{ token, thumbprint }` for verification). Verification takes an algorithm allowlist and age limit; its optional replay callback runs only after every proof check succeeds.
- **Dual-version peer deps:** `h3` v2 is installed as itself; h3 v1 only as the `h3v1` alias in devDependencies, which `build.config.ts` rewrites to `h3` in dist output for the deprecated `h3v1` adapter until 0.9.0 removes it. `elysia` is a plain optional peer dep, marked `external` in the build.
- **Single multi-input bundle:** all entry points (core subpaths + every adapter) are `input`s of one `type: "bundle"` in `build.config.ts`, so rolldown code-splits shared core into `dist/_chunks/*` (no per-adapter duplication). Adding an adapter = add its `index` input + any peer dep to `external`; `unjwt/session` (`./src/session/index`) has no peer dep, so nothing of its own is external. `unsecure` and `cookie-es` stay bundled (inlined → zero runtime deps).
- **`src/core/_crypto/`** originated as a fork of [`panva/jose`](https://github.com/panva/jose) primitives but is now maintained as part of this codebase — modify and fix it like any other module (bug fixes, lint, type-safety). It is excluded from test coverage; adding tests there is optional, not required.
- **Bundled `unsecure` dependency:** core imports primitives from [`unsecure`](https://github.com/sandros94/unsecure) (`base64UrlEncode`/`base64UrlDecode`, `secureRandomBytes`, `sanitizeObjectCopy`/`safeJsonParse`). It is a devDependency inlined into dist at build time (not marked external in `build.config.ts`), so the published package keeps zero runtime dependencies.
- **Bundled `cookie-es` dependency:** the H3 v1 adapter and `unjwt/session` parse request cookies with [`cookie-es`](https://github.com/unjs/cookie-es) v3 (`unjwt/session` also serializes and parses `Set-Cookie` with it), a devDependency inlined into dist the same way as `unsecure`. Its licence ships in obuild's `dist/THIRD-PARTY-LICENSES.md.gz`. The h3 adapters derive their cookie attribute type from their `h3` version's `setCookie`, and Elysia and `unjwt/session` share `CookieAttributes`, so no `cookie-es` type reaches the published declarations.
- **Algorithm inference:** When `alg`/`enc` aren't provided, `sign`/`encrypt` try to infer them from JWK properties. Password strings default to PBES2 in JWE.
- **JWK-first key model:** Functions accept JWK objects directly; `importKey()` normalizes CryptoKey/JWK/Uint8Array/string inputs.
- **Session adapters** store JWT tokens in chunked cookies — every adapter through the core's cookie transport (`src/session/_internal/transport.ts` over `chunked-cookie.ts`), which writes through the cookie jar each framework's driver supplies, all writing the same `__chunked__N` + `<name>.1…N` layout. Sessions are lazy — `id` is `undefined` until `session.update()` is called. `jti`/`iat`/`exp`/`nbf` are adapter-owned; the session header is read before the cookie, and a request that presents the header is read from it alone and writes no cookie back; with a `maxAge` a token expires at `exp` or `iat + maxAge`, whichever comes first; every adapter error is a `JWTError` (`ERR_SESSION_*`).
- **One session core, two codecs, four drivers:** the session core (`src/session/_internal/core.ts`, `bind.ts`, `read.ts`, `write.ts`) owns the whole session lifecycle (token read, expiry, hook dispatch, update with rollback, clear, the manager's lazy getters) and the transports (`transport.ts`: the chunked cookie and the session header, and two causes a cookie cannot be written: `readonly`, a jar without `write` — `update()` throws, `clear()` only empties state — and `writable()`, the response already sent — both throw). It works through two contracts: a _codec_ (`codec-jws.ts` / `codec-jwe.ts`, each a spec over `codec.ts`) that issues and opens the token and carries the family's defaults, and a _driver_ (`driver.ts`, implemented by `src/session/_internal/web-driver.ts` and each adapter's `_internal/shared.ts`: Web, h3 v1, h3 v2, Elysia) that supplies the framework's primitives for one request _event_ — its state record, a request header, its cookie jar, and whether the response can still change. The hook argument name is not the driver's: each entry passes `hookArgs` to `defineSession`/`bindSession` (`{ event }` on h3 and `unjwt/session`, whatever driver `unjwt/session` is given; `{ context }` on Elysia), so the hook types hold by construction. The same contract is public through `unjwt/session` (`SessionDriver`, `CookieJar`, `defineSessionDriver`), so a third-party driver binds to the codecs with `defineJWSSession(config, { driver })`. `definition.ts` binds one config to a driver and a codec as a `SessionDefinition`; `src/session/{jws,jwe}.ts` and `src/adapters/<fw>/session/{jws,jwe}.ts` are then the public surface alone: the `define*Session` factories, the config/hook types, and the binding of driver to codec. New session logic belongs in the core, new token rules in a codec, how a token travels in the transport, and anything that touches a framework in its driver.
- **Handed token:** a driver's optional `handed(event)` returns `{ token }` when the event carries the token itself (`unjwt/session`'s `{ token }` shape). `resolveTransport` then returns a transport that reads that token, is always writable and has no `write`/`drop`: the full read lifecycle runs (hooks, expiry, `rolling`), `update()` re-mints onto `manager.token` and `clear()` empties the session, whatever `cookie`/`sessionHeader` the config sets. A token presented in the session header travels the same way (`transport.source` is `"handed"`, `"header"` or `"cookie"`; only a cookie transport has `write`/`drop`). The h3 and Elysia drivers do not implement `handed`.

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
- Split logic across files; avoid long single-file modules (>200 LoC). Internal files go in an `_internal/` directory next to their users (shared ones in the nearest common parent), named without a `_` prefix; `src/core/_crypto/` keeps its `_*` names.
- For multi-arg functions, use an options object as the second parameter.
- Avoid barrel files (`index.ts` re-exports); import directly from specific modules.
- Relative imports name the file with its `.ts` extension (`/index.ts` for a directory): the stub `dist` re-exports `src`, and Node resolves nothing else.
- **`skills/unjwt/`** contains reference docs for the public API — keep these files updated when making architectural changes or modifying public-facing signatures/types
