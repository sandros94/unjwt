# Elysia Session Adapter — Design Draft

Status: **design agreed, not yet implemented.** This doc drafts a new `unjwt/adapters/elysia`
session adapter. Delete it once the feature ships (vision docs are for drafting, not archiving).

---

## Narrative summary

unjwt already ships cookie-based session adapters for H3 v1/v2. This adds a third, native to
[Elysia](https://elysiajs.com) (a bun-first, Web-Standard TypeScript framework). The goal is the
same DX as the H3 adapters — session state and lifecycle hooks living on the request context — but
expressed in Elysia's idioms rather than bolted on. A handler should just destructure
`({ session })` and get a typed, ready-to-use session manager; protected routes should opt into a
guard that 401s when no valid session is present.

Elysia's primitives map cleanly onto the H3 model with two frictions worth calling out up front:
Elysia has **no built-in cookie chunking** (H3 gave us `getChunkedCookie`/`setChunkedCookie` for
free), so we port that ourselves; and the word **"hooks"** is overloaded — Elysia's _lifecycle_
hooks (`onRequest`/`resolve`/`beforeHandle`/…) are unrelated to unjwt's _session_ hooks
(`onRead`/`onUpdate`/…), which the docs must disambiguate.

The payoff: Elysia users get unjwt sessions that feel native, share the H3 adapters' surface and
security model, and stay testable in the existing vitest+Node CI without Bun.

---

## Decisions locked (Q&A rounds 1–3)

| #                     | Decision                                                                                                                                                                        |
| --------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Surface               | Plugin auto-attaches an ambient `ctx.session` (via scoped `.resolve()`) **and** exposes a guard macro for protected routes.                                                     |
| Guard failure         | Return Elysia `status(401)` — idiomatic, not a thrown error; stateless, no redirect.                                                                                            |
| Scope                 | `scoped` — session reaches the app that `.use()`s the plugin and its descendants.                                                                                               |
| Cookie chunking       | **Port** transparent split/reassemble over `context.cookie` (full H3 parity).                                                                                                   |
| First cut             | **JWS + JWE parity** — both `jwsSession()` and `jweSession()` from the start.                                                                                                   |
| Multi-session + hooks | Full H3 parity: `config.name` for independent sessions; `config.hooks` keeps the exact H3 names (`onRead`/`onUpdate`/`onClear`/`onExpire`/`onError`).                           |
| Cookie defaults       | **Exact H3 parity**: JWS `httpOnly:false`, JWE `httpOnly:true`, both `secure:true`, `path:"/"`, no `sameSite` (browser default). CSRF-surface note carried into docs as for H3. |

### Phase 2 design decisions (resolved during implementation)

- **Lifecycle code: standalone, mirror h3v2.** Reimplement the session lifecycle in Elysia-native
  code, reusing only the core crypto (`sign`/`verify`/`encrypt`/`decrypt`), `JWTError` routing, and
  the Phase 1 chunking. No shared-core refactor. Base everything on **h3v2** (h3v1 is being
  deprecated). Re-apply the O-1…O-8 hook-ordering fixes carefully.
- **Context key: configurable, default `session`.** The scoped `resolve` injects under a key that
  defaults to `"session"` and is overridable per plugin (`config.contextKey`). Single-session apps
  destructure `({ session })`; multi-session apps give each plugin a distinct key.
- **Session types: duplicated into the elysia adapter** (`src/adapters/elysia/session/types.ts`),
  copied from h3v2's framework-agnostic set. Consistent with the existing h3v1/v2 duplication.
- **Per-request state: resolve closure.** No `context.sessions` map — the manager closes over its
  `SessionJWS`/`SessionJWE` state object, which `update`/`clear` mutate in place. Cleaner than h3's
  context store given Elysia's per-request `resolve`.
- **Context provisioning (CRITICAL for Phase 3).** Elysia lazily provisions context fields
  (`cookie`, etc.) by statically scanning each hook's source for property references. Passing an
  opaque `ctx` into `createJWSSession`/`createJWESession` hides the `cookie` usage, so Elysia does
  NOT provision `ctx.cookie` and it is `undefined` at runtime (verified under Node — throws "Cannot
  read properties of undefined"). The plugin's `resolve` MUST destructure the needed fields so they
  are provisioned, then pass a minimal context:
  `resolve(async ({ cookie, request }) => ({ [key]: await createJWSSession({ cookie, request }, config) }))`.
  This is also why `SessionContext` is intentionally minimal (`{ cookie, request }`).
- **Phasing note:** hooks (vision Phase 4) are woven into the lifecycle and into the config type
  (`config.hooks` + the hook arg shapes reference the Elysia context), so Phases 2 and 4 are
  implemented together as one "session core" unit rather than sequentially.

### Phase 3 design decisions (resolved during implementation)

- **`isolatedDeclarations` vs Elysia plugin types.** The project sets `isolatedDeclarations: true`
  (fast/portable `.d.ts`), which requires every exported function to have a hand-writable return
  type. `jwsSession`/`jweSession` return `new Elysia().resolve().macro()` — a deeply-inferred type.
  Resolved WITHOUT a tsconfig/build carve-out by writing the return type explicitly (shared
  `SessionPlugin<Resolved, GuardName>` in `_plugin.ts`) against Elysia's 7 generics: the scoped
  resolve augmentation goes in `Ephemeral.resolve` as `{ [P in K]: SessionManager }`, and the guard
  in `Metadata.macro` as `{ [GuardName]?: boolean }`; the body is cast `as unknown as <that type>`.
  This keeps `isolatedDeclarations` on for the whole library while giving consumers typed
  `ctx[contextKey]` and a working `.guard({ requireSession: true })`. (`macroFn` is left `{}` — consumers
  only need `Metadata.macro` for the route option. The macro slot must be **optional**
  (`requireSession?`); a required key forces `requireSession` onto every route's hook options.)
- **Guard macro name is derived from `contextKey`:** `require${Capitalize<contextKey>}` (default
  `requireSession`, `contextKey: "shared"` → `requireShared`, etc.). Without this, multiple session
  plugins on one app all register a hardcoded `requireSession` macro and Elysia silently keeps the
  **last-registered** one (verified: a `session` cookie failed a guard that had been shadowed to
  check `shared`). The runtime key is computed (`guardName()` helper), so the `.macro({ [key]: … })`
  call relies on the `as unknown as SessionPlugin` return cast (Elysia's macro typing expects literal
  keys); the consumer-facing type stays exact via the template-literal `GuardName`. The macro
  `resolve` must use an **inferred** `ctx` param — an explicit annotation breaks the macro overload.
- **Multi-session is supported and tested:** distinct `contextKey` AND `name` per plugin →
  independent ambient sessions, cookies, and guards. JWS + JWE together works (e.g. access-JWS +
  refresh-JWE), each keeping its own cookie defaults (`httpOnly:false` vs `true`).
- **Plugin instance dedupe:** `new Elysia({ name: "unjwt/elysia-jws" | "unjwt/elysia-jwe", seed: contextKey })`.
  Seeding by `contextKey` means multi-session apps with distinct keys produce distinct instances,
  while two plugins on the same key dedupe (which is correct — they would collide on context).
- **Plugin factories live with their cores** (`session/jws.ts`, `session/jwe.ts`), mirroring h3v2's
  one-file-per-mode layout. This pulls `elysia` into those modules (expected for the adapter). The
  shared plugin return type + `guardName()` helper live in `_plugin.ts`.

---

## H3 → Elysia mapping

| H3                                                            | Elysia                                                                                                                                                                           |
| ------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `event.context.sessions[name]` (per-request store)            | per-request `context`; attach `session` via `.resolve()` (typed, runs at `beforeHandle`)                                                                                         |
| `useJWSSession(event, config)` called in handler              | plugin `.resolve({ as: 'scoped' }, …)` exposes ambient `ctx.session`; handler reads `({ session })`                                                                              |
| `getChunkedCookie` / `setChunkedCookie`                       | **own chunking layer** over the reactive `context.cookie` jar                                                                                                                    |
| reading token: header → response Set-Cookie → request cookie  | Elysia's reactive jar already reflects pending writes — `ctx.cookie[name].value` returns fresh-or-incoming, collapsing H3's `findSetCookie` hack; header read from `ctx.headers` |
| writing token: `setChunkedCookie`                             | mutate `ctx.cookie[...]`; Elysia auto-emits `Set-Cookie` only when a value changed                                                                                               |
| cookie attrs (`httpOnly`/`secure`/`sameSite`/`maxAge`/`path`) | `ctx.cookie[name].set({...})`                                                                                                                                                    |
| `config.hooks.{onRead,…}`                                     | identical — namespaced under `config.hooks`, so no real clash with Elysia lifecycle hooks (docs disambiguate)                                                                    |
| h3v1 / h3v2 split                                             | single adapter (Elysia 1.x unified)                                                                                                                                              |
| lazy session (`id` undefined until `update()`)                | same semantic — manager attached in `resolve`                                                                                                                                    |

Key Elysia facts behind these choices (all from official docs, see research notes):

- `.resolve()` runs at the **`beforeHandle`** stage (after validation, typed); `.derive()` runs at
  **`transform`** (pre-validation, untyped). We use `resolve` — session reading depends only on
  cookies/headers, but typed context is worth the later stage.
- Hooks/derive/resolve are **`local` by default** (encapsulated); they must be cast **`scoped`** to
  reach the consuming app's routes. Plain `decorate`/`state` properties already propagate, but
  per-request resolved values do not — hence the explicit scope.
- The reactive cookie jar **auto-flushes** `Set-Cookie`; we never write the header manually. Elysia
  cookie **signing** exists but we do **not** use it — the JWS/JWE token is already authenticated;
  we store the raw token string (chunked).

---

## Plumbing sketch (illustrative, not final)

```ts
// unjwt/adapters/elysia
import { Elysia } from "elysia";

export function jwsSession<T>(config: SessionConfigJWS<T>) {
  return new Elysia({ name: "unjwt.jws-session", seed: config })
    .resolve({ as: "scoped" }, async (ctx) => ({
      session: await getJWSSession(ctx, config), // lazy manager, reads chunked cookie/header
    }))
    .macro({
      requireSession: {
        resolve({ session, status }) {
          if (!session.id) return status(401, "Unauthorized");
          return { session };
        },
      },
    });
}
```

```ts
// consumer
const app = new Elysia()
  .use(jwsSession({ key }))
  .get("/me", ({ session }) => session.data.user) // ambient
  .post("/login", async ({ session }) => {
    await session.update({ user });
  })
  .guard({ requireSession: true }, (a) => a.get("/admin", ({ session }) => session.data)); // gated → 401 if absent
```

`getJWSSession`/`getJWESession` reuse the **core** `sign`/`verify`/`encrypt`/`decrypt` and the same
structured-error routing (`ERR_JWT_EXPIRED` via `error.cause.jti`) the H3 adapters use — so the
hook lifecycle (mutually-exclusive `onRead`/`onExpire`/`onError`, deep-cloned `oldSession`) ports
directly. The `SessionManager` shape (`id`, `data`, `token`, `update`, `clear`) is shared.

---

## Phase 0 spike — VALIDATED ✓

The load-bearing unknowns were validated against **Elysia 1.4.28** in vitest+**Node 24**
(`test/elysia-spike.test.ts`, 6/6 passing, typecheck clean). Results:

1. ✓ `import { Elysia } from "elysia"` loads clean under Node, and `app.handle(new Request(...))`
   returns a `Response` in vitest — **no Bun needed**. `@elysiajs/node` only for `.listen()`.
2. ✓ The reactive **cookie jar is populated at the `resolve` stage** — incoming cookies are
   readable there, not just in the handler. (No need for the `request.headers` fallback.)
3. ✓ A **scoped `.resolve()` propagates both the runtime value and the TS type** of `session` to
   the consumer's routes (`session.id`/`session.data.n` typed cleanly, no cast). The guard macro
   composes with it and `status(401)` short-circuits as designed.
4. ✓ Chunked cookies round-trip: writing `cookie["name.0"]`/`["name.1"]` emits per-chunk
   `Set-Cookie`, incoming chunks reassemble, and `.remove()` expires each. Set-Cookie is emitted
   **only when a value changes** (read-only access emits nothing).

**Finding (minor, shapes the chunking layer):** dynamic-key cookie reads (`cookie[\`name.${i}\`].value`)
are typed **`unknown`** — Elysia only types schema-declared cookie names as `string`. The chunking
layer must cast reads to `string` explicitly. Not a blocker.

**Still to determine empirically:** minimum Node version (Elysia/`@elysiajs/node` declare no
`engines`) — pin a CI matrix entry once the adapter lands. Node 24 confirmed working.

---

## Phased plan (dependency order)

Each phase is thin enough that a wrong assumption invalidates at most the next phase.

> **Phase 4 (hooks) was absorbed into Phases 2+3.** The hook lifecycle is inseparable from the
> session lifecycle and config type, so it shipped with the cores (init/update/clear hooks) and the
> plugin (the guard reads the hook-populated session). There is no standalone Phase 4.

- **Phase 0 — Spike. ✓ DONE.** Validated the CI + plumbing story (see "Phase 0 spike" above).
  `test/elysia-spike.test.ts` was the throwaway proof; superseded by the real tests below.
- **Phase 1 — Cookie chunking layer. ✓ DONE & COMMITTED.** `_cookie.ts` (read/reassemble,
  write/split, remove) ported from H3's scheme; unit + real-Elysia integration tested.
- **Phase 2 + 4 — Session core + hooks. ✓ DONE & COMMITTED.** `createJWSSession`/`createJWESession`
  (`session/jws.ts`, `session/jwe.ts`) with closure state, lazy `id`, `update`/`clear`, full hook
  lifecycle (onRead/onUpdate/onClear/onExpire/onError, mutual exclusivity, deep-clone rollback),
  reusing core sign/verify/encrypt/decrypt + the chunking layer. JWS and JWE. Unit + integration tested.
- **Phase 3 — Plugin factories + guard macro. ✓ DONE.** `jwsSession()`/`jweSession()` (scoped
  resolve destructuring `{ cookie, request }`, inject under `contextKey`, explicit `SessionPlugin`
  return type for `isolatedDeclarations`) + `requireSession` guard macro (→ `status(401)`) +
  `index.ts` barrel. Real-server integration tested.
- **Phase 5 — Packaging + docs.** Add `./src/adapters/elysia/index` to the **existing single
  multi-input `bundle` entry** in `build.config.ts` (NOT a separate entry) + add `"elysia"` to
  `rolldown.external` (peer dep, never bundled; no alias replacement — single Elysia major). Add the
  `./adapters/elysia` `package.json` exports entry. Then skills reference + docs-site page
  (disambiguate "session hooks" vs Elysia "lifecycle hooks"). Docs after the implementation is committed.

  **Bundling note (no core duplication):** the build is one `type: "bundle"` with many `input`s, so
  rolldown code-splits shared core into `dist/_chunks/*.mjs` (jwk/jws/jwe/utils/\_internal) and every
  entry — core subpaths AND adapters — imports from those chunks. Core lives once. This is why
  adapters must stay inputs of the _same_ bundle (separate bundle entries = separate rolldown builds
  = duplicated core). Externalizing core to published `unjwt/*` specifiers was considered and
  rejected: unnecessary for a single package with subpath exports, and adds self-referential
  complexity. `unsecure` stays bundled (inlined → zero runtime deps); only true peer deps
  (`elysia`, `h3`, `cookie-es`, `rou3`) are external.

---

## Notes

- `elysia` joins the peer deps (alongside `h3`, `cookie-es`, `rou3`); add as a dev/peer dep. Unlike
  H3, no dual-version aliasing is expected (single Elysia major).
- Cookie defaults match H3 exactly; the JWS `httpOnly:false` CSRF-surface caveat is documented, not
  changed (deliberate parity decision).
