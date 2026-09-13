# Elysia Session Adapter Reference

JWT-based session management for [Elysia](https://elysiajs.com) (`>=1.4.0`). Ships as two plugins —
`jwsSession` (signed) and `jweSession` (encrypted) — that attach an ambient session manager to the
request context, plus a per-session guard macro.

Import path: `unjwt/adapters/elysia`

```ts
import { jwsSession, jweSession } from "unjwt/adapters/elysia";
```

Also re-exports: `generateJWK`, `thumbprint`, `importPEM`, `exportPEM`, `deriveJWKFromPassword`, all core types.

Peer dep: `elysia` (optional). Runs anywhere `app.handle(Request)` does (Bun, Node, Deno, Workers);
`@elysiajs/node` is only needed to run an actual server via `.listen()`, not for `handle()`.

## Plugin vs core function

| Export                                                            | Purpose                                                                                                           |
| ----------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------- |
| `jwsSession(config)` / `jweSession(config)`                       | Elysia **plugin**: scoped `resolve` attaches `ctx[contextKey]` + registers a guard macro. The normal entry point. |
| `createJWSSession(ctx, config)` / `createJWESession(ctx, config)` | Lower-level: takes `{ cookie, request }`, returns a `SessionManager`. For manual `resolve`/`derive` wiring.       |

## Basic usage

```ts
import { Elysia, t } from "elysia";
import { jweSession } from "unjwt/adapters/elysia";

// Derive once at boot — the adapter takes key material, never a password.
const key = await deriveJWKFromPassword(process.env.SESSION_SECRET!, {
  alg: "PBES2-HS256+A128KW",
  salt: process.env.SESSION_SALT!,
  iterations: 600_000,
});

const app = new Elysia()
  .use(jweSession({ key, maxAge: "7D" }))
  .post(
    "/login",
    async ({ session, body }) => {
      await session.update({ userId: body.userId });
      return { id: session.id };
    },
    { body: t.Object({ userId: t.String() }) },
  )
  .get("/me", ({ session }) => session.data);
```

`ctx.session` is typed (the plugin's scoped `resolve` populates it per request). Cookie defaults match
the rest of the library: JWE `httpOnly: true`, JWS `httpOnly: false`, both `secure: true`, `path: "/"`,
`sameSite: "lax"`.

## Guard macro

Each plugin registers a guard macro named `require` + the capitalized `contextKey`. Default key
`"session"` → `requireSession`. Opting a route in returns `status(401)` (not a throw/redirect) when no
valid session is present:

```ts
.guard({ requireSession: true }, (app) => app.get("/admin", ({ session }) => session.data));
```

The macro key is **optional** on route options (you opt in per route). The runtime macro key is
computed from `contextKey`, so distinct context keys produce distinct guards (no collision when
multiple session plugins are used).

## Multiple sessions

Set a distinct `contextKey` AND `name` on each plugin (e.g. access JWS + refresh JWE):

```ts
const app = new Elysia()
  .use(jwsSession({ key: accessKey, contextKey: "access", name: "at", maxAge: "10m" }))
  .use(jweSession({ key: refreshKey, contextKey: "refresh", name: "rt", maxAge: "7D" }))
  .get("/me", ({ access, refresh }) => ({ user: access.data, sub: refresh.data.sub }))
  .guard({ requireAccess: true }, (app) => app.get("/api", () => "ok")); // checks ctx.access
```

- `contextKey` (default `"session"`) — the context property the session is exposed under.
- `name` (default `"elysia-jws"` / `"elysia-jwe"`) — the cookie name and the default `x-<name>-session` header.
- Guard names follow `contextKey`: `requireAccess`, `requireRefresh`, etc.

With defaults, two plugins would both expose `ctx.session` (later wins) — always set distinct
`contextKey` + `name` when combining. Each plugin's Elysia identity is seeded from `name` and
`contextKey`, so two differently-named sessions register side by side instead of deduplicating.

## SessionManager Interface

Same shape as the H3 adapters:

```ts
interface SessionManager<
  T extends Record<string, any> = SessionClaims,
  ConfigMaxAge extends ExpiresIn | undefined = ExpiresIn | undefined,
> {
  readonly id: string | undefined; // jti — undefined until update() is called (lazy)
  readonly createdAt: number; // iat, ms
  readonly expiresAt: ConfigMaxAge extends ExpiresIn ? number : number | undefined;
  readonly data: SessionData<T>; // payload, excludes jti/iat/exp/nbf
  readonly token: string | undefined;
  update: (
    update?: SessionUpdate<T>,
    options?: SessionIssueOptions, // { maxAge?: ExpiresIn } — this issue only
  ) => Promise<SessionManager<T, ConfigMaxAge>>;
  clear: () => Promise<SessionManager<T, ConfigMaxAge>>;
}

type SessionUpdate<T> =
  Partial<SessionData<T>> | ((oldData: SessionData<T>) => Partial<SessionData<T>> | undefined);
```

- Lazy: `session.id` is `undefined` until `update()`; reading `ctx.session` alone sets no cookie.
- `update()` — partial merge, updater fn, or no-arg token rotation. `update(data, { maxAge })` gives
  one token a lifetime of its own.
- `clear()` — expires the cookie, resets state, fires `onClear` (distinct from expiry → `onExpire`).
- Reserved claims `jti`, `iat`, `exp` and `nbf` are adapter-owned: stripped from every `update()`
  payload and never read back out of `session.data`. A token's lifetime comes only from `maxAge`.
  A `__proto__`, `constructor` or `prototype` key in an update throws `ERR_INVALID_OPTION`.

## Config

### SessionConfigJWS

```ts
interface SessionConfigJWS<T, MaxAge, TContext> {
  key:
    | CryptoKey // requires jws.signOptions.alg
    | JWK_oct<JWK_HMAC>
    | {
        privateKey: JWSAsymmetricPrivateJWK | CryptoKey;
        publicKey: JWSAsymmetricPublicJWK | JWSAsymmetricPublicJWK[] | JWKSet | CryptoKey;
      };
  maxAge?: MaxAge;
  name?: string; // default "elysia-jws"
  contextKey?: string; // default "session"
  cookie?: false | (CookieAttributes & { chunkMaxLength?: number });
  sessionHeader?: false | string; // default x-<name>-session; "Bearer " stripped (case-insensitive)
  generateId?: () => string;
  jws?: {
    signOptions?: Omit<JWSSignOptions, "expiresIn">;
    /** Claim validation the adapter does not own — `maxTokenAge` follows `maxAge`, `typ` the signed `typ`. */
    verifyOptions?: SessionVerifyOptions;
  };
  hooks?: SessionHooksJWS<T, MaxAge, TContext>;
}
```

### SessionConfigJWE

```ts
interface SessionConfigJWE<T, MaxAge, TContext> {
  key:
    | CryptoKey // requires jwe.encryptOptions.alg + enc
    | JWEEncryptJWK
    | {
        privateKey: JWEAsymmetricPrivateJWK | CryptoKey;
        publicKey?: JWEAsymmetricPublicJWK | CryptoKey;
      };
  maxAge?: MaxAge;
  name?: string; // default "elysia-jwe"
  contextKey?: string; // default "session"
  cookie?: false | (CookieAttributes & { chunkMaxLength?: number });
  sessionHeader?: false | string;
  generateId?: () => string;
  jwe?: {
    encryptOptions?: Omit<JWEEncryptOptions, "expiresIn">;
    // JWEDecryptOptions minus the adapter-owned algorithms, encryptionAlgorithms,
    // typ, validateClaims and forceUint8Array — so minIterations/maxIterations,
    // clockTolerance, issuer and audience are settable. With a PBES2 `alg` pinned,
    // `maxIterations` defaults to the `p2c` the session itself mints.
    decryptOptions?: SessionDecryptOptions;
  };
  hooks?: SessionHooksJWE<T, MaxAge, TContext>;
}
```

**Pin algorithms** for production: set `jws.signOptions.alg` (or `jwe.encryptOptions.alg` + `enc`).
Verification/unsealing then accepts only those values; otherwise they are inferred from the key.

`CookieAttributes` is the Elysia cookie option subset: `domain`, `expires`, `httpOnly`, `maxAge`,
`path`, `priority`, `sameSite`, `secure`, `partitioned`. The adapter does NOT use Elysia's cookie
signing — the JWS/JWE token is already authenticated; the raw token is stored (chunked).

## Keys, token source and errors

- **Key material only.** `key` is a JWK, a `{ privateKey, publicKey }` pair, or a `CryptoKey`.
  A password string throws `ERR_SESSION_KEY_INVALID` — derive a JWK once with
  `deriveJWKFromPassword()`. A `CryptoKey` needs `jws.signOptions.alg` (or
  `jwe.encryptOptions.alg` + `enc`), else `ERR_SESSION_CONFIG_INVALID`.
- **Token source.** The cookie is read first; the session header is the fallback when the cookie
  carries no token. A present-but-empty or whitespace-only header never hides the cookie.
  `cookie: false` + `sessionHeader: false` throws `ERR_SESSION_CONFIG_INVALID` on first use.
- **Foreign tokens.** A token is only a session when it carries `cty: "application/json"`; with
  `maxAge` set it must also carry `exp` and its `iat` must fall within `maxAge`.
- **Chunking.** The base cookie holds `__chunked__<count>` and the parts follow as `<name>.1` …
  `<name>.<count>`, up to 16 chunks; the same layout as both H3 adapters, so cookies are
  interchangeable. Cleanup of a previous set is bounded by the same limit.
- **Errors.** Every adapter error is a `JWTError`: `ERR_SESSION_TOKEN_INVALID` (with the original
  failure as `cause`), `ERR_SESSION_KEY_INVALID`, `ERR_SESSION_CONFIG_INVALID`,
  `ERR_SESSION_READONLY_EVENT`, `ERR_INVALID_OPTION`.

## Lifecycle Hooks

`config.hooks` — same set as H3: `onRead`, `onUpdate`, `onClear`, `onExpire`, `onError`, plus
`onVerifyKeyLookup` (JWS) / `onUnsealKeyLookup` (JWE) for key rotation.

> These are unjwt **session hooks** (`config.hooks.*`), unrelated to Elysia's request **lifecycle
> hooks** (`onRequest`, `beforeHandle`, …).

Each hook receives `{ session, context, config }` — `context` is the Elysia context (not an H3
`event`). Guarantees (ported from H3v2):

- `onRead` / `onExpire` / `onError` are mutually exclusive per incoming token. `onRead` fires on
  each read of a session established from a valid token, so dedupe on `session.id` where
  once-per-request is what you want.
- Every hook is dispatched with the session state already settled, so a hook may call
  `createJWSSession` / `createJWESession` again on the same context without deadlocking.
- `onExpire` receives the expired token's decoded claims via `error.cause` (`jti`/`iat`/`exp`), so
  `session.id` is available. The session cookie is removed and `session.token` reset before it fires.
- `onUpdate` fires after every successful sign/seal (including data-less token refresh) with a
  deep-cloned `oldSession`.
- `onError` fires on read-path failures other than expiry, and on write-path sign/seal failures
  (with `session.data` rolled back). A read-path `error` is always an `ERR_SESSION_TOKEN_INVALID`
  `JWTError` whose `cause` is the failure underneath.

```ts
jweSession({
  key,
  maxAge: "7D",
  hooks: {
    onUpdate: ({ session }) => db.sessions.upsert(session.id!, session.expiresAt),
    onExpire: ({ session }) => db.sessions.revoke(session.id),
  },
});
```

## Lower-level: manual resolve

```ts
import { createJWSSession } from "unjwt/adapters/elysia";

new Elysia()
  .resolve(async ({ cookie, request }) => ({
    session: await createJWSSession({ cookie, request }, { key, maxAge: "1h" }),
  }))
  .get("/me", ({ session }) => session.data);
```

**Must destructure `{ cookie, request }`** in the `resolve` signature. Elysia provisions context
fields by statically scanning the hook source; passing an opaque `ctx` means `cookie` is never
referenced there and stays `undefined` at runtime. A `cookie` object that holds no reactive cookie
throws `ERR_SESSION_CONFIG_INVALID` on the first write, naming the jar contract.

## Notes / gotchas

- `jwsSession`/`jweSession` return an explicitly-typed Elysia plugin (`SessionPlugin<Resolved, GuardName>`
  in `_plugin.ts`) so the package satisfies `isolatedDeclarations`; the factory body is cast
  `as unknown as SessionPlugin<…>` because Elysia's `.macro()` expects literal keys while the guard
  key is computed.
- The session lifecycle is the shared core in `src/adapters/_session-core.ts`, over the JWS/JWE
  codec and the Elysia port in `session/_shared.ts` (reactive-jar cookie writes, token reading),
  so hooks, error codes and claim handling match the h3 adapters exactly.
- Build: the adapter is an input of the single multi-input bundle (shared core in `dist/_chunks/`,
  `elysia` external, `unsecure` inlined) — no core duplication.
- Testable in vitest+Node via `app.handle(new Request(...))`; no Bun required.
