# Elysia Session Adapter Reference

JWT-based session management for [Elysia](https://elysiajs.com) (`>=1.4.0`). Ships as two plugins —
`jwsSession` (signed) and `jweSession` (encrypted) — that attach an ambient session manager to the
request context, plus a per-session guard macro.

Import path: `unjwt/adapters/elysia`

```ts
import { jwsSession, jweSession } from "unjwt/adapters/elysia";
```

Also re-exports: `generateJWK`, `importPEM`, `exportPEM`, `deriveJWKFromPassword`, all core types.

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

const app = new Elysia()
  .use(jweSession({ key: process.env.SESSION_SECRET!, maxAge: "7D" }))
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
the rest of the library: JWE `httpOnly: true`, JWS `httpOnly: false`, both `secure: true`, `path: "/"`.

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
`contextKey` + `name` when combining.

## SessionManager Interface

Same shape as the H3 adapters:

```ts
interface SessionManager<
  T extends Record<string, any> = SessionClaims,
  ConfigMaxAge extends ExpiresIn | undefined = ExpiresIn | undefined,
> {
  readonly id: string | undefined; // jti — undefined until update() is called (lazy)
  readonly createdAt: number; // iat, ms
  readonly expiresAt: ConfigMaxAge extends ExpiresIn
    ? number
    : "exp" extends keyof T
      ? T["exp"]
      : number | undefined;
  readonly data: SessionData<T>; // payload, excludes jti/iat/exp
  readonly token: string | undefined;
  update: (update?: SessionUpdate<T>) => Promise<SessionManager<T, ConfigMaxAge>>;
  clear: () => Promise<SessionManager<T, ConfigMaxAge>>;
}

type SessionUpdate<T> =
  | Partial<SessionData<T>>
  | ((oldData: SessionData<T>) => Partial<SessionData<T>> | undefined);
```

- Lazy: `session.id` is `undefined` until `update()`; reading `ctx.session` alone sets no cookie.
- `update()` — partial merge, updater fn, or no-arg token rotation.
- `clear()` — expires the cookie, resets state, fires `onClear` (distinct from expiry → `onExpire`).
- Reserved claims `jti`/`iat` always overwrite same-named data keys; `exp` only when `maxAge` is set
  (without `maxAge`, an `exp` data key becomes the token's real expiry).

## Config

### SessionConfigJWS

```ts
interface SessionConfigJWS<T, MaxAge, TContext> {
  key:
    | JWK_oct<JWK_HMAC>
    | {
        privateKey: JWSAsymmetricPrivateJWK;
        publicKey: JWSAsymmetricPublicJWK | JWSAsymmetricPublicJWK[] | JWKSet;
      };
  maxAge?: MaxAge;
  name?: string; // default "elysia-jws"
  contextKey?: string; // default "session"
  cookie?: false | (CookieAttributes & { chunkMaxLength?: number });
  sessionHeader?: false | string; // default x-<name>-session; "Bearer " stripped
  generateId?: () => string;
  jws?: {
    signOptions?: Omit<JWSSignOptions, "expiresIn">;
    verifyOptions?: JWTClaimValidationOptions;
  };
  hooks?: SessionHooksJWS<T, MaxAge, TContext>;
}
```

### SessionConfigJWE

```ts
interface SessionConfigJWE<T, MaxAge, TContext> {
  key:
    | string
    | JWEEncryptJWK
    | { privateKey: JWEAsymmetricPrivateJWK; publicKey?: JWEAsymmetricPublicJWK };
  maxAge?: MaxAge;
  name?: string; // default "elysia-jwe"
  contextKey?: string; // default "session"
  cookie?: false | (CookieAttributes & { chunkMaxLength?: number });
  sessionHeader?: false | string;
  generateId?: () => string;
  jwe?: {
    encryptOptions?: Omit<JWEEncryptOptions, "expiresIn">;
    decryptOptions?: JWTClaimValidationOptions;
  };
  hooks?: SessionHooksJWE<T, MaxAge, TContext>;
}
```

**Pin algorithms** for production: set `jws.signOptions.alg` (or `jwe.encryptOptions.alg` + `enc`).
Verification/unsealing then accepts only those values; otherwise they are inferred from the key.

`CookieAttributes` is the Elysia cookie option subset: `domain`, `expires`, `httpOnly`, `maxAge`,
`path`, `priority`, `sameSite`, `secure`, `partitioned`. The adapter does NOT use Elysia's cookie
signing — the JWS/JWE token is already authenticated; the raw token is stored (chunked).

## Lifecycle Hooks

`config.hooks` — same set as H3: `onRead`, `onUpdate`, `onClear`, `onExpire`, `onError`, plus
`onVerifyKeyLookup` (JWS) / `onUnsealKeyLookup` (JWE) for key rotation.

> These are unjwt **session hooks** (`config.hooks.*`), unrelated to Elysia's request **lifecycle
> hooks** (`onRequest`, `beforeHandle`, …).

Each hook receives `{ session, context, config }` — `context` is the Elysia context (not an H3
`event`). Guarantees (ported from H3v2):

- `onRead` / `onExpire` / `onError` are mutually exclusive per incoming token. `onRead` fires only
  when a valid session was established.
- `onExpire` receives the expired token's decoded claims via `error.cause` (`jti`/`iat`/`exp`), so
  `session.id` is available.
- `onUpdate` fires after every successful sign/seal (including data-less token refresh) with a
  deep-cloned `oldSession`.
- `onError` fires on read-path failures other than expiry, and on write-path sign/seal failures
  (with `session.data` rolled back).

```ts
jweSession({
  key: secret,
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
referenced there and stays `undefined` at runtime (the session can't read/write it).

## Notes / gotchas

- `jwsSession`/`jweSession` return an explicitly-typed Elysia plugin (`SessionPlugin<Resolved, GuardName>`
  in `_plugin.ts`) so the package satisfies `isolatedDeclarations`; the factory body is cast
  `as unknown as SessionPlugin<…>` because Elysia's `.macro()` expects literal keys while the guard
  key is computed.
- Build: the adapter is an input of the single multi-input bundle (shared core in `dist/_chunks/`,
  `elysia` external, `unsecure` inlined) — no core duplication.
- Testable in vitest+Node via `app.handle(new Request(...))`; no Bun required.
