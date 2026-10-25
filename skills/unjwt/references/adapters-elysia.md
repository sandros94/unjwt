# Elysia Session Adapter Reference

JWT-based session management for [Elysia](https://elysiajs.com) (`^1.4.29`). Ships as two plugins — `jwsSession` (signed) and `jweSession` (encrypted) — that attach an ambient session manager to the request context, plus a per-session guard macro. Each plugin is the `plugin()` of a session definition (`defineJWSSession` / `defineJWESession`), which also exposes `use`, `token`, `issue` and `open`.

Import path: `unjwt/adapters/elysia`

```ts
import { defineJWESession, defineJWSSession, jweSession, jwsSession } from "unjwt/adapters/elysia";
```

Also exports the types `SessionDefinition`, `OpenedSessionState`, `SessionPluginDefinition`, `SessionPlugin`, `SessionContext`, `SessionManager`, `SessionClaims`, `SessionData`, `SessionUpdate`, `SessionUpdateTrigger`, `SessionIssueOptions`, `SessionConfigJWS`/`SessionConfigJWE`, `SessionHooksJWS`/`SessionHooksJWE`, `SessionJWS`/`SessionJWE`, `SessionSignOptions`, `SessionVerifyOptions`, `SessionEncryptOptions`, `SessionDecryptOptions`, the cookie types `CookieAttributes`, `ChunkableCookie`, `ChunkableCookieJar`, `WriteChunkedCookieOptions`, and all core types. Re-exports `generateJWK`, `thumbprint`, `importPEM`, `exportPEM`, `deriveJWKFromPassword`.

Peer dep: `elysia` (optional). Runs anywhere `app.handle(Request)` does (Bun, Node, Deno, Workers); `@elysiajs/node` is only needed to run an actual server via `.listen()`, not for `handle()`.

## Plugin vs definition

| Export | Purpose |
| --- | --- |
| `jwsSession(config)` / `jweSession(config)` | Elysia **plugin**: scoped `resolve` attaches `ctx[contextKey]` + registers a guard macro. The normal entry point. |
| `defineJWSSession(config)` / `defineJWESession(config)` | Session definition (`SessionPluginDefinition<T, MaxAge, K>`): `use`, `token`, `issue`, `open`, plus `plugin()` — exactly what `jwsSession(config)` returns. |

```ts
interface SessionDefinition<T, MaxAge, TContext> {
  use(context: TContext): Promise<SessionManager<T, MaxAge>>; // reads once per request; calls share state
  token(context: TContext): string | undefined; // raw token: this response's write, cookie, then session header
  issue(data?: Partial<SessionData<T>>, options?: SessionIssueOptions): Promise<string>; // fresh jti/iat, exp from maxAge; no request, no cookie
  open(token: string): Promise<OpenedSessionState<T, MaxAge>>; // { id, createdAt, expiresAt, data }; same checks as a cookie read
}

interface SessionPluginDefinition<
  T,
  MaxAge,
  K extends string = "session",
> extends SessionDefinition<T, MaxAge, SessionContext> {
  plugin(): SessionPlugin<{ [P in K]: SessionManager<T, MaxAge> }, `require${Capitalize<K>}`>;
}
```

`K` is inferred from `config.contextKey` (default `"session"`). `SessionContext` is `{ cookie, request }` from an Elysia handler.

## Basic usage

```ts
import { Elysia, t } from "elysia";
import { deriveJWKFromPassword, jweSession } from "unjwt/adapters/elysia";

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

`ctx.session` is typed (the plugin's scoped `resolve` populates it per request). Cookie defaults match the rest of the library: JWE `httpOnly: true`, JWS `httpOnly: false`, both `secure: true`, `path: "/"`, `sameSite: "lax"`.

## Guard macro

Each plugin registers a guard macro named `require` + the capitalized `contextKey`. Default key `"session"` → `requireSession`. Opting a route in returns `status(401)` (not a throw/redirect) when no valid session is present:

```ts
.guard({ requireSession: true }, (app) => app.get("/admin", ({ session }) => session.data));
```

The macro key is **optional** on route options (you opt in per route). The runtime macro key is computed from `contextKey`, so distinct context keys produce distinct guards (no collision when multiple session plugins are used).

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

With defaults, two plugins would both expose `ctx.session` (later wins) — always set distinct `contextKey` + `name` when combining. Each plugin's Elysia identity is seeded from `name` and `contextKey`, so two differently-named sessions register side by side instead of deduplicating.

A `name` spells one cookie and one cookie carries one token, so on any one request a name belongs to one session — families included. Opening a second family under a name already in use on the same request throws `ERR_SESSION_CONFIG_INVALID` (`'[unjwt/elysia] Session name "app" is already used by a JWS session on this request.'`). Re-creating the same family under the same name — a hook re-reading its own session — is the same session and is always allowed. All `use()` calls of one family and name on a request (plugin, handler, hook) share one state: a hook's `clear()` empties `ctx.session` and closes `requireSession`, a hook's `update()` hands the handler the new session.

Elysia serializes cookies when it builds the response, and its lifecycle context is the same before and after (`response` and `responseValue` are both set once the handler returns), so the adapter cannot tell `onAfterHandle` from `onAfterResponse`: an `update()`/`clear()` after the response is built (e.g. `onAfterResponse`) resolves, but its cookie is never sent. Write the session before the response is built.

## SessionManager Interface

Same shape as `unjwt/session`:

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
  | Partial<SessionData<T>>
  | ((oldData: SessionData<T>) => Partial<SessionData<T>> | undefined);
```

- Lazy: `session.id` is `undefined` until `update()`; reading `ctx.session` alone sets no cookie.
- `update()` — partial merge, updater fn, or no-arg token rotation. `update(data, { maxAge })` gives one token a shorter lifetime of its own (a longer one ends at the config's `maxAge` when read back).
- `clear()` — expires the cookie, resets state, fires `onClear` (distinct from expiry → `onExpire`).
- Reserved claims `jti`, `iat`, `exp` and `nbf` are adapter-owned: stripped from every `update()` payload, dropped from `session.data` on every issue, never read back out of `session.data`. A token's lifetime comes only from `maxAge`; a read under a config `maxAge` ends any token at `iat + maxAge` at the latest. A token with an `iat` later than now plus `clockTolerance` is refused even without a `maxAge`. A `__proto__`, `constructor` or `prototype` key in an update throws `ERR_INVALID_OPTION`. Data travels as JSON: the writing request keeps the values as given, later reads get their JSON round trip (`Date` → ISO string, `NaN`/`±Infinity` → `null`, `undefined` members dropped).

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
  rolling?: true | ExpiresIn;
  name?: string; // default "elysia-jws"
  contextKey?: string; // default "session"
  cookie?: false | (CookieAttributes & { chunkMaxLength?: number });
  sessionHeader?: boolean | string; // true = x-<name>-session (name without __Host-/__Secure-), read before the cookie; unset or false = no header
  generateId?: () => string;
  jws?: {
    // JWSSignOptions minus expiresIn / expiresAt / notBeforeIn / notBeforeAt;
    // `protectedHeader.typ` sets the session `typ` (default "session+jwt") incoming tokens must carry
    signOptions?: SessionSignOptions;
    /** JWSVerifyOptions the adapter does not own (`limits`, claim checks) — not algorithms, typ, maxTokenAge, validateClaims, payload. */
    verifyOptions?: SessionVerifyOptions;
  };
  hooks?: SessionHooksJWS<T, MaxAge, TContext>;
}
```

### SessionConfigJWE

```ts
interface SessionConfigJWE<T, MaxAge, TContext> {
  key:
    | CryptoKey // a secret key; requires jwe.encryptOptions.alg + enc
    | JWK_oct // an `oct` JWK: the one key seals and opens
    // rotation: `current` seals (its `kid` in the header) and opens, `keys` open too, by `kid`
    | { current: JWK_oct | CryptoKey; keys: JWK_oct[] | JWKSet };
  // asymmetric keys throw ERR_SESSION_KEY_INVALID: a pair seals with its public half, so any holder of it mints sessions
  maxAge?: MaxAge;
  rolling?: true | ExpiresIn;
  name?: string; // default "elysia-jwe"
  contextKey?: string; // default "session"
  cookie?: false | (CookieAttributes & { chunkMaxLength?: number });
  sessionHeader?: boolean | string;
  generateId?: () => string;
  jwe?: {
    // JWEEncryptOptions minus expiresIn / expiresAt / notBeforeIn / notBeforeAt;
    // `protectedHeader.typ` sets the session `typ` (default "session+jwt") incoming tokens must carry
    encryptOptions?: SessionEncryptOptions;
    // JWEDecryptOptions minus the adapter-owned algorithms, encryptionAlgorithms,
    // typ, maxTokenAge, validateClaims and payload — so minIterations/maxIterations,
    // clockTolerance, issuer and audience are settable. With a PBES2 `alg` pinned or
    // carried by the configured `key` (whatever `onUnsealKeyLookup` returns),
    // `maxIterations` defaults to the `p2c` the session itself mints.
    decryptOptions?: SessionDecryptOptions;
  };
  hooks?: SessionHooksJWE<T, MaxAge, TContext>;
}
```

**Pin algorithms** for production: set `jws.signOptions.alg` (or `jwe.encryptOptions.alg` + `enc`). Verification/unsealing then accepts only those values; otherwise they are inferred from the key.

`CookieAttributes` is the Elysia cookie option subset: `domain`, `expires`, `httpOnly`, `maxAge`, `path`, `priority`, `sameSite`, `secure`, `partitioned`. The adapter does NOT use Elysia's cookie signing — the JWS/JWE token is already authenticated; the raw token is stored (chunked).

## Keys, token source and errors

- **Key material only.** `key` is a JWK, a `{ privateKey, publicKey }` pair, or a `CryptoKey`. A JWE session takes a symmetric `oct` JWK (or secret `CryptoKey`): one key seals and opens. To rotate, pass `{ current, keys }`: `current` (an `oct` JWK or secret `CryptoKey`) seals, its `kid` in the header, and opens; `keys` (a list or JWK Set of `oct` JWKs, `current` need not be repeated) open too, picked by the token's `kid` (with a `CryptoKey` `current`, a token whose `kid` names none of them opens with `current`); a token under any other key is a token failure. An asymmetric key — a `{ privateKey, publicKey? }` pair, a private or public JWK, a non-secret `CryptoKey` — throws `ERR_SESSION_KEY_INVALID` on first use: a pair seals with its public half, so anyone who holds it could mint a session the server accepts — use an `oct` JWK, or `defineJWSSession` for a key pair. A password string throws `ERR_SESSION_KEY_INVALID` — derive a JWK once with `deriveJWKFromPassword()`. A `CryptoKey` needs `jws.signOptions.alg` (or `jwe.encryptOptions.alg` + `enc`), else `ERR_SESSION_CONFIG_INVALID`. A configured JWK is imported when the session is created: one it cannot use (undecodable `k`, wrong AES key length) throws `ERR_SESSION_KEY_INVALID` (import failure as `cause`) instead of reaching `onError`. A pair half that is not the half it is named after — for a JWS `publicKey` list or set, any entry that is not a public JWK — throws `ERR_SESSION_KEY_INVALID` naming `"privateKey"` or `"publicKey"`. A `protectedHeader.kid` in the issue options wins over the key's own `kid`.
- **Token source.** The session header is read first: a request that carries it is read from it alone, and the cookie only when the header is absent. The header carries the bare token or `Bearer <token>`; any other value — blank, another scheme such as `Basic …`, a `Bearer` with no token — is a token failure: `ERR_SESSION_TOKEN_INVALID` to `onError`, empty session, the cookie neither read nor dropped. A session read from the header never writes a cookie: `update()` and `rolling` re-mint onto `session.token`, `clear()` empties the session, no `Set-Cookie` (the session cookie included); it updates without a response too. Left unset, a cookie session reads its cookie alone, and a `cookie: false` one reads `x-<name>-session`. A `sessionHeader` that is not a header name throws `ERR_SESSION_CONFIG_INVALID` on first use. `cookie: false` + `sessionHeader: false` is a token-only session: `use`/`token` throw `ERR_SESSION_CONFIG_INVALID`, `issue`/`open` work.
- **Cookie lifetime.** A session with a lifetime sets the cookie's `expires` to the token's `exp` and drops a configured `cookie.maxAge` (`Max-Age` beats `Expires`, RFC 6265 §5.3); without one, `cookie.expires` / `cookie.maxAge` are written as configured. `clear()` and an expired read write `Max-Age=0` plus an epoch `Expires` on the cookie and every chunk. `session.token` and `definition.token(context)` read the session state once `use()` read or wrote it, empty after `clear()`; before that `definition.token(context)` reads the request without opening the token.
- **Names.** Prefer a `__Host-` name (`"__Host-session"`) so no sibling subdomain can plant a cookie that shadows the session (the adapter reads the first cookie of a name); the defaults satisfy the prefix, and a `__Host-` name with `domain`, a `path` other than `/` or `secure: false` (or a `__Secure-` name with `secure: false`) throws `ERR_SESSION_CONFIG_INVALID` when the session is opened. The default session header drops a `__Host-` / `__Secure-` prefix: `"__Host-session"` reads `x-session-session`. A name ending in a dot and digits (`app.1`) spells a chunk cookie of another session and throws `ERR_SESSION_CONFIG_INVALID`.
- **Foreign tokens.** A token is only a session when it carries the session `typ` (default `"session+jwt"`, set through `protectedHeader.typ`, compared as a media type; RFC 8725 §3.11). No `cty` is written or required. With `maxAge` set it must also carry `exp`, and it expires at `exp` or `iat + maxAge`, whichever is sooner (`expiresAt` holds that instant), so a token issued with a longer `update(data, { maxAge })`, or minted elsewhere with a far `exp`, still ends at the reading config's `maxAge`. A foreign token is `ERR_SESSION_TOKEN_INVALID` → `onError` even when expired; only a session token's expiry reaches `onExpire`.
- **Update data** must be a plain object; a string, an array or a `__proto__`-like key throws `ERR_INVALID_OPTION`.
- **Chunking.** The base cookie holds `__chunked__<count>` and the parts follow as `<name>.1` … `<name>.<count>`, up to 16 chunks; the same layout as `unjwt/session`, so cookies are interchangeable. Cleanup of a previous set is bounded by the same limit.
- **Errors.** Every adapter error is a `JWTError`: `ERR_SESSION_TOKEN_INVALID` (with the original failure as `cause`), `ERR_SESSION_KEY_INVALID`, `ERR_SESSION_CONFIG_INVALID`, `ERR_INVALID_OPTION`. `ERR_SESSION_READONLY_EVENT` never comes from Elysia: its cookie jar always takes a write and it exposes no response-sent signal.

## Lifecycle Hooks

`config.hooks` — same set as `unjwt/session`: `onRead`, `onUpdate`, `onClear`, `onExpire`, `onError`, plus `onVerifyKeyLookup` (JWS) / `onUnsealKeyLookup` (JWE) for key rotation. The two lookups receive `context` only when the token came through `use()` (typed `context?: SessionContext`); `open()` passes none. A throw from a lookup fails the token: `onError` (`ERR_SESSION_TOKEN_INVALID`) on `use()`, a throw from `open()`.

> These are unjwt **session hooks** (`config.hooks.*`), unrelated to Elysia's request **lifecycle hooks** (`onRequest`, `beforeHandle`, …).

Each hook receives `{ session, context, config }` — `context` is the Elysia context (not an `event`). Guarantees (the same as on `unjwt/session`):

- `onRead` / `onExpire` / `onError` are mutually exclusive per incoming token. `onRead` fires once per request, when the session is read from its token; later reads in the request are silent.
- `session` in `onRead`, `onUpdate` and `onError` is the manager (`update()`, `clear()`); `oldSession` is a snapshot. `onUpdate` carries `trigger: "update" | "rolling"`.
- `rolling: true | ExpiresIn` reissues a session on read so `exp` slides: every read, or once the token is that old (needs `maxAge`, duration shorter than it).
- Every hook is dispatched with the session state already settled, so a hook may call `definition.use(context)` again on the same context and gets the same session.
- `onExpire` receives the expired token's decoded claims via `error.cause` (`jti`/`iat`/`exp`), so `session.id` is available. The session cookie is removed and `session.token` reset before it fires.
- `onUpdate` fires after every successful sign/seal and cookie write (including data-less token refresh) with a deep-cloned `oldSession`. A hook that throws makes `update()` reject with its error while the new session stays in place — no rollback, no `onError`.
- `onError` fires on read-path failures other than expiry, and on write-path sign/seal or cookie write failures (with `session.data` rolled back). A read-path `error` is always an `ERR_SESSION_TOKEN_INVALID` `JWTError` whose `cause` is the failure underneath.

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
import { defineJWSSession } from "unjwt/adapters/elysia";

const useSession = defineJWSSession({ key, maxAge: "1h" });

new Elysia()
  .resolve(async ({ cookie, request }) => ({
    session: await useSession.use({ cookie, request }),
  }))
  .get("/me", ({ session }) => session.data);
```

**Must destructure `{ cookie, request }`** in the `resolve` signature. Elysia provisions context fields by statically scanning the hook source; passing an opaque `ctx` means `cookie` is never referenced there and stays `undefined` at runtime. A `cookie` object that holds no reactive cookie throws `ERR_SESSION_CONFIG_INVALID` on the first write, naming the jar contract.

## Issuing and opening tokens

`issue()` and `open()` need no request — magic links, email verification, tokens handed over outside a cookie:

```ts
const magicLink = defineJWESession({ key, maxAge: "15m", cookie: false, sessionHeader: false });

const token = await magicLink.issue({ email: "a@example.com" }); // options: { maxAge }
const { id, data, expiresAt } = await magicLink.open(token);
```

- `issue(data, { maxAge })` strips `jti`/`iat`/`exp`/`nbf` from `data`; a `__proto__`, `constructor` or `prototype` key throws `ERR_INVALID_OPTION`. No cookie is written.
- `open(token)` resolves to `{ id, createdAt, expiresAt, data }` (`id` and `createdAt` always set), applies the cookie-read checks (`typ`, pinned algorithms, `jti`/`iat`, `exp` with `maxAge`) and throws `ERR_SESSION_TOKEN_INVALID` (failure as `cause`) or `ERR_JWT_EXPIRED`. `onVerifyKeyLookup` / `onUnsealKeyLookup` get the header and the config, no `context`.

## Notes / gotchas

- `jwsSession`/`jweSession` (and `plugin()`) return an explicitly-typed Elysia plugin (`SessionPlugin<Resolved, GuardName>` in `src/adapters/elysia/_internal/plugin.ts`) so the package satisfies `isolatedDeclarations`; the factory body is cast `as unknown as SessionPlugin<…>` because Elysia's `.macro()` expects literal keys while the guard key is computed.
- The session lifecycle is the shared core in `src/session/_internal/core.ts`, over the JWS/JWE codec and the Elysia driver in `src/adapters/elysia/_internal/shared.ts` (reactive-jar cookie writes, token reading), so hooks, error codes and claim handling match `unjwt/session` exactly.
- Build: the adapter is an input of the single multi-input bundle (shared core in `dist/_chunks/`, `elysia` external, `unsecure` inlined) — no core duplication.
- Testable in vitest+Node via `app.handle(new Request(...))`; no Bun required.
