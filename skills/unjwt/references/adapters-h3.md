# H3 Session Adapters Reference

JWT-based session management for H3 (Nuxt/Nitro). Available for both H3 v1 and v2.

Import paths:

- `unjwt/adapters/h3` — resolves to h3v2
- `unjwt/adapters/h3v1` — H3 v1 (Nuxt v4, Nitro v2)
- `unjwt/adapters/h3v2` — H3 v2 (Nuxt v5, Nitro v3)

All three export the same API: `defineJWSSession`, `defineJWESession` and their types (`SessionDefinition`, `SessionManager`, `OpenedSessionState`, `SessionConfigJWS`, `SessionConfigJWE`, …). Each also re-exports: `generateJWK`, `thumbprint`, `importPEM`, `exportPEM`, `deriveJWKFromPassword`, and the session option types `SessionSignOptions`, `SessionVerifyOptions`, `SessionEncryptOptions`, `SessionDecryptOptions`.

Peer dep: `h3`

## JWE vs JWS

|                 | JWE (Encrypted)                                 | JWS (Signed)                                     |
| --------------- | ----------------------------------------------- | ------------------------------------------------ |
| Data visibility | Encrypted, not readable by client               | Base64URL-encoded, readable by anyone            |
| Default cookie  | `httpOnly: true, secure: true, sameSite: "lax"` | `httpOnly: false, secure: true, sameSite: "lax"` |
| Key types       | Symmetric JWK, asymmetric keypair, `CryptoKey`  | Symmetric JWK, asymmetric keypair, `CryptoKey`   |
| Use when        | Session data is sensitive                       | Data is non-sensitive, clients need to read it   |

## Security notes

- **Pin algorithms.** Set `jws.signOptions.alg` (JWS) or `jwe.encryptOptions.alg` + `enc`
  (JWE) in the session config: signing/sealing uses them, and verification/unsealing then
  accepts only those values. Without them, accepted algorithms are inferred from the key's
  metadata.
- **Key material only.** `key` is a JWK, a `{ privateKey, publicKey }` pair, or a
  `CryptoKey`. A password string throws `ERR_SESSION_KEY_INVALID` — derive a JWK once with
  `deriveJWKFromPassword()`. A `CryptoKey` carries no algorithm, so it also requires
  `jws.signOptions.alg` (or `jwe.encryptOptions.alg` + `enc`), else
  `ERR_SESSION_CONFIG_INVALID`. A configured JWK is imported when the session is opened: one the
  session cannot use (undecodable `k`, wrong AES key length for its `alg`) throws
  `ERR_SESSION_KEY_INVALID` (import failure as `cause`) instead of reaching `onError`.
  A pair half that is not the half it is named after — for a JWS `publicKey` list or set, any
  entry that is not a public JWK — throws `ERR_SESSION_KEY_INVALID` naming `"privateKey"` or
  `"publicKey"`. A `protectedHeader.kid` in the issue options wins over the key's own `kid`.
- **Reserved claims.** `jti`, `iat`, `exp` and `nbf` are adapter-owned. They are stripped
  from every `update()` payload (object and updater-function form alike), dropped from
  `session.data` on every issue even when written there directly, and never read back out
  of `session.data`. An incoming token whose `iat` is later than now plus `clockTolerance`
  is refused (`ERR_SESSION_TOKEN_INVALID`) whether or not a `maxAge` is set. A token's lifetime comes only from `maxAge` — on the config,
  or on one call via `session.update(data, { maxAge })`. Update data that is not a plain object
  (a string, an array), or a `__proto__`, `constructor` or `prototype` key in it, throws
  `ERR_INVALID_OPTION`. Data travels as JSON: the writing request keeps the values as given,
  later reads get their JSON round trip (`Date` → ISO string, `NaN`/`±Infinity` → `null`,
  `undefined` members dropped).
- **Foreign tokens.** An incoming token is only a session when it carries the session `typ`
  (`signOptions.protectedHeader.typ` / `encryptOptions.protectedHeader.typ`, default
  `"session+jwt"`, compared as a media type; RFC 8725 §3.11). No `cty` is written or required.
  With `maxAge` set it must also carry `exp`. That `exp` alone bounds
  its life (no `maxTokenAge`), so a token issued with `update(data, { maxAge })` keeps its own
  lifetime past the config's `maxAge`. Anything else is `ERR_SESSION_TOKEN_INVALID`, whose
  `cause` is the failure underneath — an expired token that is not a session included, so it
  reaches `onError`, never `onExpire`.
- **Token source.** The cookie is read first; the session header is consulted only when the
  cookie carries no token. The header carries the bare token or `Bearer <token>` (scheme
  case-insensitive); any other value — blank, another scheme such as `Basic …`, a `Bearer` with
  no token — carries none, so it never hides the cookie nor reaches `onError`. A `sessionHeader`
  that is not a header name (RFC 7230 token) throws `ERR_SESSION_CONFIG_INVALID` when the
  session is opened. `sessionHeader: true` names `x-<name>-session`; left unset, a session with
  cookies still reads that header, and so does one with `cookie: false`. `cookie: false` plus
  `sessionHeader: false` is a token-only session: `use()` and `token()` throw
  `ERR_SESSION_CONFIG_INVALID`, while `issue()` and `open()` work (magic links, email
  verification). Once `clear()` has written its deletion, `token(event)` returns `undefined` for
  the rest of the request, header token included.
- **Cookie lifetime.** A session with a lifetime (config `maxAge` or `update(data, { maxAge })`)
  sets the cookie's `expires` to the token's `exp` and drops a configured `cookie.maxAge`
  (`Max-Age` beats `Expires`, RFC 6265 §5.3). Without a lifetime, `cookie.expires` /
  `cookie.maxAge` are written as configured.
  `clear()` and an expired read write `Max-Age=0` plus an epoch `Expires` on the cookie and every
  chunk.
- **Names.** Prefer a `__Host-` name (`"__Host-session"`): every adapter reads the first cookie
  of a name, so a sibling subdomain could otherwise plant one that shadows the session; the
  defaults (`secure`, `path: "/"`, no `domain`) satisfy the prefix, and the prefix rules are
  enforced when the session is opened, on every adapter: a `__Host-` name with `domain`, a `path` other than
  `/` or `secure: false`, or a `__Secure-` name with `secure: false`, throws
  `ERR_SESSION_CONFIG_INVALID` (RFC 6265bis §4.1.3). The default session header
  drops a `__Host-` / `__Secure-` prefix: `"__Host-session"` reads `x-session-session`. A name ending in a dot and
  digits (`app.1`) spells a chunk cookie of another session and throws
  `ERR_SESSION_CONFIG_INVALID`.

## Cookie chunking

A token longer than `cookie.chunkMaxLength` (default 4000) is split: the base cookie holds
`__chunked__<count>` and the parts follow as `<name>.1` … `<name>.<count>`, up to 16 chunks
(beyond which the write throws `ERR_SESSION_CONFIG_INVALID`). h3 v1 and h3 v2 write the same
layout — h3 v2 and h3 v1 each through the adapter's own chunk layer
(`src/adapters/_chunked-cookie.ts`) over that h3 version's `setCookie` — as does the Elysia adapter, so a cookie written by any of them is readable by
the others. Cleanup of a previous chunk set is bounded by the same 16-chunk limit, so a
forged marker cannot inflate the number of `Set-Cookie` headers on a response. The previous
set is the one the response already wrote, else the request's, so a set that shrinks within one
request expires the chunks it no longer uses.

## Error codes

Every error the adapters throw is a `JWTError`:

| Code                         | Raised when                                                                                  |
| ---------------------------- | -------------------------------------------------------------------------------------------- |
| `ERR_SESSION_TOKEN_INVALID`  | incoming token failed verification/decryption; `cause` is the original                       |
| `ERR_SESSION_READONLY_EVENT` | `update()` on an event that takes no cookie; `update()`/`clear()` once the response was sent |
| `ERR_SESSION_KEY_INVALID`    | `key` missing, a password string, the wrong shape, or not importable                         |
| `ERR_SESSION_CONFIG_INVALID` | config combination that cannot work (no token source, unpinned CryptoKey)                    |
| `ERR_INVALID_OPTION`         | `update()` data not a plain object, or a `__proto__`-like key in it                          |
| `ERR_JWT_EXPIRED`            | the token's `exp` has passed — surfaced through `onExpire`                                   |

## Drift from h3 core sessions

Forked from h3's `useSession`, then deliberately diverged:

- **Every `update()` issues a new JWT** — fresh `jti`, `iat`, `exp`. RFC 7519: `jti` names one
  token, `iat` is that token's issue time. h3 keeps `id`/`createdAt` for the session's life;
  unjwt does not, so a rotated token stays distinguishable from a compromised one.
- **`maxAge` counts from the latest issue**, not first creation. Lineage across rotations is
  the application's job (e.g. record the previous `jti` in `onUpdate`).
- **No `idleTimeout` / `lastSeenAt`.** Sliding expiration = `rolling: true` (reissue on every
  read) or `rolling: "15m"` (reissue once less than that remains); needs `maxAge`.
- **Lazy first cookie**, `onExpire`/`onError` instead of silent replacement, hooks, `Bearer `
  prefix on the session header, JWS cookies default `httpOnly: false`.
- **`clear()` is final for the request.** The context slot is left holding an empty session,
  so a later `use(event)` on the same event does not restore the request cookie.
- **h3 v2 error responses** get the session `Set-Cookie` mirrored into `res.errHeaders`
  (same as upstream), so throwing after `update()`/`clear()` still reaches the client — unless
  an app-level `onError` returns a `Response` of its own, which h3 sends without `res.errHeaders`.
- **After the response is sent** (`res.headersSent` / `res.writableEnded`): `update()` and
  `clear()` throw `ERR_SESSION_READONLY_EVENT` (`Cannot update/clear session: the response was
  already sent.`) and leave the session as it was — on h3 v1, and
  on h3 v2 under Node (`event.runtime.node.res`). Other h3 v2 runtimes expose no such signal, so
  a write made after the response was built is accepted but never sent: write inside the
  handler, before it returns. A read after the response was sent only observes: an expired
  token reaches `onExpire` without its cookie being dropped and `rolling` does not reissue;
  the next request, carrying the same token, does both.

Both h3 adapters, the Elysia one and `unjwt/session` run the same session core
(`src/adapters/_session-core.ts`) over a JWS/JWE codec and a per-framework driver
(`session/_shared.ts`), so the lifecycle, hook order and error codes are the same everywhere;
only cookie writing, per-request state and the `res.errHeaders` staging differ per framework.

## WebSockets

Nitro hands crossws hooks a request without a response. h3 v1 (crossws 0.3): `upgrade(request)`
gets a request-like `{ url, headers, context }`, passed as is to `use(request)`; `message(peer)`
uses `use({ headers: peer.request.headers, context: peer.context })`. h3 v2 (crossws 0.4):
`upgrade(request)` gets the `Request`, passed as `use({ req: request })`; `message(peer)` uses
`use({ req: peer.request })`.

- The upgrade object takes no cookie: `update()` throws `ERR_SESSION_READONLY_EVENT`, while
  `clear()` empties the session for the rest of the connection and leaves the cookie to the next
  HTTP request. `onRead` revocation needs no gate: `if (await revoked.has(session.id)) await
  session.clear();`. A hook that needs `event.node`/`event.res` gates on `isEvent(event)` from `h3`.
- `upgrade` wraps `use()` in `try/catch` and returns `new Response(…, { status: 401 })` itself
  (also when `!session.id`): crossws rethrows anything that is not a `Response`.
- `message` is a cache hit on the upgrade's read (`onRead` does not fire again): on v1
  `peer.context` is the upgrade's context (pass `context: {}` to re-read per message); on v2
  `peer.request` is the upgrade's `Request`. The v2 `defineWebSocketHandler((event) => hooks)`
  factory hands the upgrade a full `H3Event`.
- A `cookie: false, sessionHeader: false` session is not read by `use()`; over a socket exchange
  its tokens with `open()` / `issue()` in `message`, no event involved.
- `clear()` expires the cookie, it does not invalidate the token: a copy stays valid until `exp`.
  Revocation is `onRead` plus your own store.

## SessionManager Interface

`definition.use(event)` returns a `SessionManager`:

```ts
interface SessionManager<
  T extends Record<string, any> = SessionClaims,
  ConfigMaxAge extends ExpiresIn | undefined = ExpiresIn | undefined,
> {
  readonly id: string | undefined; // from jti — undefined until update() is called
  readonly createdAt: number; // from iat, in ms
  // With a maxAge the session always has an exp → number; without one, no exp
  // unless a single update() supplies its own maxAge.
  readonly expiresAt: ConfigMaxAge extends ExpiresIn ? number : number | undefined;
  readonly data: SessionData<T>; // session payload (excludes jti/iat/exp/nbf)
  readonly token: string | undefined; // current raw JWT token
  update: (
    update?: SessionUpdate<T>,
    options?: SessionIssueOptions, // { maxAge?: ExpiresIn } — this issue only
  ) => Promise<SessionManager<T, ConfigMaxAge>>;
  clear: () => Promise<SessionManager<T, ConfigMaxAge>>;
}

// SessionUpdate can be a partial object (which gets merged) or an updater function
type SessionUpdate<T extends Record<string, any> = SessionClaims> =
  | Partial<SessionData<T>>
  | ((oldData: SessionData<T>) => Partial<SessionData<T>> | undefined);

interface SessionClaims {
  jti: string; // required
  iat: number; // required
  iss?: string;
  sub?: string;
  aud?: string | string[];
  exp?: number;
  nbf?: number;
  [propName: string]: unknown;
}

type SessionData<T extends Record<string, any> = SessionClaims> = {
  [K in keyof T as K extends "jti" | "iat" | "exp" | "nbf" ? never : K]: T[K];
};

interface SessionIssueOptions {
  /** Lifetime for this issue only, overriding the config's `maxAge`. */
  maxAge?: ExpiresIn;
}

interface SessionJWS<
  T extends Record<string, any> = SessionClaims,
  MaxAge extends ExpiresIn | undefined = ExpiresIn | undefined,
> {
  id: string | undefined;
  createdAt: number;
  expiresAt: MaxAge extends ExpiresIn ? number : number | undefined;
  data: SessionData<T>;
  token: string | undefined;
}

interface SessionJWE<
  T extends Record<string, any> = SessionClaims,
  MaxAge extends ExpiresIn | undefined = ExpiresIn | undefined,
> {
  id: string | undefined;
  createdAt: number;
  expiresAt: MaxAge extends ExpiresIn ? number : number | undefined;
  data: SessionData<T>;
  token: string | undefined;
}
```

> `TEvent` is the event `use()` accepts and every hook receives. It defaults to its bound, `HTTPEvent` on v2 and `CompatEvent | H3Event` on v1 (signatures below show v2), because a definition is written once and cannot know which handlers call `use()`. Narrow it to `H3Event` (third generic) only in a project that never passes anything else; a Nuxt project narrows instead in a `useSession(event: H3Event)` wrapper around `definition.use(event)`.

**Key behavior:** Sessions are lazy — `id` is `undefined` until `session.update()` is called.

## defineJWESession / defineJWSSession

Define a session once, at module scope, from its config; nothing is validated or read until a
member runs. `use(event)` serves every request.

```ts
const useSession = defineJWESession<MyData>(config); // or defineJWSSession

app.get("/me", async (event) => {
  const session = await useSession.use(event);
  return session.data;
});
```

### SessionDefinition

```ts
function defineJWSSession<
  T extends Record<string, any> = SessionClaims,
  MaxAge extends ExpiresIn | undefined = ExpiresIn | undefined,
  TEvent extends HTTPEvent = HTTPEvent,
>(config: SessionConfigJWS<T, MaxAge, TEvent>): SessionDefinition<TEvent, T, MaxAge>;
// defineJWESession: same shape over SessionConfigJWE

interface SessionDefinition<TContext, T, MaxAge> {
  /** Reads the request's session once and returns its manager; later calls on the same request share that state. */
  use: (context: TContext) => Promise<SessionManager<T, MaxAge>>;
  /** The token the request carries (this response's own write first), unopened. */
  token: (context: TContext) => string | undefined;
  /** Mints a token for `data` with a fresh `jti` and `iat`, and `exp` from `maxAge` (`options.maxAge` overrides it); reads and writes nothing. */
  issue: (data?: Partial<SessionData<T>>, options?: SessionIssueOptions) => Promise<string>;
  /** Opens a token into session state, checking `typ`, pinned algorithms, `jti`/`iat` and `exp` when `maxAge` is set; the key-lookup hook receives no request. */
  open: (token: string) => Promise<OpenedSessionState<T, MaxAge>>;
}

/** What `open()` resolves to: `id` and `createdAt` always set, `expiresAt` a number with `maxAge`. */
type OpenedSessionState<T, MaxAge> = {
  id: string;
  createdAt: number;
  expiresAt: MaxAge extends ExpiresIn ? number : number | undefined;
  data: SessionData<T>;
};
```

| Member                  | Reads request | Writes cookie                                     | Hooks                                                |
| ----------------------- | ------------- | ------------------------------------------------- | ---------------------------------------------------- |
| `use(event)`            | once          | on `update()`/`clear()`, `rolling`, expired token | `onRead`/`onExpire`/`onError`, `onUpdate`, `onClear` |
| `token(event)`          | yes           | no                                                | none                                                 |
| `issue(data, options?)` | no            | no                                                | none                                                 |
| `open(token)`           | no            | no                                                | key lookup only, without `event`                     |

- `use(event)`: two calls on one request (same family and `name`) share one state, whatever
  definition they come from.
- `token(event)`: cookie this response wrote, then request cookie (chunks joined), then the
  session header; `undefined` without one; checks nothing.
- `issue(data, { maxAge })`: no request needed, works on a token-only config; reserved claims
  `jti`/`iat`/`exp`/`nbf` are stripped from `data`, a `__proto__`/`constructor`/`prototype` key
  throws `ERR_INVALID_OPTION`; writes no cookie, fires no hook.
- `open(token)`: same checks as reading a cookie; resolves to `{ id, createdAt, expiresAt, data }`;
  throws `ERR_SESSION_TOKEN_INVALID` (`cause` the failure) or `ERR_JWT_EXPIRED`;
  `onVerifyKeyLookup` / `onUnsealKeyLookup` get the header and the config, no `event`. Writes
  nothing.

### SessionConfigJWE

```ts
interface SessionConfigJWE<
  T extends Record<string, any> = SessionClaims,
  MaxAge extends ExpiresIn | undefined = ExpiresIn | undefined,
  TEvent extends HTTPEvent = HTTPEvent,
> {
  key:
    | CryptoKey // requires jwe.encryptOptions.alg + enc
    | JWK_Symmetric // symmetric JWK
    // each half must be key material of its own side, else ERR_SESSION_KEY_INVALID
    | { privateKey: JWK_Private | CryptoKey; publicKey: JWK_Public | CryptoKey };
  maxAge?: MaxAge;
  /** Reissue on read so `exp` slides: `true` every request, a duration once less than that remains. Needs `maxAge`. */
  rolling?: true | ExpiresIn;
  name?: string; // cookie name (default: "h3-jwe")
  cookie?: false | (CookieSerializeOptions & { chunkMaxLength?: number });
  sessionHeader?: boolean | string; // header to read token from; true = x-<name>-session
  generateId?: () => string; // default: crypto.randomUUID()
  jwe?: {
    // Options passed through to `encrypt()`; `exp` comes from `maxAge` and a
    // session writes no `nbf`, so expiresIn / expiresAt / notBeforeIn /
    // notBeforeAt are not accepted here. `protectedHeader.typ` sets the
    // session `typ` (default "session+jwt") that incoming tokens must carry.
    encryptOptions?: SessionEncryptOptions;
    // JWEDecryptOptions minus the fields the adapter owns: algorithms,
    // encryptionAlgorithms, typ, maxTokenAge, validateClaims, payload. So
    // minIterations / maxIterations / clockTolerance / issuer / audience are
    // settable. When the session is PBES2 — a pinned PBES2 `alg`, or a
    // configured `key` carrying one, whatever an `onUnsealKeyLookup` hook
    // returns — `maxIterations` defaults to the `p2c` the session itself mints.
    decryptOptions?: SessionDecryptOptions;
  };
  hooks?: SessionHooksJWE<T, MaxAge, TEvent>;
}
```

### SessionConfigJWS

```ts
interface SessionConfigJWS<
  T extends Record<string, any> = SessionClaims,
  MaxAge extends ExpiresIn | undefined = ExpiresIn | undefined,
  TEvent extends HTTPEvent = HTTPEvent,
> {
  key:
    | CryptoKey // requires jws.signOptions.alg
    | JWK_Symmetric
    | {
        privateKey: JWK_Private | CryptoKey;
        publicKey: JWK_Public | JWK_Public[] | JWKSet | CryptoKey;
      };
  maxAge?: MaxAge;
  /** Reissue on read so `exp` slides: `true` every request, a duration once less than that remains. Needs `maxAge`. */
  rolling?: true | ExpiresIn;
  name?: string; // default: "h3-jws"
  cookie?: false | (CookieSerializeOptions & { chunkMaxLength?: number });
  sessionHeader?: boolean | string;
  generateId?: () => string;
  jws?: {
    // Options passed through to `sign()`; `exp` comes from `maxAge` and a
    // session writes no `nbf`, so expiresIn / expiresAt / notBeforeIn /
    // notBeforeAt are not accepted here. `protectedHeader.typ` sets the
    // session `typ` (default "session+jwt") that incoming tokens must carry.
    signOptions?: SessionSignOptions;
    /** JWSVerifyOptions the adapter does not own (`limits`, `allowSymmetricJWKSet`, claim checks) — not algorithms, typ, maxTokenAge, validateClaims, payload. */
    verifyOptions?: SessionVerifyOptions;
  };
  hooks?: SessionHooksJWS<T, MaxAge, TEvent>;
}
```

## Lifecycle Hooks

### Hook interfaces

```ts
interface SessionHooksJWS<
  T extends Record<string, any> = SessionClaims,
  MaxAge extends ExpiresIn | undefined = ExpiresIn | undefined,
  TEvent extends HTTPEvent = HTTPEvent,
> {
  /** Fires once per request, when the session is read from a valid token. `session` is the manager. */
  onRead?: (args: {
    // `id` and `token` are narrowed to `string` — they are guaranteed present
    // once the token has been successfully read.
    session: SessionManager<T, MaxAge> & { id: string; token: string };
    event: TEvent;
    config: SessionConfigJWS<T, MaxAge, TEvent>;
  }) => void | Promise<void>;

  /** Fires after a successful sign, by `update()` or by `rolling` — the live manager and a snapshot of the old state. */
  onUpdate?: (args: {
    session: SessionManager<T, MaxAge> & { id: string; token: string };
    oldSession: SessionJWS<T, MaxAge>;
    trigger: "update" | "rolling";
    event: TEvent;
    config: SessionConfigJWS<T, MaxAge, TEvent>;
  }) => void | Promise<void>;

  /** Fires after explicit session termination (session.clear()). */
  onClear?: (args: {
    oldSession: SessionJWS<T, MaxAge> | undefined;
    event: TEvent;
    config: SessionConfigJWS<T, MaxAge, TEvent>;
  }) => void | Promise<void>;

  /** Fires when a token's exp has passed. Mutually exclusive with onRead and onClear. */
  onExpire?: (args: {
    session: {
      id: string | undefined; // jti from the expired token (if decodable)
      createdAt: number | undefined; // iat × 1000 ms
      expiresAt: number | undefined; // exp × 1000 ms
      token: string; // the raw expired token
    };
    event: TEvent;
    error: Error;
    config: SessionConfigJWS<T, MaxAge, TEvent>;
  }) => void | Promise<void>;

  /** Fires when token verification fails for a non-expiry reason. Mutually exclusive with onRead. */
  onError?: (args: {
    session: SessionManager<T, MaxAge>;
    event: TEvent;
    error: any;
    config: SessionConfigJWS<T, MaxAge, TEvent>;
  }) => void | Promise<void>;

  /** Override key lookup during verification (e.g. for key rotation); a throw fails the token. */
  onVerifyKeyLookup?: (args: {
    header: JWKLookupFunctionHeader;
    event?: TEvent; // only when the token came through use(); open() passes none
    config: SessionConfigJWS<T, MaxAge, TEvent>;
  }) => JWKSet | JWSVerifyJWK | Promise<JWKSet | JWSVerifyJWK>;
}

interface SessionHooksJWE<
  T extends Record<string, any> = SessionClaims,
  MaxAge extends ExpiresIn | undefined = ExpiresIn | undefined,
  TEvent extends HTTPEvent = HTTPEvent,
> {
  onRead?: (args: {
    session: SessionManager<T, MaxAge> & { id: string; token: string };
    event: TEvent;
    config: SessionConfigJWE<T, MaxAge, TEvent>;
  }) => void | Promise<void>;

  onUpdate?: (args: {
    session: SessionManager<T, MaxAge> & { id: string; token: string };
    oldSession: SessionJWE<T, MaxAge>;
    trigger: "update" | "rolling";
    event: TEvent;
    config: SessionConfigJWE<T, MaxAge, TEvent>;
  }) => void | Promise<void>;

  onClear?: (args: {
    oldSession: SessionJWE<T, MaxAge> | undefined;
    event: TEvent;
    config: SessionConfigJWE<T, MaxAge, TEvent>;
  }) => void | Promise<void>;

  onExpire?: (args: {
    session: {
      id: string | undefined;
      createdAt: number | undefined;
      expiresAt: number | undefined;
      token: string;
    };
    event: TEvent;
    error: Error;
    config: SessionConfigJWE<T, MaxAge, TEvent>;
  }) => void | Promise<void>;

  onError?: (args: {
    session: SessionManager<T, MaxAge>;
    event: TEvent;
    error: any;
    config: SessionConfigJWE<T, MaxAge, TEvent>;
  }) => void | Promise<void>;

  /** Override key lookup during decryption; a throw fails the token. */
  onUnsealKeyLookup?: (args: {
    header: JWEHeaderParameters;
    event?: TEvent; // only when the token came through use(); open() passes none
    config: SessionConfigJWE<T, MaxAge, TEvent>;
  }) => JWK_Symmetric | JWK_Private | Promise<JWK_Symmetric | JWK_Private>;
}
```

### Hook lifecycle guarantees

| Hook       | When it fires                                                                                                                                                                                                                                                                                                                            | Mutually exclusive with |
| ---------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------------- |
| `onRead`   | Once per request, when the session is read from a valid token (`id` and `token` set); later reads in the request are silent                                                                                                                                                                                                              | `onExpire`, `onError`   |
| `onUpdate` | After seal/sign and the cookie write succeed; a hook that throws makes `update()` reject with its error, the new session staying in place (no rollback, no `onError`)                                                                                                                                                                    | —                       |
| `onClear`  | After explicit `session.clear()` call                                                                                                                                                                                                                                                                                                    | `onExpire`              |
| `onExpire` | Token's `exp` claim is in the past                                                                                                                                                                                                                                                                                                       | `onRead`, `onClear`     |
| `onError`  | A read-path failure other than expiry, and a write-path sign/seal failure — the read-path `error` is always an `ERR_SESSION_TOKEN_INVALID` `JWTError` whose `cause` is the underlying failure, while the write-path `error` is the issue failure itself (e.g. `ERR_INVALID_OPTION`) and `session` is rolled back to its pre-update state | `onRead` (read path)    |

Every hook is dispatched with the session state already settled, so a hook may read the same session again — through `definition.use(event)` — and gets the same session without `onRead` firing again. `session` in `onRead`, `onUpdate` and `onError` is the manager, so `session.update()` / `session.clear()` work in place.

Key material is configuration rather than token content: a `key` the config cannot resolve into a signing and a verification key throws `ERR_SESSION_KEY_INVALID` out of `use(event)` itself, and never reaches `onError` as an unreadable token. A session `name` outside the RFC 6265 cookie-name characters is `ERR_SESSION_CONFIG_INVALID`, raised when the session is opened. So is a `name` a different family already holds on the same request: a name spells one cookie and one cookie carries one token, so a JWS and a JWE session under one name would write over each other (`'[unjwt/h3] Session name "app" is already used by a JWS session on this request; …'`). Reading the same family and name again is the same session and is always allowed.

**Important:** `onExpire` deletes the session cookie inline and resets `session.token` to `undefined` — it does **not** go through `clear()`, so `onClear` is **never** triggered by natural token expiry. These two hooks are semantically distinct: `onExpire` = lifetime ended by clock; `onClear` = explicit user/system termination.

`onExpire`'s `session.id` is populated with the `jti` from the expired token (via `JWTError.cause`) when the token was cryptographically valid but past its `exp`. Use this to look up and invalidate revocation-list entries.

## Examples

### Basic JWE session (encrypted)

```ts
import { defineJWESession, deriveJWKFromPassword } from "unjwt/adapters/h3v2";

// Derive once at boot — the adapters never take a password.
const key = await deriveJWKFromPassword(process.env.SESSION_SECRET!, {
  alg: "PBES2-HS256+A128KW",
  salt: process.env.SESSION_SALT!,
  iterations: 600_000,
});

const useSession = defineJWESession({ key, maxAge: "7D" });

app.get("/", async (event) => {
  const session = await useSession.use(event);

  if (!session.id) {
    await session.update({ userId: "123" });
  }

  return { user: session.data };
});
```

### JWS session with asymmetric keys

```ts
import { defineJWSSession, generateJWK } from "unjwt/adapters/h3v2";

const keys = await generateJWK("RS256");

const useSession = defineJWSSession({ key: keys, maxAge: "1h" });

app.get("/", async (event) => {
  const session = await useSession.use(event);
  return { data: session.data };
});
```

### Token from Authorization header

The cookie wins when it carries a token; the header is the fallback.

```ts
const apiSession = defineJWESession({
  key,
  sessionHeader: "Authorization", // "Bearer <token>" or the bare token
  cookie: false, // header-only
});

const session = await apiSession.use(event);
```

### Key rotation via hooks

```ts
const useSession = defineJWESession({
  key: currentKey,
  hooks: {
    onUnsealKeyLookup({ header }) {
      const key = header.kid === undefined ? undefined : keyStore.get(header.kid);
      // an unknown kid fails the token: onError (ERR_SESSION_TOKEN_INVALID) on use(), a throw from open()
      if (!key) throw new Error(`No session key with kid ${JSON.stringify(header.kid)}`);
      return key;
    },
  },
});
```

### Token refresh without data change

```ts
// Rotate the token (new jti/iat/exp) without touching session.data
await session.update();

// One token with a lifetime of its own
await session.update({ step: "mfa" }, { maxAge: "5m" });
```

### Revocation tracking via onExpire

```ts
const useSession = defineJWSSession({
  key: keys,
  maxAge: "1h",
  hooks: {
    async onExpire({ session }) {
      // session.id is the jti from the expired token (populated via JWTError.cause)
      if (session.id) await db.revoke(session.id);
    },
    async onClear({ oldSession }) {
      // explicit logout — mutually exclusive with onExpire
      if (oldSession?.id) await db.revoke(oldSession.id);
    },
  },
});
```

### Magic link (token-only session)

```ts
const magicLink = defineJWSSession({ key, maxAge: "15m", cookie: false, sessionHeader: false });

const token = await magicLink.issue({ email }); // no request needed
// later, in the login handler:
const { data } = await magicLink.open(token); // throws on a bad or expired token
```

### Refresh token pattern

```ts
import {
  defineJWESession,
  defineJWSSession,
  generateJWK,
  deriveJWKFromPassword,
} from "unjwt/adapters/h3v2";

const atKeys = await generateJWK("RS256");

const refreshKey = await deriveJWKFromPassword(process.env.REFRESH_SECRET!, {
  alg: "PBES2-HS256+A128KW",
  salt: process.env.REFRESH_SALT!,
  iterations: 600_000,
});

const refreshSession = defineJWESession({
  key: refreshKey,
  name: "refresh_token",
});

const accessSession = defineJWSSession({
  key: atKeys,
  name: "access_token",
  maxAge: "15m",
  hooks: {
    async onExpire({ event }) {
      const refresh = await refreshSession.use(event);
      if (refresh.data.sub) {
        const access = await accessSession.use(event);
        await access.update({
          sub: refresh.data.sub,
          scope: refresh.data.scope,
        });
      }
    },
  },
});
```
