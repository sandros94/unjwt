# H3 Session Adapters Reference

JWT-based session management for H3 (Nuxt/Nitro). Available for both H3 v1 and v2.

Import paths:

- `unjwt/adapters/h3` — aliases to h3v1 (will switch to h3v2 in a future breaking change)
- `unjwt/adapters/h3v1` — H3 v1 (Nuxt v4, Nitro v2)
- `unjwt/adapters/h3v2` — H3 v2 (Nuxt v5, Nitro v3)

All three export the same API. Each also re-exports: `generateJWK`, `thumbprint`, `importPEM`, `exportPEM`, `deriveJWKFromPassword`, and the session option types `SessionSignOptions`, `SessionVerifyOptions`, `SessionEncryptOptions`, `SessionDecryptOptions`.

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
  Tokens issued before 0.8 carry `typ: "JWT"` and are refused, so every existing session signs out once after the upgrade.
  With `maxAge` set it must also carry `exp`. That `exp` alone bounds
  its life (no `maxTokenAge`), so a token issued with `update(data, { maxAge })` keeps its own
  lifetime past the config's `maxAge`. Anything else is `ERR_SESSION_TOKEN_INVALID`, whose
  `cause` is the failure underneath — an expired token that is not a session included, so it
  reaches `onError`, never `onExpire`.
- **Token source.** The cookie is read first; the session header is consulted only when the
  cookie carries no token. The header carries the bare token or `Bearer <token>` (scheme
  case-insensitive); any other value — blank, another scheme such as `Basic …`, a `Bearer` with
  no token — carries none, so it never hides the cookie nor reaches `onError`. A `sessionHeader`
  that is not a header name (RFC 7230 token) throws `ERR_SESSION_CONFIG_INVALID` where the
  session is bound. `cookie: false` plus
  `sessionHeader: false` throws `ERR_SESSION_CONFIG_INVALID` on first use of a session manager
  and from `clearJWSSession` / `clearJWESession`;
  `signJWSSession` / `sealJWESession` accept it and issue a one-off token (fresh `jti`, no cookie).
  Once `clear()` has written its deletion, `getJWSSessionToken` / `getJWESessionToken` return
  `undefined` for the rest of the request, header token included.
- **Cookie lifetime.** A session with a lifetime (config `maxAge` or `update(data, { maxAge })`)
  sets the cookie's `expires` to the token's `exp` and drops a configured `cookie.maxAge`
  (`Max-Age` beats `Expires`, RFC 6265 §5.3). Without a lifetime, `cookie.expires` /
  `cookie.maxAge` are written as configured.
  `clear()` and an expired read write `Max-Age=0` plus an epoch `Expires` on the cookie and every
  chunk.
- **Names.** Prefer a `__Host-` name (`"__Host-session"`): every adapter reads the first cookie
  of a name, so a sibling subdomain could otherwise plant one that shadows the session; the
  defaults (`secure`, `path: "/"`, no `domain`) satisfy the prefix, and the prefix rules are
  enforced at bind time on every adapter: a `__Host-` name with `domain`, a `path` other than
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

| Code                         | Raised when                                                               |
| ---------------------------- | ------------------------------------------------------------------------- |
| `ERR_SESSION_TOKEN_INVALID`  | incoming token failed verification/decryption; `cause` is the original    |
| `ERR_SESSION_READONLY_EVENT` | `update()` / `clear()` once the response cannot take a `Set-Cookie`       |
| `ERR_SESSION_KEY_INVALID`    | `key` missing, a password string, the wrong shape, or not importable      |
| `ERR_SESSION_CONFIG_INVALID` | config combination that cannot work (no token source, unpinned CryptoKey) |
| `ERR_INVALID_OPTION`         | `update()` data not a plain object, or a `__proto__`-like key in it       |
| `ERR_JWT_EXPIRED`            | the token's `exp` has passed — surfaced through `onExpire`                |

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
  so a later `useSession`/`getSession` on the same event does not restore the request cookie.
- **h3 v2 error responses** get the session `Set-Cookie` mirrored into `res.errHeaders`
  (same as upstream), so throwing after `update()`/`clear()` still reaches the client — unless
  an app-level `onError` returns a `Response` of its own, which h3 sends without `res.errHeaders`.
- **After the response is sent** (`res.headersSent` / `res.writableEnded`): `update()` and
  `clear()` throw `ERR_SESSION_READONLY_EVENT` and leave the session as it was — on h3 v1, and
  on h3 v2 under Node (`event.runtime.node.res`). Other h3 v2 runtimes expose no such signal, so
  a write made after the response was built is accepted but never sent.

Both h3 adapters and the Elysia one run the same session core (`src/adapters/_session-core.ts`)
over a JWS/JWE codec and a per-framework port (`session/_shared.ts`), so the lifecycle, hook
order and error codes are the same everywhere; only cookie writing, context storage and the
`res.errHeaders` staging differ per framework.

## SessionManager Interface

Both `useJWESession` and `useJWSSession` return a `SessionManager`:

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

> The `TEvent` generic differs by h3 version. The blocks above (and below) show the v2 bound `TEvent extends HTTPEvent | H3Event = HTTPEvent | H3Event`. For h3v1 the bound is `TEvent extends CompatEvent | H3Event = CompatEvent | H3Event`.

**Key behavior:** Sessions are lazy — `id` is `undefined` until `session.update()` is called.

## useJWESession / useJWSSession

High-level session helpers. Use these for most cases.

```ts
const session = await useJWESession<MyData>(event, config);
const session = await useJWSSession<MyData>(event, config);
```

### SessionConfigJWE

```ts
interface SessionConfigJWE<
  T extends Record<string, any> = SessionClaims,
  MaxAge extends ExpiresIn | undefined = ExpiresIn | undefined,
  TEvent extends HTTPEvent | H3Event = HTTPEvent | H3Event,
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
  sessionHeader?: false | string; // header to read token from
  generateId?: () => string; // default: crypto.randomUUID()
  jwe?: {
    // Options passed through to `encrypt()`; `exp` comes from `maxAge` and a
    // session writes no `nbf`, so expiresIn / expiresAt / notBeforeIn /
    // notBeforeAt are not accepted here. `protectedHeader.typ` sets the
    // session `typ` (default "session+jwt") that incoming tokens must carry.
    encryptOptions?: SessionEncryptOptions;
    // JWEDecryptOptions minus the fields the adapter owns: algorithms,
    // encryptionAlgorithms, typ, validateClaims, forceUint8Array. So
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
  TEvent extends HTTPEvent | H3Event = HTTPEvent | H3Event,
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
  sessionHeader?: false | string;
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
  TEvent extends HTTPEvent | H3Event = HTTPEvent | H3Event,
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

  /** Override key lookup during verification (e.g. for key rotation). */
  onVerifyKeyLookup?: (args: {
    header: JWKLookupFunctionHeader;
    event: TEvent;
    config: SessionConfigJWS<T, MaxAge, TEvent>;
  }) => JWKSet | JWK_Symmetric | JWK_Public | Promise<JWKSet | JWK_Symmetric | JWK_Public>;
}

interface SessionHooksJWE<
  T extends Record<string, any> = SessionClaims,
  MaxAge extends ExpiresIn | undefined = ExpiresIn | undefined,
  TEvent extends HTTPEvent | H3Event = HTTPEvent | H3Event,
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
    session: SessionJWE<T, MaxAge>;
    event: TEvent;
    error: any;
    config: SessionConfigJWE<T, MaxAge, TEvent>;
  }) => void | Promise<void>;

  /** Override key lookup during decryption. */
  onUnsealKeyLookup?: (args: {
    header: JWEHeaderParameters;
    event: TEvent;
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

Every hook is dispatched with the session state already settled, so a hook may read the same session again — through `useJWSSession`/`getJWSSession` with the same config — and gets the same session without `onRead` firing again. `session` in `onRead`, `onUpdate` and `onError` is the manager, so `session.update()` / `session.clear()` work in place.

Key material is configuration rather than token content: a `key` the config cannot resolve into a signing and a verification key throws `ERR_SESSION_KEY_INVALID` out of `useJWSSession` / `getJWSSession` itself, and never reaches `onError` as an unreadable token. A session `name` outside the RFC 6265 cookie-name characters is `ERR_SESSION_CONFIG_INVALID`, raised where the session is bound. So is a `name` a different family already holds on the same request: a name spells one cookie and one cookie carries one token, so a JWS and a JWE session under one name would write over each other (`'[unjwt/h3] Session name "app" is already used by a JWS session on this request; …'`). Reading the same family and name again is the same session and is always allowed.

**Important:** `onExpire` deletes the session cookie inline and resets `session.token` to `undefined` — it does **not** call the `clearSession` function, so `onClear` is **never** triggered by natural token expiry. These two hooks are semantically distinct: `onExpire` = lifetime ended by clock; `onClear` = explicit user/system termination.

`onExpire`'s `session.id` is populated with the `jti` from the expired token (via `JWTError.cause`) when the token was cryptographically valid but past its `exp`. Use this to look up and invalidate revocation-list entries.

## Lower-Level Functions

For advanced control over the session lifecycle:

### JWE

| Function                                             | Purpose                                            |
| ---------------------------------------------------- | -------------------------------------------------- |
| `getJWESession(event, config)`                       | Read/initialize session from cookie/header         |
| `getJWESessionToken(event, config)`                  | Get raw token string from cookie/header            |
| `updateJWESession(event, config, update?, options?)` | Update data, re-encrypt, set cookie                |
| `sealJWESession(event, config)`                      | Encrypt current session to JWE token string        |
| `unsealJWESession(event, config, token)`             | Decrypt a JWE token to session data                |
| `clearJWESession(event, config)`                     | Empty the session in context and expire the cookie |

### JWS

| Function                                             | Purpose                                            |
| ---------------------------------------------------- | -------------------------------------------------- |
| `getJWSSession(event, config)`                       | Read/initialize session from cookie/header         |
| `getJWSSessionToken(event, config)`                  | Get raw token string from cookie/header            |
| `updateJWSSession(event, config, update?, options?)` | Update data, re-sign, set cookie                   |
| `signJWSSession(event, config)`                      | Sign current session to JWS token string           |
| `verifyJWSSession(event, config, token)`             | Verify a JWS token to session data                 |
| `clearJWSSession(event, config)`                     | Empty the session in context and expire the cookie |

## Examples

### Basic JWE session (encrypted)

```ts
import { useJWESession, deriveJWKFromPassword } from "unjwt/adapters/h3v2";

// Derive once at boot — the adapters never take a password.
const key = await deriveJWKFromPassword(process.env.SESSION_SECRET!, {
  alg: "PBES2-HS256+A128KW",
  salt: process.env.SESSION_SALT!,
  iterations: 600_000,
});

app.get("/", async (event) => {
  const session = await useJWESession(event, {
    key,
    maxAge: "7D",
  });

  if (!session.id) {
    await session.update({ userId: "123" });
  }

  return { user: session.data };
});
```

### JWS session with asymmetric keys

```ts
import { useJWSSession, generateJWK } from "unjwt/adapters/h3v2";

const keys = await generateJWK("RS256");

app.get("/", async (event) => {
  const session = await useJWSSession(event, {
    key: keys,
    maxAge: "1h",
  });
  return { data: session.data };
});
```

### Token from Authorization header

The cookie wins when it carries a token; the header is the fallback.

```ts
const session = await useJWESession(event, {
  key,
  sessionHeader: "Authorization", // "Bearer <token>" or the bare token
  cookie: false, // header-only
});
```

### Key rotation via hooks

```ts
const session = await useJWESession(event, {
  key: currentKey,
  hooks: {
    onUnsealKeyLookup({ header }) {
      // Try old keys for decryption based on kid
      return keyStore.get(header.kid) ?? currentKey;
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
const session = await useJWSSession(event, {
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

### Refresh token pattern

```ts
import {
  type SessionConfigJWE,
  type SessionConfigJWS,
  useJWESession,
  useJWSSession,
  getJWESession,
  updateJWSSession,
  generateJWK,
  deriveJWKFromPassword,
} from "unjwt/adapters/h3v2";

const atKeys = await generateJWK("RS256");

const refreshKey = await deriveJWKFromPassword(process.env.REFRESH_SECRET!, {
  alg: "PBES2-HS256+A128KW",
  salt: process.env.REFRESH_SALT!,
  iterations: 600_000,
});

const refreshConfig = {
  key: refreshKey,
  name: "refresh_token",
} satisfies SessionConfigJWE;

const accessConfig = {
  key: atKeys,
  name: "access_token",
  maxAge: "15m",
  hooks: {
    async onExpire({ event, config }) {
      const refresh = await getJWESession(event, refreshConfig);
      if (refresh.data.sub) {
        await updateJWSSession(event, config, {
          sub: refresh.data.sub,
          scope: refresh.data.scope,
        });
      }
    },
  },
} satisfies SessionConfigJWS;
```
