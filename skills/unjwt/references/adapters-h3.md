# H3 Session Adapters Reference

JWT-based session management for H3 (Nuxt/Nitro). Available for both H3 v1 and v2.

Import paths:

- `unjwt/adapters/h3` — aliases to h3v1 (will switch to h3v2 in a future breaking change)
- `unjwt/adapters/h3v1` — H3 v1 (Nuxt v4, Nitro v2)
- `unjwt/adapters/h3v2` — H3 v2 (Nuxt v5, Nitro v3)

All three export the same API. Each also re-exports: `generateJWK`, `importPEM`, `exportPEM`, `deriveJWKFromPassword`.

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
  `ERR_SESSION_CONFIG_INVALID`.
- **Reserved claims.** `jti`, `iat`, `exp` and `nbf` are adapter-owned. They are stripped
  from every `update()` payload (object and updater-function form alike) and never read
  back out of `session.data`. A token's lifetime comes only from `maxAge` — on the config,
  or on one call via `session.update(data, { maxAge })`. A `__proto__`, `constructor` or
  `prototype` key in an update throws `ERR_INVALID_OPTION`.
- **Foreign tokens.** An incoming token is only a session when it carries
  `cty: "application/json"`; with `maxAge` set it must also carry `exp`, and its `iat` must
  fall within `maxAge` (`maxTokenAge`). Anything else is `ERR_SESSION_TOKEN_INVALID`, whose
  `cause` is the failure underneath.
- **Token source.** The cookie is read first; the session header is consulted only when the
  cookie carries no token. A present-but-empty or whitespace-only header never hides the
  cookie, and the `Bearer ` prefix is matched case-insensitively. `cookie: false` plus
  `sessionHeader: false` throws `ERR_SESSION_CONFIG_INVALID` on first use.

## Cookie chunking

A token longer than `cookie.chunkMaxLength` (default 4000) is split: the base cookie holds
`__chunked__<count>` and the parts follow as `<name>.1` … `<name>.<count>`, up to 16 chunks
(beyond which the write throws `ERR_SESSION_CONFIG_INVALID`). h3 v1 and h3 v2 write the same
layout — h3 v2 through h3's own `setChunkedCookie`, h3 v1 through the adapter's port over
`setCookie` — as does the Elysia adapter, so a cookie written by any of them is readable by
the others. Cleanup of a previous chunk set is bounded by the same 16-chunk limit, so a
forged marker cannot inflate the number of `Set-Cookie` headers on a response.

## Error codes

Every error the adapters throw is a `JWTError`:

| Code                         | Raised when                                                               |
| ---------------------------- | ------------------------------------------------------------------------- |
| `ERR_SESSION_TOKEN_INVALID`  | incoming token failed verification/decryption; `cause` is the original    |
| `ERR_SESSION_READONLY_EVENT` | `update()` / `clear()` on an event with no writable response              |
| `ERR_SESSION_KEY_INVALID`    | `key` missing, a password string, or the wrong shape                      |
| `ERR_SESSION_CONFIG_INVALID` | config combination that cannot work (no token source, unpinned CryptoKey) |
| `ERR_INVALID_OPTION`         | `update()` handed a `__proto__` / `constructor` / `prototype` key         |
| `ERR_JWT_EXPIRED`            | the token's `exp` has passed — surfaced through `onExpire`                |

## Drift from h3 core sessions

Forked from h3's `useSession`, then deliberately diverged:

- **Every `update()` issues a new JWT** — fresh `jti`, `iat`, `exp`. RFC 7519: `jti` names one
  token, `iat` is that token's issue time. h3 keeps `id`/`createdAt` for the session's life;
  unjwt does not, so a rotated token stays distinguishable from a compromised one.
- **`maxAge` counts from the latest issue**, not first creation. Lineage across rotations is
  the application's job (e.g. record the previous `jti` in `onUpdate`).
- **No `idleTimeout` / `lastSeenAt`.** Sliding expiration = `session.update()` from `onRead`
  when `expiresAt - Date.now()` is under the app's threshold.
- **Lazy first cookie**, `onExpire`/`onError` instead of silent replacement, hooks, `Bearer `
  prefix on the session header, JWS cookies default `httpOnly: false`.
- **`clear()` is final for the request.** The context slot is left holding an empty session,
  so a later `useSession`/`getSession` on the same event does not restore the request cookie.
- **h3 v2 error responses** get the session `Set-Cookie` mirrored into `res.errHeaders`
  (same as upstream), so throwing after `update()`/`clear()` still reaches the client.

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
  Partial<SessionData<T>> | ((oldData: SessionData<T>) => Partial<SessionData<T>> | undefined);

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
    | { privateKey: JWK_Private | JWK_Symmetric | CryptoKey; publicKey?: JWK_Public | CryptoKey };
  maxAge?: MaxAge;
  name?: string; // cookie name (default: "h3-jwe")
  cookie?: false | (CookieSerializeOptions & { chunkMaxLength?: number });
  sessionHeader?: false | string; // header to read token from
  generateId?: () => string; // default: crypto.randomUUID()
  jwe?: {
    // Options passed through to `encrypt()`; `expiresIn` is managed via `maxAge`
    // and cannot be overridden here.
    encryptOptions?: JWEEncryptOptions;
    // JWEDecryptOptions minus the fields the adapter owns: algorithms,
    // encryptionAlgorithms, typ, validateClaims, forceUint8Array. So
    // minIterations / maxIterations / clockTolerance / issuer / audience are
    // settable. With a PBES2 `alg` pinned, `maxIterations` defaults to the
    // `p2c` the session itself mints.
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
  name?: string; // default: "h3-jws"
  cookie?: false | (CookieSerializeOptions & { chunkMaxLength?: number });
  sessionHeader?: false | string;
  generateId?: () => string;
  jws?: {
    // Options passed through to `sign()`; `expiresIn` is managed via `maxAge`
    // and cannot be overridden here.
    signOptions?: JWSSignOptions;
    verifyOptions?: JWTClaimValidationOptions;
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
  /** Fires once per request when a valid session token was decoded and loaded. */
  onRead?: (args: {
    // `id` and `token` are narrowed to `string` — they are guaranteed present
    // once the token has been successfully read.
    session: SessionJWS<T, MaxAge> & { id: string; token: string };
    event: TEvent;
    config: SessionConfigJWS<T, MaxAge, TEvent>;
  }) => void | Promise<void>;

  /** Fires after a successful sign — receives the new session and a snapshot of the old one. */
  onUpdate?: (args: {
    session: SessionJWS<T, MaxAge> & { id: string; token: string };
    oldSession: SessionJWS<T, MaxAge>;
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
    session: SessionJWS<T, MaxAge>;
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
    session: SessionJWE<T, MaxAge> & { id: string; token: string };
    event: TEvent;
    config: SessionConfigJWE<T, MaxAge, TEvent>;
  }) => void | Promise<void>;

  onUpdate?: (args: {
    session: SessionJWE<T, MaxAge> & { id: string; token: string };
    oldSession: SessionJWE<T, MaxAge>;
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

| Hook       | When it fires                                                                                                                               | Mutually exclusive with |
| ---------- | ------------------------------------------------------------------------------------------------------------------------------------------- | ----------------------- |
| `onRead`   | Token decoded successfully (`id` and `token` set)                                                                                           | `onExpire`, `onError`   |
| `onUpdate` | After seal/sign succeeds                                                                                                                    | —                       |
| `onClear`  | After explicit `session.clear()` call                                                                                                       | `onExpire`              |
| `onExpire` | Token's `exp` claim is in the past                                                                                                          | `onRead`, `onClear`     |
| `onError`  | Token verification/decryption fails (non-expiry) — always an `ERR_SESSION_TOKEN_INVALID` `JWTError` whose `cause` is the underlying failure | `onRead`                |

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
const key = await deriveJWKFromPassword(process.env.SESSION_SECRET!, "PBES2-HS256+A128KW", {
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

const refreshKey = await deriveJWKFromPassword(process.env.REFRESH_SECRET!, "PBES2-HS256+A128KW", {
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
