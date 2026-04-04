# H3 Session Adapters Reference

JWT-based session management for H3 (Nuxt/Nitro). Available for both H3 v1 and v2.

Import paths:

- `unjwt/adapters/h3` — aliases to h3v1 (will switch to h3v2 in a future breaking change)
- `unjwt/adapters/h3v1` — H3 v1 (Nuxt v4, Nitro v2)
- `unjwt/adapters/h3v2` — H3 v2 (Nuxt v5, Nitro v3)

All three export the same API. Each also re-exports: `generateJWK`, `importJWKFromPEM`, `exportJWKToPEM`, `deriveJWKFromPassword`.

Peer dep: `h3`

## JWE vs JWS

|                 | JWE (Encrypted)                                    | JWS (Signed)                                   |
| --------------- | -------------------------------------------------- | ---------------------------------------------- |
| Data visibility | Encrypted, not readable by client                  | Base64URL-encoded, readable by anyone          |
| Default cookie  | `httpOnly: true, secure: true`                     | `httpOnly: false, secure: true`                |
| Key types       | Password string, symmetric JWK, asymmetric keypair | Symmetric JWK, asymmetric keypair              |
| Use when        | Session data is sensitive                          | Data is non-sensitive, clients need to read it |

## SessionManager Interface

Both `useJWESession` and `useJWSSession` return a `SessionManager`:

```ts
interface SessionManager<T, ConfigMaxAge extends ExpiresIn | undefined = ExpiresIn | undefined> {
  readonly id: string | undefined;       // from jti — undefined until update() is called
  readonly createdAt: number;            // from iat, in ms
  readonly expiresAt: ConfigMaxAge extends ExpiresIn ? number : number | undefined; // from exp, in ms
  readonly data: SessionData<T>;         // session payload (excludes jti/iat/exp)
  readonly token: string | undefined;    // current raw JWT token
  update(data?: SessionUpdate<T>): Promise<SessionManager<T, ConfigMaxAge>>;
  clear(): Promise<SessionManager<T, ConfigMaxAge>>;
}

// SessionUpdate can be a partial object or an updater function
type SessionUpdate<T> =
  | Partial<SessionData<T>>
  | ((old: SessionData<T>) => Partial<SessionData<T>> | undefined);
```

**Key behavior:**
- Sessions are lazy — `id` is `undefined` until `session.update()` is called. This is intentional for OAuth/spec-compliant flows.
- `session.update()` with no argument refreshes the token (new `jti`, new `iat`/`exp`) without changing `data`.

## useJWESession / useJWSSession

High-level session helpers. Use these for most cases.

```ts
const session = await useJWESession<MyData>(event, config);
const session = await useJWSSession<MyData>(event, config);
```

### SessionConfigJWE

```ts
interface SessionConfigJWE<
  T = SessionClaims,
  MaxAge extends ExpiresIn | undefined = ExpiresIn | undefined,
  TEvent extends HTTPEvent = HTTPEvent,
> {
  key: string | JWK_Symmetric | { privateKey: JWK_Private | JWK_Symmetric; publicKey?: JWK_Public };
  maxAge?: ExpiresIn;            // session lifetime (seconds or string: "1h", "7D", etc.)
  name?: string;                 // cookie name (default: "h3-jwe")
  cookie?: false | CookieSerializeOptions & { chunkMaxLength?: number };
  sessionHeader?: false | string; // header to read token from (default: "x-{name}-session")
  generateId?: () => string;     // default: crypto.randomUUID()
  jwe?: { encryptOptions?: ...; decryptOptions?: ... };
  hooks?: SessionHooksJWE<T, MaxAge, TEvent>;
}
```

### SessionConfigJWS

```ts
interface SessionConfigJWS<
  T = SessionClaims,
  MaxAge extends ExpiresIn | undefined = ExpiresIn | undefined,
  TEvent extends HTTPEvent = HTTPEvent,
> {
  key: JWK_Symmetric | { privateKey: JWK_Private; publicKey: JWK_Public | JWK_Public[] | JWKSet };
  maxAge?: ExpiresIn;
  name?: string;                 // default: "h3-jws"
  cookie?: false | CookieSerializeOptions & { chunkMaxLength?: number };
  sessionHeader?: false | string;
  generateId?: () => string;
  jws?: { signOptions?: ...; verifyOptions?: ... };
  hooks?: SessionHooksJWS<T, MaxAge, TEvent>;
}
```

## Lifecycle Hooks

### Hook interfaces

```ts
interface SessionHooksJWS<
  T = SessionClaims,
  MaxAge extends ExpiresIn | undefined = ExpiresIn | undefined,
  TEvent extends HTTPEvent = HTTPEvent,
> {
  /** Fires once per request when a valid session token was decoded and loaded. */
  onRead?(args: {
    session: SessionJWS<T, MaxAge> & { id: string; token: string };
    event: TEvent;
    config: SessionConfigJWS<T, MaxAge, TEvent>;
  }): void | Promise<void>;

  /** Fires after a successful sign — receives the new session and a snapshot of the old one. */
  onUpdate?(args: {
    session: SessionJWS<T, MaxAge> & { id: string; token: string };
    oldSession: SessionJWS<T, MaxAge>;
    event: TEvent;
    config: SessionConfigJWS<T, MaxAge, TEvent>;
  }): void | Promise<void>;

  /** Fires after explicit session termination (session.clear()). */
  onClear?(args: {
    oldSession: SessionJWS<T, MaxAge> | undefined;
    event: TEvent;
    config: SessionConfigJWS<T, MaxAge, TEvent>;
  }): void | Promise<void>;

  /** Fires when a token's exp has passed. Mutually exclusive with onRead and onClear. */
  onExpire?(args: {
    session: {
      id: string | undefined;        // jti from the expired token (if decodable)
      createdAt: number | undefined; // iat × 1000 ms
      expiresAt: number | undefined; // exp × 1000 ms
      token: string;                 // the raw expired token
    };
    event: TEvent;
    error: JWTError;
    config: SessionConfigJWS<T, MaxAge, TEvent>;
  }): void | Promise<void>;

  /** Fires when token verification fails for a non-expiry reason. Mutually exclusive with onRead. */
  onError?(args: {
    session: SessionJWS<T, MaxAge>;
    event: TEvent;
    error: any;
    config: SessionConfigJWS<T, MaxAge, TEvent>;
  }): void | Promise<void>;

  /** Override key lookup during verification (e.g. for key rotation). */
  onVerifyKeyLookup?(args: {
    header: JWSProtectedHeader;
    event: TEvent;
    config: SessionConfigJWS<T, MaxAge, TEvent>;
  }): JWKSet | JWK_Symmetric | JWK_Public | Promise<JWKSet | JWK_Symmetric | JWK_Public>;
}

interface SessionHooksJWE<T, MaxAge, TEvent> {
  // identical shape — replace JWS-specific types with their JWE equivalents:
  onRead?(...):   // session: SessionJWE
  onUpdate?(...): // session/oldSession: SessionJWE
  onClear?(...):  // oldSession: SessionJWE | undefined
  onExpire?(...): // same { id, createdAt, expiresAt, token } snapshot + JWTError
  onError?(...):  // session: SessionJWE
  /** Override key lookup during decryption. */
  onUnsealKeyLookup?(args: {
    header: JWEHeaderParameters;
    event: TEvent;
    config: SessionConfigJWE<T, MaxAge, TEvent>;
  }): JWK_Symmetric | JWK_Private | Promise<JWK_Symmetric | JWK_Private>;
}
```

### Hook lifecycle guarantees

| Hook         | When it fires                                        | Mutually exclusive with |
| ------------ | ---------------------------------------------------- | ----------------------- |
| `onRead`     | Token decoded successfully (`id` and `token` set)    | `onExpire`, `onError`   |
| `onUpdate`   | After seal/sign succeeds                             | —                       |
| `onClear`    | After explicit `session.clear()` call                | `onExpire`              |
| `onExpire`   | Token's `exp` claim is in the past                   | `onRead`, `onClear`     |
| `onError`    | Token verification/decryption fails (non-expiry)     | `onRead`                |

**Important:** `onExpire` clears the cookie inline — it does **not** call the `clearSession` function, so `onClear` is **never** triggered by natural token expiry. These two hooks are semantically distinct: `onExpire` = lifetime ended by clock; `onClear` = explicit user/system termination.

`onExpire`'s `session.id` is populated with the `jti` from the expired token (via `JWTError.cause`) when the token was cryptographically valid but past its `exp`. Use this to look up and invalidate revocation-list entries.

## Lower-Level Functions

For advanced control over the session lifecycle:

### JWE

| Function                                   | Purpose                                       |
| ------------------------------------------ | --------------------------------------------- |
| `getJWESession(event, config)`             | Read/initialize session from cookie/header    |
| `getJWESessionToken(event, config)`        | Get raw token string from cookie/header       |
| `updateJWESession(event, config, update?)` | Update data, re-encrypt, set cookie           |
| `sealJWESession(event, config)`            | Encrypt current session to JWE token string   |
| `unsealJWESession(event, config, token)`   | Decrypt a JWE token to session data           |
| `clearJWESession(event, config)`           | Delete session from context and expire cookie |

### JWS

| Function                                   | Purpose                                       |
| ------------------------------------------ | --------------------------------------------- |
| `getJWSSession(event, config)`             | Read/initialize session from cookie/header    |
| `getJWSSessionToken(event, config)`        | Get raw token string from cookie/header       |
| `updateJWSSession(event, config, update?)` | Update data, re-sign, set cookie              |
| `signJWSSession(event, config)`            | Sign current session to JWS token string      |
| `verifyJWSSession(event, config, token)`   | Verify a JWS token to session data            |
| `clearJWSSession(event, config)`           | Delete session from context and expire cookie |

## Examples

### Basic JWE session (encrypted)

```ts
import { useJWESession } from "unjwt/adapters/h3v2";

app.get("/", async (event) => {
  const session = await useJWESession(event, {
    key: process.env.SESSION_SECRET!,
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

```ts
const session = await useJWESession(event, {
  key: secret,
  sessionHeader: "Authorization", // reads Bearer token
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
} from "unjwt/adapters/h3v2";

const atKeys = await generateJWK("RS256");

const refreshConfig = {
  key: process.env.REFRESH_SECRET!,
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
