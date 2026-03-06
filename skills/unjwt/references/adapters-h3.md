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
interface SessionManager<T, ConfigMaxAge> {
  readonly id: string | undefined; // from jti — undefined until update() is called
  readonly createdAt: number; // from iat, in ms
  readonly expiresAt: number | undefined; // from exp, in ms (set when maxAge is configured)
  readonly data: SessionData<T>; // session payload (excludes jti/iat/exp)
  readonly token: string | undefined; // current raw JWT token
  update(data: SessionUpdate<T>): Promise<SessionManager>;
  clear(): Promise<SessionManager>;
}

// SessionUpdate can be a partial object or an updater function
type SessionUpdate<T> =
  | Partial<SessionData<T>>
  | ((old: SessionData<T>) => Partial<SessionData<T>> | undefined);
```

**Key behavior:** Sessions are lazy — `id` is `undefined` until `session.update()` is called. This is intentional for OAuth/spec-compliant flows.

## useJWESession / useJWSSession

High-level session helpers. Use these for most cases.

```ts
const session = await useJWESession<MyData>(event, config);
const session = await useJWSSession<MyData>(event, config);
```

### SessionConfigJWE

```ts
interface SessionConfigJWE<T, MaxAge> {
  key: string | JWK_Symmetric | { privateKey: JWK_Private | JWK_Symmetric; publicKey?: JWK_Public };
  maxAge?: ExpiresIn;            // session lifetime (seconds or string: "1h", "7D", etc.)
  name?: string;                 // cookie name (default: "h3-jwe")
  cookie?: false | CookieSerializeOptions & { chunkMaxLength?: number };
  sessionHeader?: false | string; // header to read token from (default: "x-{name}-session")
  generateId?: () => string;     // default: crypto.randomUUID()
  jwe?: { encryptOptions?: ...; decryptOptions?: ... };
  hooks?: SessionHooksJWE<T, MaxAge>;
}
```

### SessionConfigJWS

```ts
interface SessionConfigJWS<T, MaxAge> {
  key: JWK_Symmetric | { privateKey: JWK_Private; publicKey: JWK_Public | JWK_Public[] | JWKSet };
  maxAge?: ExpiresIn;
  name?: string;                 // default: "h3-jws"
  cookie?: false | CookieSerializeOptions & { chunkMaxLength?: number };
  sessionHeader?: false | string;
  generateId?: () => string;
  jws?: { signOptions?: ...; verifyOptions?: ... };
  hooks?: SessionHooksJWS<T, MaxAge>;
}
```

## Lifecycle Hooks

Both adapters support these hooks:

```ts
interface SessionHooks<T, MaxAge> {
  onRead?(args: { session; event; config }): void | Promise<void>;
  onUpdate?(args: { session; oldSession; event; config }): void | Promise<void>;
  onClear?(args: { session; event; config }): void | Promise<void>;
  onExpire?(args: { event; error; config }): void | Promise<void>;
  onError?(args: { event; error; config }): void | Promise<void>;
}
```

JWE additionally has `onUnsealKeyLookup?(args: { header, event, config }) => JWK_Symmetric | JWK_Private`
JWS additionally has `onVerifyKeyLookup?(args: { header, event, config }) => JWKSet | JWK_Symmetric | JWK_Public`

These allow dynamic key rotation / multi-key verification.

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

### Refresh token pattern

```ts
const jwsConfig = {
  key: atKeys,
  maxAge: "15m",
  hooks: {
    async onExpire({ event, config }) {
      const refresh = await getJWESession(event, rtConfig);
      if (refresh.data.sub) {
        await updateJWSSession(event, config, { sub: refresh.data.sub });
      }
    },
  },
} satisfies SessionConfigJWS;
```
