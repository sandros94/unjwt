## H3 v2 (Nuxt v5, Nitro v3)

The `h3` adapter bundles session helpers that store data inside signed or encrypted JWTs.

> [!WARNING]
> While these adapters try to be compatible with h3's `useSession` API, the key difference is that new sessions are not automatically created when calling `use(event)`, marking their `id` as `undefined` until you explicitly call `session.update()`. This is to comply with various specs that do integrate JWT one (such as OAuth) where sessions are only created upon valid operations (like user authorization).

For an in-depth guide on using these adapters, please refer to the [H3 sessions guide](../../../docs/5.adapters/2.h3/0.index.md).

A session is defined once, at module scope, and opened on each request with `use(event)`:

- `defineJWESession(config)` encrypts the session payload with `config.key` (a JWK, a `{ privateKey, publicKey }` pair, or a `CryptoKey`). Use this when session data must remain confidential. (cookie's `httpOnly: true` by default)
- `defineJWSSession(config)` signs, but does not encrypt, the session payload with `config.key`. Use this when clients may read the session content but you still need tamper protection. (cookie's `httpOnly: false` by default)

Both definitions expose the same API: `use(event)` returns the session manager, `token(event)` the raw token, `issue(data)` mints a token without a request (magic links, email verification) and `open(token)` opens one by hand. On the manager, read `session.id` / `session.data`, call `session.update()` to patch values, and `session.clear()` to invalidate the cookie. `jti`, `iat`, `exp` and `nbf` belong to the adapter — they are stripped from update payloads, and the lifetime comes from `maxAge` (on the config, or on a single `session.update(data, { maxAge })`). They also support a number of `hooks` in the config for custom logic (e.g. logging, refreshing, etc).

Keys are key material, never passwords: turn a secret into a JWK once with `deriveJWKFromPassword()`.

```ts
import { H3, HTTPError, serve } from "h3";

import {
  defineJWESession,
  defineJWSSession,
  generateJWK,
  deriveJWKFromPassword,
} from "unjwt/adapters/h3v2";

const atJwk = await generateJWK("RS256"); // Make sure to persist these keys somewhere!
const rtJwk = await deriveJWKFromPassword(process.env.REFRESH_SECRET!, {
  alg: "PBES2-HS256+A128KW",
  salt: process.env.REFRESH_SALT!,
  iterations: 600_000,
});

const refreshToken = defineJWESession({
  key: rtJwk,
  name: "refresh_token",
});

const accessToken = defineJWSSession({
  key: atJwk,
  name: "access_token",
  maxAge: 15 * 60, // 15 minutes
  hooks: {
    async onExpire({ event }) {
      const refreshSession = await refreshToken.use(event);
      if (!refreshSession.data.sub) {
        // no valid refresh session, nothing to do
        return;
      }

      console.log("Access token expired, refreshing...");

      // refresh the access token
      const accessSession = await accessToken.use(event);
      await accessSession.update({
        sub: refreshSession.data.sub,
        scope: refreshSession.data.scope,
      });
    },
  },
});

const app = new H3();

app.post("/login", async (event) => {
  const refreshSession = await refreshToken.use(event);
  const accessSession = await accessToken.use(event);

  if (accessSession.data.sub) {
    // user already logged in, return existing info
    return {
      accessToken: {
        id: accessSession.id,
        createdAt: accessSession.createdAt,
        expiresAt: accessSession.expiresAt,
        data: accessSession.data,
      },
      refreshSession: {
        id: refreshSession.id,
        createdAt: refreshSession.createdAt,
        expiresAt: refreshSession.expiresAt,
        data: refreshSession.data,
      },
    };
  }

  const data = (await event.req.json()) as {
    username?: string;
    password?: string;
  };

  if (!data.username || !data.password) {
    throw new HTTPError("Username and password are required", { status: 400 });
  }

  // validate user credentials here

  const claims = {
    sub: data.username,
    scope: ["read:profile"],
  };

  await accessSession.update(claims);

  await refreshSession.update(claims);

  return {
    accessToken: {
      id: accessSession.id,
      createdAt: accessSession.createdAt,
      expiresAt: accessSession.expiresAt,
      data: accessSession.data,
    },
    refreshSession: {
      id: refreshSession.id,
      createdAt: refreshSession.createdAt,
      expiresAt: refreshSession.expiresAt,
      data: refreshSession.data,
    },
  };
});

serve(app);
```
