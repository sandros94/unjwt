## H3 v2 (Nuxt v5, Nitro v3)

The `h3v2` adapter bundles session helpers that store data inside signed or encrypted JWTs.

- `useJWESession(event, config)` encrypts the session payload with the provided `secret` (password string or private/symmetric JWK). Use this when session data must remain confidential. (cookie's `httpOnly: true` by default)
- `useJWSSession(event, config)` signs, but does not encrypt, the session payload with `config.key`. Use this when clients may read the session content but you still need tamper protection. (cookie's `httpOnly: false` by default)

Both helpers expose the same API: read `session.id` / `session.data`, call `session.update()` to patch values, and `session.clear()` to invalidate the cookie. When setting `maxAge`, `exp` claim is automatically managed and validated. They also support a number of `hooks` in the config for custom logic (e.g. logging, refreshing, etc).

```ts
import { H3, HTTPError, serve } from "h3v2";

import {
  type SessionConfigJWE,
  type SessionConfigJWS,
  useJWESession,
  useJWSSession,
  getJWESession,
  updateJWSSession,
  generateJWK,
} from "unjwt/adapters/h3v2";

const atJwk = await generateJWK("RS256"); // Make sure to persist these keys somewhere!

const jweOptions = {
  key: "refresh_token_secret",
  name: "refresh_token",
} satisfies SessionConfigJWE;

const jwsOptions = {
  key: atJwk,
  name: "access_token",
  maxAge: 15 * 60, // 15 minutes
  hooks: {
    async onExpire({ event, config }) {
      const refreshSession = await getJWESession(event, jweOptions);
      if (!refreshSession.data.sub) {
        // no valid refresh session, nothing to do
        return;
      }

      console.log("Access token expired, refreshing...");

      // refresh the access token
      await updateJWSSession(event, config, {
        sub: refreshSession.data.sub,
        scope: refreshSession.data.scope,
      });
    },
  },
} satisfies SessionConfigJWS;

const app = new H3();

app.post("/login", async (event) => {
  const refreshSession = await useJWESession(event, jweOptions);
  const accessSession = await useJWSSession(event, jwsOptions);

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
