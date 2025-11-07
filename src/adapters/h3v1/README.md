## H3 v1 (Nuxt up to v4, Nitro up to v2)

The `h3v1` adapter bundles session helpers that store data inside signed or encrypted JWTs.

- `useJWESession(event, config)` encrypts the session payload with the provided `secret` (password string or private/symmetric JWK). Use this when session data must remain confidential. (cookie's `httpOnly: true` by default)
- `useJWSSession(event, config)` signs, but does not encrypt, the session payload with `config.key`. Use this when clients may read the session content but you still need tamper protection. (cookie's `httpOnly: false` by default)

Both helpers expose the same API: read `session.id` / `session.data`, call `session.update()` to patch values, and `session.clear()` to invalidate the cookie. When setting `maxAge`, `exp` claim is automatically managed and validated. They also support a number of `hooks` in the config for custom logic (e.g. logging, refreshing, etc).

```ts
import { defineEventHandler } from "h3";
import { useJWESession, useJWSSession, generateJWK } from "unjwt/adapters/h3v1";

const keys = await generateJWK("RS256"); // Make sure to persist these keys somewhere!

export default defineEventHandler(async (event) => {
  const privateSession = await useJWESession(event, {
    name: "app-session",
    secret: process.env.SESSION_SECRET!, // or symmetric or asymmetric keypair
  });

  await privateSession.update((data) => ({
    visits: (data.visits ?? 0) + 1,
  }));

  const publicSession = await useJWSSession(event, {
    name: "app-session-public",
    key: keys, // you can directly pass symmetric or asymmetric keypairs
    maxAge: 60 * 60, // seconds
  });

  return {
    encryptedSession: privateSession.data,
    signedSession: publicSession.data,
  };
});
```
