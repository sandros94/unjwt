## H3 v1 (Nuxt up to v4, Nitro up to v2)

The `h3` adapter bundles session helpers that store data inside signed or encrypted JWTs.

> [!WARNING]
> While these adapters try to be compatible with h3's `useSession` API, the key difference is that new sessions are not automatically created when calling `useJWESession` or `useJWSSession`, marking their `id` as `undefined` until you explicitly call `session.update()`. This is to comply with various specs that do integrate JWT one (such as OAuth) where sessions are only created upon valid operations (like user authorization).

For an in-depth guide on using these adapters, please refer to the [H3 sessions guide](../../../docs/99.Adapters/1.h3-sessions.md).

- `useJWESession(event, config)` encrypts the session payload with `config.key` (a JWK, a `{ privateKey, publicKey }` pair, or a `CryptoKey`). Use this when session data must remain confidential. (cookie's `httpOnly: true` by default)
- `useJWSSession(event, config)` signs, but does not encrypt, the session payload with `config.key`. Use this when clients may read the session content but you still need tamper protection. (cookie's `httpOnly: false` by default)

Both helpers expose the same API: read `session.id` / `session.data`, call `session.update()` to patch values, and `session.clear()` to invalidate the cookie. `jti`, `iat`, `exp` and `nbf` belong to the adapter — they are stripped from update payloads, and the lifetime comes from `maxAge` (on the config, or on a single `session.update(data, { maxAge })`). They also support a number of `hooks` in the config for custom logic (e.g. logging, refreshing, etc).

Keys are key material, never passwords: turn a secret into a JWK once with `deriveJWKFromPassword()`.

```ts
import { defineEventHandler } from "h3";
import {
  useJWESession,
  useJWSSession,
  generateJWK,
  deriveJWKFromPassword,
} from "unjwt/adapters/h3v1";

const keys = await generateJWK("RS256"); // Make sure to persist these keys somewhere!
const sessionKey = await deriveJWKFromPassword(process.env.SESSION_SECRET!, {
  alg: "PBES2-HS256+A128KW",
  salt: process.env.SESSION_SALT!,
  iterations: 600_000,
});

export default defineEventHandler(async (event) => {
  const privateSession = await useJWESession(event, {
    name: "app-session",
    key: sessionKey, // or a symmetric JWK, an asymmetric keypair, or a CryptoKey
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
