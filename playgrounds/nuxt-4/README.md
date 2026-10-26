# Nuxt 4 playground

A JWS session on Nuxt v4.6 with `unjwt/session`, keyed from the runtime config. Nuxt v4.6 still runs on Nitro v2 and h3 v1, but a handler defined through `nuxt/server` receives the web-standard `RequestEvent` (`{ req, res, context }`), which `unjwt/session` takes as it is. No `h3` import, no alias, the same code on Nitro v3.

- [`server/utils/session.ts`](./server/utils/session.ts): the definition, `useAppSession(event)` and `requireAppSession(event)`.
- [`server/plugins/session-key.ts`](./server/plugins/session-key.ts): defines the session at start-up, so a missing key stops the server.
- [`server/routes/`](./server/routes/): `login`, `me`, `logout`, `throw-after-clear`, and a WebSocket at `/ws`.
- [`shared/types/session.d.ts`](./shared/types/session.d.ts): `SessionData`, visible to the utils and the routes.
- [`app.vue`](./app.vue): one button per route, and a log of what each answered.

```sh
pnpm dev:prepare # at the repository root, once: the stub dist runs from src; `pnpm build` works too

# once: an HS256 JWK, as JSON (or put it in .env, see .env.example)
export NUXT_SESSION_KEY=$(node --input-type=module -e 'import { generateJWK } from "unjwt/jwk"; console.log(JSON.stringify(await generateJWK("HS256")))')

pnpm dev:nuxt    # at the repository root, or `pnpm dev` here
pnpm build && pnpm start
```

## Handlers come from `nuxt/server`

```ts
// server/routes/me.get.ts
import { defineEventHandler } from "nuxt/server";

export default defineEventHandler(async (event) => {
  const session = await requireAppSession(event);
  return session.data;
});
```

The import is the whole point. Nuxt's auto-imported `defineEventHandler` is still h3's, and its handler receives the raw h3 v1 event, whose `req` is Node's `IncomingMessage`. Every `nuxt/server` helper refuses that event, and so does `unjwt/session`:

```text
[unjwt/session] use() got an event whose "req" is not a web Request.
```

`readBody` and `createError` come from `nuxt/server` for the same reason.

## One definition, keyed from the runtime config

`nuxt.config.ts` declares `runtimeConfig.sessionKey`, which Nuxt fills from `NUXT_SESSION_KEY`: the JSON of an `HS256` JWK. Nuxt parses a JSON environment variable into an object, so [`server/utils/session.ts`](./server/utils/session.ts) takes the value as it comes and parses only a string. The definition is created on first use, with the default cookie name `__Host-unjwt-jws`, `maxAge: "1h"` and `rolling: "15m"`; the plugin in `server/plugins/` makes that first use happen at start-up, so a production server without the key stops at boot.

`useAppSession` takes a `WebSessionEvent`, not only `RequestEvent`: the same util serves a route's event, a WebSocket upgrade request, and `{ token }` when a token arrives some other way. It is not called `useSession`, which Nuxt auto-imports already.

`rolling: "15m"` reissues a token older than 15 minutes on the first read that sees it, over HTTP and at a WebSocket upgrade alike, so an active user never expires. A cookie whose token cannot be opened is dropped by the read itself; `onError` only reports it.

## Routes

`POST /login` reads `{ user }` and calls `update()`, which mints the token and writes the cookie. `GET /me` goes through `requireAppSession`, which turns `session.id === undefined` into a `401`, and returns `session.data`: a session has no `id` until its first `update()`. `POST /logout` calls `clear()`, which expires the cookie. `GET /throw-after-clear` clears and then throws a `401`: on Nitro 2 the `Set-Cookie` written before the throw stays on the Node response, so the client is signed out by the error response too.

## WebSockets

Nitro v2 resolves an upgrade straight to the route's hooks, and nothing can be written to the client once the socket is open. So the session is read once, in `upgrade`, the only hook that can still refuse; what the socket needs for its lifetime is copied onto `request.context`, the object crossws hands every later hook as `peer.context`. The headers `upgrade` returns travel on the `101` handshake, so a `Headers` passed as `res` lets the read roll the token or drop an expired cookie:

```ts
// server/routes/ws.ts
export default defineWebSocketHandler({
  async upgrade(request) {
    const headers = new Headers();
    const session = await useAppSession({
      headers: request.headers,
      context: request.context,
      res: { headers },
    });
    if (!session.id) return new Response("Sign in first", { status: 401 });

    Object.assign(request.context, session);
    return { headers }; // a roll or a drop made during the read rides on the 101
  },

  open(peer) {
    const { data } = getContext(peer);
    peer.send(`hello ${data.user}`);
  },

  message(peer, message) {
    const { expiresAt } = getContext(peer);
    if (expiresAt < Date.now()) {
      peer.close(4401, "Session expired");
      return;
    }
    peer.send(`echo: ${message.text()}`);
  },
});
```

The upgrade request is `{ headers, url, context }` on Nitro v2 and a `Request` on Nitro 3; naming the fields serves both, where a spread would lose a `Request`'s `headers` getter (and the linter says so). `Object.assign` snapshots the session's state onto the context; `open` and `message` never touch the session again. Closing with `4401` once `expiresAt` has passed is the one thing a socket can still do about an expired session.

The upgrade never passes through server middleware on Nitro v2, so the `upgrade` hook is the only place a WebSocket's cookie is read, rolled or dropped.

`defineWebSocketHandler` is the one h3 import left: `nuxt/server` has no WebSocket API yet.
