# Nitro 3 playground

A JWS session on Nitro v3 with `unjwt/session`. Nitro v3 runs on h3, whose event is the web-standard `{ req, res, context }` that `unjwt/session` takes as it is. No `h3` import, no alias, the same route code as the Nuxt 4 playground.

- [`server/utils/session.ts`](./server/utils/session.ts): the definition, keyed from the runtime config, `useAppSession(event)` and `requireAppSession(event)`.
- [`server/plugins/session-key.ts`](./server/plugins/session-key.ts): defines the session at start-up, so a missing key stops the server.
- [`server/routes/`](./server/routes/): `login`, `me`, `logout`, `throw-after-clear`, and a WebSocket at `/ws`.
- [`index.html`](./index.html): one button per route, and a log of what each answered. Nitro serves it for every unmatched route.

```sh
pnpm dev:prepare # at the repository root, once: the stub dist runs from src; `pnpm build` works too

# once: an HS256 JWK, as JSON
export NITRO_SESSION_KEY=$(node --input-type=module -e 'import { generateJWK } from "unjwt/jwk"; console.log(JSON.stringify(await generateJWK("HS256")))')

pnpm dev:nitro   # at the repository root, or `pnpm dev` here
pnpm build && pnpm start
```

## Imports come from `nitro`

```ts
// server/routes/me.get.ts
import { defineHandler } from "nitro";
import { requireAppSession } from "../utils/session.ts";

export default defineHandler(async (event) => {
  const session = await requireAppSession(event);
  return session.data;
});
```

Nitro v3 has no auto-imports: `defineHandler`, `defineWebSocketHandler` and `HTTPError` come from `nitro`, `readBody` from `nitro/h3`, and the session utils are imported by path.

## One definition, keyed from the runtime config

`nitro.config.ts` declares `runtimeConfig.sessionKey`, which Nitro fills from `NITRO_SESSION_KEY`: the JSON of an `HS256` JWK. [`server/utils/session.ts`](./server/utils/session.ts) parses it on first use and defines the session with the default cookie name `__Host-unjwt-jws`, `maxAge: "1h"` and `rolling: "15m"`. The plugin in `server/plugins/` makes that first use happen at start-up, so the server refuses to start without the key.

`useAppSession` takes a `WebSessionEvent`, not only an `H3Event`: the same util serves a route's event, a WebSocket upgrade request, and `{ token }` when a token arrives some other way.

`rolling: "15m"` reissues a token older than 15 minutes on the first read that sees it, over HTTP and at a WebSocket upgrade alike, so an active user never expires. A cookie whose token cannot be opened is dropped by the read itself; `onError` only reports it.

## Routes

`POST /login` reads `{ user }` and calls `update()`, which mints the token and writes the cookie. `GET /me` goes through `requireAppSession`, which turns `session.id === undefined` into a `401`, and returns `session.data`: a session has no `id` until its first `update()`. `POST /logout` calls `clear()`, which expires the cookie.

`GET /throw-after-clear` clears and then throws a `401`, and on Nitro v3 the client stays signed in: the `Set-Cookie` written before the throw is lost, because Nitro's error handler answers with a `Response` of its own and h3 sends that without the prepared headers. That is the reproduction this route exists for; the fix belongs upstream.

## WebSockets

The session is read once, in `upgrade`, the only hook that can refuse; what the socket needs for its lifetime is returned as `context`, which every later hook receives as `peer.context`. The headers `upgrade` returns travel on the `101` handshake, so a `Headers` passed as `res` lets the read roll the token or drop an expired cookie:

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
    if (!session.id) throw new Response("Sign in first", { status: 401 });

    return { headers, context: { ...session } };
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

Three Nitro v3 differences from the Nuxt 4 playground: the upgrade request is a `Request`, so its fields are named rather than spread; a refusal is a thrown `Response`; and the `context` goes back as a return value instead of being written onto the request. crossws 0.4 merges the returned headers with `set`, which keeps one `Set-Cookie` line, so a session that fits one cookie is what rides the upgrade.
