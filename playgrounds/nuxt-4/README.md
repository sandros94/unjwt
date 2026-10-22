# Nuxt 4 playground

A JWE session on Nuxt v4.6 with `unjwt/session`, keyed from Nuxt's own `appSecret`. Nuxt v4.6 still runs on Nitro v2 and h3 v1, but a handler defined through `nuxt/server` receives the web-standard `RequestEvent` (`{ req, res, context }`), which `unjwt/session` takes as it is. No `h3` import, no alias, the same code on Nitro v3.

- [`server/utils/session.ts`](./server/utils/session.ts): the definition, `useAppSession(event)` and `requireAppSession(event)`.
- [`server/routes/`](./server/routes/): `login`, `me`, `logout`, `throw-after-clear`, and a WebSocket at `/ws`.
- [`shared/types/session.d.ts`](./shared/types/session.d.ts): `SessionData`, visible to the utils and the routes.
- [`app.vue`](./app.vue): one button per route, and a log of what each answered.

```sh
pnpm dev:prepare # at the repository root, once: the stub dist runs from src; `pnpm build` works too
pnpm dev:nuxt    # at the repository root, or `pnpm dev` here; a dev appSecret is generated into .nuxt/app-secret

NUXT_APP_SECRET=$(openssl rand -base64 32) pnpm build && pnpm start
```

## Handlers come from `nuxt/server`

```ts
// server/routes/me.get.ts
import { defineEventHandler } from "nuxt/server";

export default defineEventHandler(async (event) => {
  const session = await requireAppSession(event);

  return { id: session.id, user: session.data.user, expiresAt: session.expiresAt };
});
```

The import is the whole point. Nuxt's auto-imported `defineEventHandler` is still h3's, and its handler receives the raw h3 v1 event, whose `req` is Node's `IncomingMessage`. Every `nuxt/server` helper refuses that event, and so does `unjwt/session`:

```text
[unjwt/session] use() got an event whose "req" is not a web Request.
```

`readBody` and `createError` come from `nuxt/server` for the same reason.

## One definition, keyed from `appSecret`

```ts
// server/utils/session.ts
import { deriveSecret, createError } from "nuxt/server";

import { type SessionDefinition, type WebSessionEvent, defineJWESession } from "unjwt/session";
import { base64UrlStringify } from "unjwt/utils";

type Definition = SessionDefinition<SessionData, "1h", WebSessionEvent>;
let definition: Promise<Definition> | undefined;

async function define(): Promise<Definition> {
  const secret = await deriveSecret("unjwt:session");
  const bytes = Uint8Array.from(secret.match(/../g)!, (pair) => Number.parseInt(pair, 16));

  return defineJWESession<SessionData, "1h">({
    key: { kty: "oct", k: base64UrlStringify(bytes), alg: "A256GCM" },
    name: "unjwt-session",
    maxAge: "1h",
    rolling: "15m",
  });
}

export async function useAppSession(event: WebSessionEvent) {
  return (definition ??= define()).then((current) => current.use(event));
}
```

Nuxt v4.6 reads `NUXT_APP_SECRET` (or `runtimeConfig.appSecret`) and generates a development one when unset; builds do not. `deriveSecret(purpose)` returns 32 HKDF-SHA256 bytes as hex, stable while `appSecret` is and distinct per purpose; the util turns them into an `A256GCM` `oct` JWK. It needs the runtime config, so the definition is created on the first `useAppSession()` call, not at module load, and cached in the module.

`useAppSession` takes a `WebSessionEvent`, not only `RequestEvent`: the same util serves a route's event, a WebSocket upgrade request, and `{ token }` when a token arrives some other way.

`rolling: "15m"` reissues a token older than 15 minutes on the first read that sees it, over HTTP and at a WebSocket upgrade alike, so an active user never expires. A cookie whose token cannot be opened is dropped by the read itself, so a tampered or foreign cookie is not sent back on every request; `onError` only reports it.

## Routes

`POST /login` reads `{ user }` and calls `update()`, which mints the token and writes the cookie. `GET /me` goes through `requireAppSession`, which turns `session.id === undefined` into a `401`: a session has no `id` until its first `update()`. `POST /logout` calls `clear()`, which expires the cookie. `GET /throw-after-clear` clears and then throws a `401`: on Nitro 2 the `Set-Cookie` written before the throw stays on the Node response, so the client is signed out by the error response too.

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

    setContext(request, session);
    return { headers }; // a roll or a drop made during the read rides on the 101
  },

  open(peer) {
    const { data } = getContext(peer);
    peer.send(`hello ${data.user}`);
  },

  message(peer, message) {
    const { expiresAt } = getContext(peer);
    if (expiresAt !== undefined && expiresAt < Date.now()) {
      peer.close(4401, "Session expired");
      return;
    }
    peer.send(`echo: ${message.text()}`);
  },
});
```

The upgrade request is `{ headers, url, context }` on Nitro v2 and a `Request` on Nitro 3; naming the fields serves both, where a spread would lose a `Request`'s `headers` getter (and the linter says so). `setContext` snapshots the session's state onto the context; `open`, `message` and `close` never touch the session again. Closing with `4401` once `expiresAt` has passed is the one thing a socket can still do about an expired session.

The upgrade never passes through server middleware on Nitro v2, so the `upgrade` hook is the only place a WebSocket's cookie is read, rolled or dropped.

`defineWebSocketHandler` is the one h3 import left: `nuxt/server` has no WebSocket API yet.
