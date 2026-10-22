# Nitro 3 playground

A JWE session on Nitro v3 with `unjwt/session`. Nitro v3 runs on h3 v2, whose event is the web-standard `{ req, res, context }` that `unjwt/session` takes as it is. No `h3` import, no alias, the same route code as the Nuxt 4 playground.

- [`server/utils/session.ts`](./server/utils/session.ts): the definition, `useAppSession(event)` and `requireAppSession(event)`.
- [`server/routes/`](./server/routes/): `login`, `me`, `logout`, `throw-after-clear`, and a WebSocket at `/ws`.
- [`index.html`](./index.html): one button per route, and a log of what each answered. Nitro serves it for every unmatched route.

```sh
pnpm dev:prepare # at the repository root, once: the stub dist runs from src; `pnpm build` works too
pnpm dev:nitro   # at the repository root, or `pnpm dev` here

SESSION_PASSWORD=$(openssl rand -base64 32) pnpm build && pnpm start
```

## Imports come from `nitro`

```ts
// server/routes/me.get.ts
import { defineHandler } from "nitro";
import { requireAppSession } from "../utils/session.ts";

export default defineHandler(async (event) => {
  const session = await requireAppSession(event);

  return { id: session.id, user: session.data.user, expiresAt: session.expiresAt };
});
```

Nitro v3 has no auto-imports: `defineHandler`, `defineWebSocketHandler` and `HTTPError` come from `nitro`, `readBody` from `nitro/h3`, and the session utils are imported by path.

## One definition, keyed from a password

```ts
// server/utils/session.ts
import { HTTPError } from "nitro";
import { type WebSessionEvent, defineJWESession, deriveJWKFromPassword } from "unjwt/session";

const key = await deriveJWKFromPassword(password, {
  alg: "PBES2-HS256+A128KW",
  salt: "unjwt-playground-nitro",
  iterations: 600_000,
});

const definition = defineJWESession<SessionData, "1h">({
  key,
  name: "unjwt-session",
  maxAge: "1h",
  rolling: "15m",
});

export function useAppSession(event: WebSessionEvent) {
  return definition.use(event);
}
```

The key is derived once at module load from `SESSION_PASSWORD` (with a default for local use), so the definition needs no runtime config and is created at import time.

`useAppSession` takes a `WebSessionEvent`, not only an `H3Event`: the same util serves a route's event, a WebSocket upgrade request, and `{ token }` when a token arrives some other way.

`rolling: "15m"` reissues a token older than 15 minutes on the first read that sees it, over HTTP and at a WebSocket upgrade alike, so an active user never expires. A cookie whose token cannot be opened is dropped by the read itself, so a tampered or foreign cookie is not sent back on every request; `onError` only reports it.

## Routes

`POST /login` reads `{ user }` and calls `update()`, which mints the token and writes the cookie. `GET /me` goes through `requireAppSession`, which turns `session.id === undefined` into a `401`: a session has no `id` until its first `update()`. `POST /logout` calls `clear()`, which expires the cookie.

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
    if (expiresAt !== undefined && expiresAt < Date.now()) {
      peer.close(4401, "Session expired");
      return;
    }
    peer.send(`echo: ${message.text()}`);
  },
});
```

Three Nitro v3 differences from the Nuxt 4 playground: the upgrade request is a `Request`, so its fields are named rather than spread; a refusal is a thrown `Response`; and the `context` goes back as a return value instead of being written onto the request. crossws 0.4 merges the returned headers with `set`, which keeps one `Set-Cookie` line, so a session that fits one cookie is what rides the upgrade.
