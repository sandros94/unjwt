# h3 playground

A session over h3 with `unjwt/adapters/h3`: one `defineJWESession` at module scope, a `useSession(event)` wrapper, and three routes in [`main.ts`](./main.ts).

```sh
pnpm dev:prepare   # at the repository root, once: the stub dist runs from src; `pnpm build` works too
pnpm dev     # at the repository root, or here: runs main.ts under `node --watch`
```

```sh
curl -X POST localhost:3000/login -H 'content-type: application/json' -d '{"user":"alice"}' -c jar
curl localhost:3000/me -b jar
curl -X POST localhost:3000/logout -b jar
```

The session is a JWE cookie over a key derived once from a password (`SESSION_PASSWORD`, with a default for local use), with a one hour `maxAge` and `rolling: "15m"`: the first read on a token older than 15 minutes issues a fresh hour, so an active user never expires and the token is re-signed at most four times an hour. `session.id` is `undefined` until `update()` writes the first token, which is what `/me` checks.

`scripts/h3-from-playground.mjs` is a Node resolve hook: `unjwt` is the workspace root linked into `node_modules`, so its `h3` peer is re-anchored to this playground's h3 (Nitro and Nuxt do the same with an `alias`).
