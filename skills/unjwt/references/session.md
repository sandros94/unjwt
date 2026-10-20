# Web Standard Sessions Reference (`unjwt/session`)

JWT sessions over a web-standard request event (`{ req, res, context }`: an h3 v2 event, the
event `nuxt/server` hands a Nuxt 4.6+ handler, or one built from a `Request` and the `Headers`
its response is sent with), over a `Request` that only reads, or over a token the caller already
holds. No framework, no peer dependency. The same entry exposes the driver contract, so any
framework can run these sessions.

Import path: `unjwt/session`

Exports: `defineJWSSession`, `defineJWESession`, `defineSessionDriver`; types `SessionContext`,
`SessionRequestEvent`, `SessionRequestHeaders`, `SessionToken`,
`SessionDriver`, `CookieJar`, `CookieAttributes`, `SessionDefinition`, `OpenedSessionState`, `SessionManager`,
`SessionClaims`, `SessionData`, `SessionUpdate`, `SessionUpdateTrigger`, `SessionIssueOptions`,
`SessionConfigJWS`/`SessionConfigJWE`, `SessionHooksJWS`/`SessionHooksJWE`,
`SessionJWS`/`SessionJWE`, `SessionSignOptions`, `SessionVerifyOptions`,
`SessionEncryptOptions`, `SessionDecryptOptions`. Also re-exports `generateJWK`, `thumbprint`,
`importPEM`, `exportPEM`, `deriveJWKFromPassword` and every core type.

The session manager, config options, hooks, cookie layout, chunking, lifetime, `typ` and key rules
are those of the h3 entry: see `adapters-h3.md`. Differences are listed here.

## SessionContext

```ts
type SessionContext =
  | { req: Request; res?: { headers: Headers }; context?: Record<string, unknown> } // request event; no res = read-only
  | { headers: Headers; res?: { headers: Headers }; context?: Record<string, unknown> } // by headers: a Request, a WebSocket upgrade; no res = read-only
  | { token: string | undefined }; // a token in hand
```

State: `context.sessions` when a `context` is given (the h3 slot, shared with middleware on the same
event), else a `WeakMap` keyed on `req`, on the object passed, or on the `{ token }` object. An h3 v2
`H3Event` and Nuxt's `RequestEvent` match the first shape unchanged; a `Request` matches the second.

## Signatures

```ts
function defineJWSSession<
  T extends Record<string, any> = SessionClaims,
  MaxAge extends ExpiresIn | undefined = ExpiresIn | undefined,
>(config: SessionConfigJWS<T, MaxAge>): SessionDefinition<SessionContext, T, MaxAge>;

function defineJWSSession<
  T extends Record<string, any> = SessionClaims,
  MaxAge extends ExpiresIn | undefined = ExpiresIn | undefined,
  TContext = SessionContext,
>(
  config: SessionConfigJWS<T, MaxAge, TContext>,
  options: { driver: SessionDriver<TContext> },
): SessionDefinition<TContext, T, MaxAge>;
// defineJWESession: same two signatures over SessionConfigJWE
```

`TContext` is inferred from the driver; without `{ driver }` it is `SessionContext`. Hooks receive
`{ context: TContext }` whatever the driver: the entry names the hook argument, not the driver.
`onVerifyKeyLookup` / `onUnsealKeyLookup` get `context` only from `use()` (typed
`context?: TContext`); `open()` passes none and resolves to `{ id, createdAt, expiresAt, data }`.
Default `name`: `"unjwt-jws"` / `"unjwt-jwe"`. `cookie` takes
`CookieAttributes & { chunkMaxLength? }`. Error messages start with `[unjwt/session]` (a custom
driver's `prefix` otherwise).

## A request event: `{ req, res, context? }`

```ts
import { defineJWESession, generateJWK } from "unjwt/session";

const useSession = defineJWESession({ key: await generateJWK("A256GCM"), maxAge: "7D" });

export default {
  async fetch(req: Request) {
    const headers = new Headers();
    const session = await useSession.use({ req, res: { headers } });
    await session.update({ userId: "u_123" });
    return new Response(JSON.stringify(session.data), { headers });
  },
};
```

- Reads `req.headers`' `Cookie` (parsed once per `use()`), then the session header.
- Writes `Set-Cookie` onto `res.headers`, replacing an earlier line of the same name, domain and
  path (and partition); unrelated lines stay. A second `update()` in one request leaves one line
  per cookie; `clear()` leaves the `Max-Age=0` line.
- Hono: pass `c.req.raw` as `req` and return `new Response(body, { headers })`.
- Nuxt 4.6+: `defineEventHandler` from `nuxt/server` (not h3's auto-import) hands a `RequestEvent`
  that goes to `use(event)` as is, on Nitro 2 and 3; key it from `deriveSecret()` of `nuxt/server`
  (32 HKDF bytes as hex → `oct` JWK, created lazily since it needs the runtime config). h3 v2,
  Nuxt 5 and Nitro 3 can use `unjwt/adapters/h3` instead (adds `res.errHeaders` staging).

## Read-only: a `Request`, `{ req }` without `res`, `{ headers, context? }`

Reads work. On a cookie session `update()` throws `ERR_SESSION_READONLY_EVENT`
(`Cannot update session on read-only event.`); `clear()` empties the session for the rest of the
request, fires `onClear` and resolves, writing nothing (an `onRead` revocation clears with no
gate); an expired token fires `onExpire` without dropping the cookie; `rolling` does not reissue.
With `cookie: false`, `update()` re-mints onto `session.token`. WebSockets: in `upgrade`,
`use({ headers: request.headers, context: request.context, res: { headers } })` then
`return { headers }`: the `101` handshake carries a roll, an expired cookie's drop or a `clear()`
made during the read. Read once there, copy what the socket needs onto `request.context`
(= `peer.context` later); nothing can be written after the upgrade. crossws 0.4 (Nitro 3) merges
returned headers with `set`, so keep the session under one cookie there.

## Token in hand: `{ token }`

```ts
const session = await useSession.use({ token: message.body.session });
await session.update({ seen: true });
send(session.token); // the new token; sending it is the caller's job
```

- Full read lifecycle: `onRead`/`onExpire`/`onError`, `rolling` (with `trigger: "rolling"`).
- `update()` re-mints onto `session.token`, writes nothing. `clear()` leaves an empty session,
  `token` `undefined`.
- Config `cookie`/`sessionHeader` are not consulted: works on a token-only config
  (`cookie: false, sessionHeader: false`) and on a cookie config alike.
- `token({ token })` returns the handed token. `use({ token: undefined })` is an empty session.
- State is keyed on the context object itself.

## Rules for `use()`

1. Pass the framework's event or the incoming `Request`, never an object you built or share
   between requests.
2. Pass the `res` whose `headers` the response is sent with, or get a read-only session.
3. Call `use()` before the response starts; the library cannot tell when it is too late.
4. Holding a token yourself: `use({ token })`; sending the new token is your job.
5. One name is one cookie: two definitions with one name on one request share state; a JWS and a
   JWE under one name throw `ERR_SESSION_CONFIG_INVALID`.

## Driver contract

```ts
interface SessionDriver<TContext> {
  /** Starts every error message. */
  prefix: string;
  /** A record unique to the request: session state and the name registry. */
  state(context: TContext): Record<string, unknown>;
  /** A request header by lowercase name. */
  header(context: TContext, name: string): string | null | undefined;
  cookies(context: TContext): CookieJar;
  /** `false` once the response was sent: `update()`/`clear()` throw; absent = always open. */
  writable?(context: TContext): boolean;
  /** `{ token }` when the context carries the token: no cookie or header is consulted. */
  handed?(context: TContext): { token: string | undefined } | undefined;
}

interface CookieJar<A = { expires?: Date; maxAge?: number }> {
  /** The request's cookie. */
  read(name: string): string | undefined;
  /** This response's value for `name` (`""` once deleted); only when `read` does not see writes. */
  written?(name: string): string | undefined;
  /** Sets a cookie, replacing an earlier write of the same cookie; absent = no cookie: `update()` throws, `clear()` empties state. */
  write?(name: string, value: string, attrs: A): void;
}

function defineSessionDriver<TContext>(driver: SessionDriver<TContext>): SessionDriver<TContext>;
```

```ts
import type { RequestEvent } from "@sveltejs/kit";
import {
  type CookieAttributes,
  type CookieJar,
  defineJWESession,
  defineSessionDriver,
} from "unjwt/session";

const sveltekit = defineSessionDriver<RequestEvent>({
  prefix: "[sveltekit-session]",
  state: (event) => (event.locals.sessions ??= {}),
  header: (event, name) => event.request.headers.get(name),
  cookies: (event): CookieJar<CookieAttributes> => ({
    read: (name) => event.cookies.get(name),
    write: (name, value, attrs) =>
      event.cookies.set(name, value, { ...attrs, path: attrs.path ?? "/" }),
  }),
});

export const appSession = defineJWESession({ key, maxAge: "7D" }, { driver: sveltekit });
// appSession.use(event: RequestEvent)
```

- `state(context)` must return an object unique to the request (`event.locals`, `event.context`, a
  `WeakMap` keyed by the request). A module-level or shared object leaks sessions across requests.
- `write` must replace, not append: a re-issue in the same request writes the same names again.
- Writes arrive one cookie at a time: base cookie, chunks `name.1…N`, `Max-Age=0` for surplus.
- Shipped drivers: h3 (state on `event.context.sessions`, `writable` from Node `headersSent`,
  v2 stages cookies in `res.errHeaders`), Elysia (state keyed by `Request`, reactive jar, no
  `written`), `unjwt/session` (state on `context.sessions`, else keyed by `req`, the object passed
  or the `{ token }` object; `handed`).

## Error codes

| Code                         | When                                                                                                                                                                                                                                                 |
| ---------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `ERR_SESSION_KEY_INVALID`    | `key` missing, a password string, wrong shape, or not importable.                                                                                                                                                                                    |
| `ERR_SESSION_CONFIG_INVALID` | Bad `name`/`sessionHeader`, `__Host-`/`__Secure-` violation, an event whose `req` is not a web `Request` (Nuxt handler not from `nuxt/server`), `use(event)` with no token source, unpinned `CryptoKey`, over 16 chunks, JWS + JWE under one `name`. |
| `ERR_SESSION_READONLY_EVENT` | `update()` on a cookie session opened without a `res`; `update()`/`clear()` once a driver's `writable()` is `false`.                                                                                                                                 |
| `ERR_INVALID_OPTION`         | `update()` data not a plain object, or a `__proto__`-like key.                                                                                                                                                                                       |

An unreadable incoming token goes to `onError` as `ERR_SESSION_TOKEN_INVALID` and its cookie is
dropped (kept only when a key lookup hook threw); an expired one, cookie dropped too, to
`onExpire`. Neither throws from `use()`.
