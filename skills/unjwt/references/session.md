# Web Standard Sessions Reference (`unjwt/session`)

JWT sessions over a web-standard request event (an h3 v2 event, the event `nuxt/server` hands a Nuxt 4.6+ handler, a `Request`, a crossws upgrade request, or `{ req | headers, res, context }` built by hand; read-only without `res`), or over a token the caller already holds. No framework, no peer dependency. The same entry exposes the driver contract, so any framework can run these sessions.

Import path: `unjwt/session`

Exports: `defineJWSSession`, `defineJWESession`, `defineSessionDriver`; types `WebSessionEvent`, `SessionRequestEvent`, `SessionHandedToken`, `SessionDriver`, `CookieJar`, `CookieAttributes`, `SessionDefinition`, `OpenedSessionState`, `SessionManager`, `SessionClaims`, `SessionData`, `SessionUpdate`, `SessionUpdateTrigger`, `SessionIssueOptions`, `SessionConfigJWS`/`SessionConfigJWE`, `SessionHooksJWS`/`SessionHooksJWE`, `SessionJWS`/`SessionJWE`, `SessionSignOptions`, `SessionVerifyOptions`, `SessionEncryptOptions`, `SessionDecryptOptions`. Also re-exports `generateJWK`, `thumbprint`, `importPEM`, `exportPEM`, `deriveJWKFromPassword` and every core type.

The session manager, config options, hooks, cookie layout, chunking, lifetime, `typ` and key rules are shared by every entry (Elysia's `adapters-elysia.md` documents them in full); what is specific to this entry is listed here.

## What `use()` takes: `WebSessionEvent`

```ts
type SessionRequestEvent = { res?: { headers: Headers }; context?: Record<string, unknown> } & (
  | { req: Request; headers?: Headers } // an h3 v2 event, Nuxt's RequestEvent
  | { headers: Headers; req?: Request } // a Request itself, a crossws upgrade request
); // no res = read-only

interface SessionHandedToken {
  token: string | undefined; // a token in hand
}

type WebSessionEvent = SessionRequestEvent | SessionHandedToken;
```

`req` is read first, `headers` otherwise; an event with neither, or an empty object, throws `ERR_SESSION_CONFIG_INVALID`. State: `event.context.sessions` when a `context` is given (the h3 slot, shared with middleware on the same event), else a `WeakMap` keyed on `req`, on the object passed, or on the `{ token }` object. An h3 v2 `H3Event` and Nuxt's `RequestEvent` match by `req`; a `Request`, and a crossws 0.3 or 0.4 upgrade request (both carry `headers` and `context`), match by `headers` as they are.

## Signatures

```ts
function defineJWSSession<
  T extends Record<string, any> = SessionClaims,
  MaxAge extends ExpiresIn | undefined = ExpiresIn | undefined,
  TEvent extends WebSessionEvent = WebSessionEvent,
>(config: SessionConfigJWS<T, MaxAge, TEvent>): SessionDefinition<T, MaxAge, TEvent>;

function defineJWSSession<
  T extends Record<string, any> = SessionClaims,
  MaxAge extends ExpiresIn | undefined = ExpiresIn | undefined,
  TEvent = WebSessionEvent,
>(
  config: SessionConfigJWS<T, MaxAge, TEvent>,
  options: { driver: SessionDriver<TEvent> },
): SessionDefinition<T, MaxAge, TEvent>;
// defineJWESession: same two signatures over SessionConfigJWE
```

`TEvent` is inferred from the driver; without `{ driver }` it is `WebSessionEvent`, or the third generic when given (`defineJWESession<Data, MaxAge, H3Event>(config)`: `use()` then takes that event only). Hooks receive `{ event: TEvent }` whatever the driver: the entry names the hook argument, not the driver. `onVerifyKeyLookup` / `onUnsealKeyLookup` get `event` only from `use()` (typed `event?: TEvent`); `open()` passes none and resolves to `{ id, createdAt, expiresAt, data }`. Default `name`: `"unjwt-jws"` / `"unjwt-jwe"`. `cookie` takes `CookieAttributes & { chunkMaxLength? }`. Error messages start with `[unjwt/session]` (a custom driver's `prefix` otherwise).

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

- Reads the session header when `req.headers` carries it, else the `Cookie` (parsed once per `use()`).
- Writes `Set-Cookie` onto `res.headers`, replacing an earlier line of the same name, domain and path (and partition); unrelated lines stay. A second `update()` in one request leaves one line per cookie; `clear()` leaves the `Max-Age=0` line.
- Hono: pass `c.req.raw` as `req` and return `new Response(body, { headers })`.
- Nuxt 4.6+: `defineEventHandler` from `nuxt/server` (not h3's auto-import) hands a `RequestEvent` that goes to `use(event)` as is, on Nitro 2 and 3; key it from `deriveSecret()` of `nuxt/server` (32 HKDF bytes as hex → `oct` JWK, created lazily since it needs the runtime config).

## Read-only: a `Request`, `{ req }` or `{ headers }` without `res`

Reads work. On a cookie session `update()` throws `ERR_SESSION_READONLY_EVENT` (`Cannot update session on read-only event.`); `clear()` empties the session for the rest of the request, fires `onClear` and resolves, writing nothing (an `onRead` revocation clears with no gate); an expired token fires `onExpire` without dropping the cookie; `rolling` does not reissue. With `cookie: false`, `update()` re-mints onto `session.token`. WebSockets: in `upgrade`, `use(request)` reads (crossws 0.3's plain request and 0.4's `Request` both carry `headers` and `context`); to write, `use({ headers: request.headers, context: request.context, res: { headers } })` then `return { headers }`: the `101` handshake carries a roll, an expired cookie's drop or a `clear()` made during the read. Read once there, copy what the socket needs onto `request.context` (= `peer.context` later); nothing can be written after the upgrade. crossws 0.4 (Nitro 3) merges returned headers with `set`, so keep the session under one cookie there.

## Token in hand: `{ token }`

```ts
const session = await useSession.use({ token: message.body.session });
await session.update({ seen: true });
send(session.token); // the new token; sending it is the caller's job
```

- Full read lifecycle: `onRead`/`onExpire`/`onError`, `rolling` (with `trigger: "rolling"`).
- `update()` re-mints onto `session.token`, writes nothing. `clear()` leaves an empty session, `token` `undefined`.
- Config `cookie`/`sessionHeader` are not consulted: works on a token-only config (`cookie: false, sessionHeader: false`) and on a cookie config alike.
- `token({ token })` returns the handed token. `use({ token: undefined })` is an empty session.
- State is keyed on the context object itself.

## Rules for `use()`

1. Pass the framework's event or the incoming `Request`, never an object you built or share between requests.
2. Pass the `res` whose `headers` the response is sent with, or get a read-only session.
3. Call `use()` before the response starts; the library cannot tell when it is too late.
4. Holding a token yourself: `use({ token })`; sending the new token is your job.
5. One name is one cookie: two definitions with one name on one request share state; a JWS and a JWE under one name throw `ERR_SESSION_CONFIG_INVALID`.

## Driver contract

```ts
interface SessionDriver<TEvent> {
  /** Starts every error message. */
  prefix: string;
  /** A record unique to the request: session state and the name registry. */
  state(event: TEvent): Record<string, unknown>;
  /** A request header by lowercase name. */
  header(event: TEvent, name: string): string | null | undefined;
  cookies(event: TEvent): CookieJar;
  /** `false` once the response was sent: `update()`/`clear()` throw; absent = always open. */
  writable?(event: TEvent): boolean;
  /** `{ token }` when the event carries the token: no cookie or header is consulted. */
  handed?(event: TEvent): { token: string | undefined } | undefined;
}

interface CookieJar<A = { expires?: Date; maxAge?: number }> {
  /** The request's cookie. */
  read(name: string): string | undefined;
  /** This response's value for `name` (`""` once deleted); only when `read` does not see writes. */
  written?(name: string): string | undefined;
  /** Sets a cookie, replacing an earlier write of the same cookie; absent = no cookie: `update()` throws, `clear()` empties state. */
  write?(name: string, value: string, attrs: A): void;
}

function defineSessionDriver<TEvent>(driver: SessionDriver<TEvent>): SessionDriver<TEvent>;
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

- `state(event)` must return an object unique to the request (`event.locals`, `event.context`, a `WeakMap` keyed by the request). A module-level or shared object leaks sessions across requests.
- `write` must replace, not append: a re-issue in the same request writes the same names again.
- Writes arrive one cookie at a time: base cookie, chunks `name.1…N`, `Max-Age=0` for surplus.
- Shipped drivers: h3 (state on `event.context.sessions`, `writable` from Node `headersSent`, v2 stages cookies in `res.errHeaders`), Elysia (state keyed by `Request`, reactive jar, no `written`), `unjwt/session` (state on `event.context.sessions`, else keyed by `req`, the object passed or the `{ token }` object; `handed`).

## Frameworks

- h3 v2 (`new H3()`): the `H3Event` goes to `use()` as is. A thrown handler sends `res.errHeaders` only: keep the cookie with `hooks: { onUpdate: stage, onClear: stage }` where `stage` copies `event.res.headers.getSetCookie()` into `event.res.errHeaders` (`{ event }` is the hook arg; `defineJWESession<Data, MaxAge, H3Event>(config)` narrows `event` so it typechecks).
- Nitro 3: same event; no auto-imports (`defineHandler`, `defineWebSocketHandler`, `HTTPError` from `nitro`, `readBody` from `nitro/h3`); Nitro's error handler drops prepared headers on a throw.
- Nuxt 4.6+/5: handlers must come from `nuxt/server` (`defineEventHandler`, `readBody`, `createError`), whose `RequestEvent` goes to `use()` as is on Nitro 2 and 3; h3's auto-imported handler passes the h3 v1 event, refused with `ERR_SESSION_CONFIG_INVALID`. Key from `deriveSecret()` (lazy, needs runtime config). WebSockets: `defineWebSocketHandler` is h3's; read once in `upgrade` with `{ headers: request.headers, context: request.context, res: { headers } }`, `return { headers }` (+ `context` on crossws 0.4 / Nitro 3, thrown `Response` to refuse; written onto `request.context`, returned `Response` to refuse on crossws 0.3 / Nitro 2).

## Error codes

| Code | When |
| --- | --- |
| `ERR_SESSION_KEY_INVALID` | `key` missing, a password string, wrong shape, or not importable. |
| `ERR_SESSION_CONFIG_INVALID` | Bad `name`/`sessionHeader`, `__Host-`/`__Secure-` violation, an event whose `req` is not a web `Request` (Nuxt handler not from `nuxt/server`), `use(event)` with no token source, unpinned `CryptoKey`, over 16 chunks, JWS + JWE under one `name`. |
| `ERR_SESSION_READONLY_EVENT` | `update()` on a cookie session opened without a `res`; `update()`/`clear()` once a driver's `writable()` is `false`. |
| `ERR_INVALID_OPTION` | `update()` data not a plain object, or a `__proto__`-like key. |

An unreadable incoming token goes to `onError` as `ERR_SESSION_TOKEN_INVALID` and its cookie is dropped (kept only when a key lookup hook threw); an expired one, cookie dropped too, to `onExpire`. Neither throws from `use()`.
