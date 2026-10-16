# Web Standard Sessions Reference (`unjwt/session`)

JWT sessions over a Web `Request` and the `Headers` its response is sent with, or over a token
the caller already holds. No framework, no peer dependency. The same entry exposes the driver
contract, so any framework can run these sessions.

Import path: `unjwt/session`

Exports: `defineJWSSession`, `defineJWESession`, `defineSessionDriver`; types `SessionContext`,
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
  | { request: Request; headers?: Headers } // no headers = read-only session
  | { token: string | undefined }; // a token in hand
```

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

## Request and response headers

```ts
import { defineJWESession, generateJWK } from "unjwt/session";

const useSession = defineJWESession({ key: await generateJWK("A256GCM"), maxAge: "7D" });

export default {
  async fetch(request: Request) {
    const headers = new Headers();
    const session = await useSession.use({ request, headers });
    await session.update({ userId: "u_123" });
    return new Response(JSON.stringify(session.data), { headers });
  },
};
```

- Reads the `Cookie` header (parsed once per `use()`), then the session header.
- Writes `Set-Cookie` onto `headers`, replacing an earlier line of the same name, domain and path
  (and partition); unrelated lines stay. A second `update()` in one request leaves one line per
  cookie; `clear()` leaves the `Max-Age=0` line.
- State is kept per `Request` object (`WeakMap`): two `use()` with the same `Request` share it, two
  `Request` objects never do.
- Hono: pass `c.req.raw` and return `new Response(body, { headers })`.

## Read-only: `{ request }` alone

Reads work. On a cookie session `update()`/`clear()` throw `ERR_SESSION_READONLY_EVENT`; an
expired token fires `onExpire` without dropping the cookie; `rolling` does not reissue. With
`cookie: false`, `update()` re-mints onto `session.token`.

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

1. Pass the incoming `Request`, never an object you built or share between requests.
2. Pass the `Headers` the response is sent with, or get a read-only session.
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
  /** `false` once the response can no longer take a Set-Cookie; absent = the jar's `write` decides. */
  writable?(context: TContext): boolean;
  /** `{ token }` when the context carries the token: no cookie or header is consulted. */
  handed?(context: TContext): { token: string | undefined } | undefined;
}

interface CookieJar<A = { expires?: Date; maxAge?: number }> {
  /** The request's cookie. */
  read(name: string): string | undefined;
  /** This response's value for `name` (`""` once deleted); only when `read` does not see writes. */
  written?(name: string): string | undefined;
  /** Sets a cookie, replacing an earlier write of the same cookie; absent = read-only. */
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
  `written`), `unjwt/session` (state keyed by `Request` or the `{ token }` object, `handed`).

## Error codes

| Code                         | When                                                                                                                                                                    |
| ---------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `ERR_SESSION_KEY_INVALID`    | `key` missing, a password string, wrong shape, or not importable.                                                                                                       |
| `ERR_SESSION_CONFIG_INVALID` | Bad `name`/`sessionHeader`, `__Host-`/`__Secure-` violation, `use({ request })` with no token source, unpinned `CryptoKey`, over 16 chunks, JWS + JWE under one `name`. |
| `ERR_SESSION_READONLY_EVENT` | `update()`/`clear()` on a cookie session opened without `headers`.                                                                                                      |
| `ERR_INVALID_OPTION`         | `update()` data not a plain object, or a `__proto__`-like key.                                                                                                          |

An unreadable incoming token goes to `onError` as `ERR_SESSION_TOKEN_INVALID`; an expired one to
`onExpire`. Neither throws from `use()`.
