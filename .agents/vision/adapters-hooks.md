# H3 Adapter Hooks — Long-term Analysis & Fix Tracker

This file records every identified issue with the `SessionHooks` interfaces and their callsites across
`src/adapters/h3v1/session/jws.ts`, `src/adapters/h3v1/session/jwe.ts`,
`src/adapters/h3v2/session/jws.ts`, and `src/adapters/h3v2/session/jwe.ts`.

Each item carries a status: **open** (untouched) · **planned** (design agreed) · **done** (shipped).

> **Versioning policy:** these adapters are still in active refinement and many hook-shape changes
> are not yet published. All fixes here — even technically breaking ones — are treated as bug fixes,
> not semver-breaking changes. The core JWT library is stable; these are adapter-level issues.

---

## Design directions (agreed, not yet implemented)

### D-1 — Type-generic event parameter · `done`

All hook `event` fields currently hardcode concrete event types. For a type-first library the
event type should be inferred through a generic parameter that flows from the function signature
down to every hook arg.

**h3v1:** `CompatEvent` (`{ request/headers: Headers; context: any }`) and `H3Event` are unrelated
types with no subtype relationship, so the constraint is a genuine union:

```ts
// h3v1
export interface SessionHooksJWS<
  T extends Record<string, any> = SessionClaims,
  MaxAge extends ExpiresIn | undefined = ExpiresIn | undefined,
  TEvent extends CompatEvent | H3Event = CompatEvent | H3Event,
> { ... }
```

**h3v2:** `H3Event extends HTTPEvent` (H3Event adds `.res`), so `HTTPEvent | H3Event = HTTPEvent`
by subtype absorption — the constraint collapses to:

```ts
// h3v2
export interface SessionHooksJWS<
  T extends Record<string, any> = SessionClaims,
  MaxAge extends ExpiresIn | undefined = ExpiresIn | undefined,
  TEvent extends HTTPEvent = HTTPEvent,
> { ... }
```

**Default reasoning:** both adapters default to the broadest admissible event type
(`CompatEvent | H3Event` and `HTTPEvent` respectively). This means hook implementations receive
the least-privileged event by default and must narrow (e.g. with `hasWritableResponse`) if they
need `.res`. This is the correct safe default — hooks that assume a writable event should opt in
explicitly rather than relying on an implicit default.

**Impact:**

- Removes all `as H3Event` casts in h3v1 (issue I-A).
- Allows `onUpdate` and `onClear` to accept the broad event type, removing the dependency on
  `hasWritableResponse` for hook calls (see D-2 / issues O-1, O-7).
- Fully backwards-compatible since defaults match current broadest-type behavior.

---

### D-2 — `hasWritableResponse` must only gate cookie operations, not hook calls · `done`

The current h3v2 `updateJWSSession` and `clearJWSSession` gate both cookie-setting and the hook
call behind `hasWritableResponse(event)`:

```ts
// current — wrong
if (hasWritableResponse(event)) {
  if (config.cookie !== false) { setChunkedCookie(...); }
  await config.hooks?.onUpdate?.({...});   // ← silently skipped for WS/SSE events
}
```

The intended shape is:

```ts
// target
if (config.cookie !== false && hasWritableResponse(event)) {
  setChunkedCookie(...);
}
await config.hooks?.onUpdate?.({...});   // always fires — hooks are notifications, not cookie ops
```

**Rationale:** for OAuth 2.1 endpoints that set `cookie: false` and return the token as a JSON
body, the event _is_ an `H3Event` (regular HTTP, writable), so `onUpdate` already fires correctly
today. The real gap is WebSocket/SSE sessions where `hasWritableResponse` is false: the token is
signed and cached in `session.token`, but `onUpdate`/`onClear` never fire — enterprise
DB-tracking hooks miss those updates entirely. Cookies are the only thing that truly requires a
writable response; hook calls are pure side-effect notifications.

**Pre-condition:** D-1 must land first so that `onUpdate`/`onClear` can accept the broad event
type without being forced into the `H3Event`-narrowed scope.

---

### D-3 — Structured error codes in core utilities · `done`

Issues O-5 and O-6 both stem from the adapter having to parse error messages to distinguish
expiry errors from other errors, and from the decoded-but-rejected JWT claims being discarded
before the hook fires. The fix lives in the core `unjwt/jws` and `unjwt/jwe` modules:

1. **Add an error code** (e.g. `ERR_JWT_EXPIRED`, `ERR_JWT_CLAIM_INVALID`, `ERR_JWS_SIGNATURE`)
   to thrown errors — either via a custom `JWTError` class with a `code: string` property, or
   by attaching the code directly: `Object.assign(new Error("..."), { code: "ERR_JWT_EXPIRED" })`.

2. **Attach decoded claims to `cause`** for expiry errors: the JWT was cryptographically valid
   (signature OK) but its `exp` is in the past, which means the full payload — including `jti`,
   `iat`, `exp` — was decoded before the check failed. Exposing those in `error.cause` lets the
   adapter (and hook implementors) access the expired token's `jti` without re-decoding
   `session.token` manually.

```ts
throw Object.assign(new Error("Token has expired"), {
  code: "ERR_JWT_EXPIRED",
  cause: { jti, iat, exp }, // claims decoded from the expired token
});
```

3. The **adapter routing** then becomes structural, not textual:

```ts
// current — fragile
error_.message.includes("Token has expired") ||
  error_.message.includes("Token is too old")(
    // target — stable
    error_ as any,
  ).code === "ERR_JWT_EXPIRED";
```

**Impact:** closes O-5 (session.id available via `error.cause.jti`) and O-6 (no more string
matching). Requires coordinated changes to `src/core/jws.ts`, `src/core/jwe.ts`, and all four
adapter files.

---

## Open issues

### O-1 — `onUpdate` silently skipped for non-writable h3v2 events · `done`

**Fix:** D-1 + D-2. No further design needed.

**File:** `src/adapters/h3v2/session/jws.ts`, `src/adapters/h3v2/session/jwe.ts`
**Severity:** high — enterprise token-tracking hooks miss every WebSocket/SSE session update.

---

### O-2 — `session.data` not rolled back on sign/seal failure · `planned`

In `updateJWSSession`, `Object.assign(session.data, update)` runs before the try-catch that wraps
`signJWSSession`/`sealJWESession`. If signing fails, `id`/`createdAt`/`expiresAt`/`token` are
rolled back but `session.data` retains the new values. The session stays in context in a split
state (new data, old metadata). Consequences:

- `onError` receives a session where `session.data` looks like the intended "after" state but
  `session.id` and `session.token` are the old values — misleading for hooks.
- A subsequent `getSession` call in the same request sees the same split state.
- Accumulative mutations (array push, counter increment) applied before a sign failure remain
  visible even though the token that would have encoded them was never issued.

**Fix approach:** snapshot `session.data` with `structuredClone(session.data)` before mutations and
restore it in the catch block. `structuredClone` is part of the HTML spec and is available in all
target runtimes: Node ≥17, Deno, Bun, modern browsers, and Cloudflare Workers. Earlier concerns
about runtime-agnosticism that deferred this fix are no longer constraints as of 2026.

**File:** all four adapter files.
**Severity:** medium — split state is self-healing on the next request; harmful mainly for
in-request retry patterns and accumulative mutation payloads.

---

### O-3 — `oldSession.data` snapshot is shallow — nested objects are shared references · `planned`

`const oldSession = { ...session, data: { ...session.data } }` copies only one level.
If `session.data` contains nested objects and the update modifies a property on one of them,
`oldSession.data` already reflects that change by the time `onUpdate` fires. Enterprise hooks
that deep-compare `session.data` vs `oldSession.data` to compute a diff receive a wrong "before"
snapshot for any nested field.

**Fix approach:** replace the one-level spread with `structuredClone(session.data)`.
`structuredClone` is part of the HTML spec and is available in all target runtimes (Node ≥17,
Deno, Bun, modern browsers, Cloudflare Workers) — the prior runtime-agnosticism concern no
longer applies. Implement alongside O-2 so the two snapshot strategies stay aligned.

**File:** all four adapter files.
**Severity:** low-medium — only affects hooks that deep-compare `session.data` vs `oldSession.data`.

---

### O-4 — `onRead` fires after `onExpire`/`onError`; and `onExpire` fires twice on the cached-expiry path · `done`

`onRead`, `onExpire`, and `onError` must be **mutually exclusive**. `onRead` means "a session was
successfully established for this request". If the incoming token triggered `onExpire` or `onError`,
no session was successfully established — those hooks already covered the event.

There are two distinct bugs to fix, both rooted in the same lifecycle:

#### Bug A — Double `onExpire` on the cached-session expiry path, plus a wasteful `onClear`

When the existingSession path detects expiry, the current code clears the session and recurses:

```ts
// current
await config.hooks?.onExpire?.({...});           // fires once ✓
return clearJWSSession(event, config).then(() => // fires onClear ✗ — wrong semantic
  getJWSSession(event, config)                   // re-runs full token lookup ✗
);
```

Two problems cascade from this:

**1. `onClear` is mis-fired.** `clearJWSSession` bundles cleanup (context deletion + cookie expiry)
with the `onClear` notification. In the expiry path that notification is semantically wrong:

- `onExpire` = token's natural lifetime ended (clock-based; RFC 7519 "MUST NOT be accepted")
- `onClear` = session explicitly terminated by user or system action (logout, forced invalidation)

These must be mutually exclusive for any given jti. When `onExpire` fires and then `clearJWSSession`
also fires `onClear`, an enterprise hook doing DB-level revocation in `onClear` executes a second
`db.revoke(session.id)` call for the same jti that `onExpire` already revoked — wasteful at best,
an audit anomaly or double-delete error at worst.

**2. Double `onExpire` from the recursive `getJWSSession`.** After `clearJWSSession`, the response
carries a clearing Set-Cookie (empty value, `expires: new Date(0)`). However, `getJWSSessionToken`
skips this because `findSetCookie`'s regex requires at least one non-semicolon character after `=`,
so the empty-value cookie is not matched. It falls through to `getChunkedCookie`/`parseCookies`,
which reads from the **incoming** request — and finds the same expired token again. The recursive
call re-enters the verify/unseal promise path, gets a second expiry error, and `onExpire` fires a
second time for the same request.

**Fix:** replace both `clearJWSSession` and the recursive `getJWSSession` with inline cleanup +
direct session initialization. This keeps `onClear` exclusively for explicit user-initiated
terminations and prevents the second token lookup.

Conceptually (adapter-specific details noted below):

```ts
await config.hooks?.onExpire?.({...});

// Inline cleanup — bypasses clearJWSSession so onClear is not mis-fired.
// Delete from context always; only clear the cookie when the response is writable.
deleteSessionFromContext(event, sessionName);
if (config.cookie !== false && isResponseWritable(event)) {
  clearSessionCookie(event, sessionName);   // setChunkedCookie (h3v2) / setCookie (h3v1)
}

// Fresh session directly — no recursive getJWSSession, no token lookup, no hooks.
const freshSession = createEmptySession(config);
storeSessionInContext(event, sessionName, freshSession);
return freshSession;
// result: onExpire fires once, onClear never fires, no second onExpire, no onRead
```

**Adapter differences:**

- **h3v2:** uses `getEventContext(event)` → `context.sessions`, `setChunkedCookie`, `hasWritableResponse(event)`.
- **h3v1:** uses `event.context.sessions` directly, `setCookie`; no `hasWritableResponse` (the
  existingSession expiry block is already behind `isEvent(event)`, so the event is always H3Event
  at that point — the cookie clearing can run unconditionally).

**h3v1-specific nuance:** the existingSession expiry check in h3v1 has `&& isEvent(event)`. For
CompatEvents the entire block is skipped and the expired session is returned as-is with no hook
fired. After D-1 lands, `onExpire` is a notification that should fire regardless of event type —
only the cookie clearing is conditional. The `isEvent` guard should be removed and the cleanup
replaced with the adapter-appropriate writability check (see I-C).

**Semantic contract after this fix:**

- Expiry path: only `onExpire` fires.
- Explicit clear path (`session.clear()`): only `onClear` fires.
- The two hooks are mutually exclusive by design — enterprise revocation logic should live in one
  or the other, never both.

#### Bug B — `onRead` fires after `onError` with an inconsistent session state

In the new-session promise path, when verify/unseal fails for a non-expiry reason:
`onError` fires → `.then()` receives `undefined` → session stays as `{ id: undefined, token: invalid-token }` → `onRead` fires.

`session.token` is the rejected token but `session.id` is `undefined`. The hook receives a session
where the two fields are contradictory.

**Fix:** track whether a mutually-exclusive hook fired and skip `onRead`:

```ts
let exclusiveHookFired = false;

const promise = verifyJWSSession(...)
  .catch(async (error_) => {
    exclusiveHookFired = true;
    if (isExpiry(error_)) {
      await config.hooks?.onExpire?.({...});
    } else {
      await config.hooks?.onError?.({...});
    }
    return undefined;
  });
await promise;

if (!exclusiveHookFired) {
  await config.hooks?.onRead?.({session, config, event});
}
```

Note: Bug A (the recursive call replacement) is handled separately from this flag. After Bug A is
fixed, the flag still covers two cases in the promise catch: the verify-failure `onExpire` path
(path 2 — token had valid signature but expired `exp`) and the `onError` path. Both must suppress
`onRead`, and the single `exclusiveHookFired = true` before either branch handles both.

**File:** all four adapter files.
**Severity:** high (Bug A — double `onExpire` is a real hook mis-fire) · medium (Bug B — phantom `onRead`).

---

### O-5 — `onExpire` path 2: `session.id` is `undefined` despite claims being decodable · `done`

**Fix:** D-3 (structured error with `cause: { jti, iat, exp }`).

When a token's `exp` has passed, the JWT was fully decoded (including `jti`) before the error was
thrown. Attaching the decoded claims to `error.cause` lets the adapter populate `session.id` (and
`session.expiresAt`) on the placeholder session before firing `onExpire`.

**Note on tracking strategy:** per the OAuth/JWT specs, a token with an expired `exp` MUST NOT be
accepted. An enterprise implementation that needs to clean up expired jtis from a revocation list
should store `{ jti, exp }` in their DB when `onUpdate` fires (i.e. on issuance). `onExpire` would
then only need `session.id` to look up and invalidate the record — no need to re-derive `exp` from
the error. The D-3 fix makes `session.id` available in the hook for this lookup.

**File:** all four adapter files + `src/core/jws.ts`, `src/core/jwe.ts` (for D-3).
**Severity:** medium — `session.token` is still available for manual decoding as a workaround.

---

### O-6 — Expiry routing by error message string matching is fragile · `done`

**Fix:** D-3 (structured error codes).

```ts
// current — breaks silently if error wording changes
error_.message.includes("Token has expired") ||
  error_.message.includes("Token is too old")(
    // target after D-3
    error_ as any,
  ).code === "ERR_JWT_EXPIRED";
```

**File:** all four adapter files + `src/core/jws.ts`, `src/core/jwe.ts`.
**Severity:** low-medium — stable today; risk materialises on any refactor of core error messages.

---

### O-7 — `onClear` silently skipped for non-writable h3v2 events on explicit clear · `done`

**Fix:** D-1 + D-2. Same root cause as O-1.

When `session.clear()` is called on a WebSocket/SSE event in h3v2, `clearJWSSession` hits the
`hasWritableResponse` gate and `onClear` never fires. Enterprise revocation hooks miss explicit
logouts on non-writable events.

Note: the earlier concern about the expiry→clear path is resolved by O-4 Bug A. Once Bug A is
fixed, the expiry path never calls `clearJWSSession` at all — `onClear` intentionally does not
fire for natural expiry (only `onExpire` does). O-7 is therefore scoped exclusively to the
`session.clear()` path.

**File:** `src/adapters/h3v2/session/jws.ts`, `src/adapters/h3v2/session/jwe.ts`
**Severity:** high — same root cause as O-1.

---

### O-8 — `onClear` receives `Partial<SessionConfig>` while all other hooks receive full config · `done`

`clearJWSSession`/`clearJWESession` accept `Partial<SessionConfig>`, so `onClear` also receives a
partial config. Every other hook receives the full config. The fix is simply to pass the full
`SessionConfig` to `onClear` — this tightens safety and removes the inconsistency. Direct callers
of `clearJWSSession` who currently rely on partial config will need to supply the full object, but
this is the correct constraint for a safe API.

**File:** all four adapter files.
**Severity:** low — minor ergonomic inconsistency; the fix is straightforward.

---

### I-A — h3v1 CompatEvent cast is a type-system lie propagated through all hook calls · `done`

**Fix:** D-1.

All h3v1 hook invocations cast `event as H3Event`. In code paths reachable by `CompatEvent`,
the hook receives an object that is not an `H3Event` but is typed as one. Becomes a non-issue
once D-1 is implemented and the cast is replaced by the inferred `TEvent`.

**File:** `src/adapters/h3v1/session/jws.ts`, `src/adapters/h3v1/session/jwe.ts`
**Severity:** low — blocked by D-1.

---

### I-C — h3v1 `isEvent` guard suppresses `onExpire` entirely for CompatEvents · `done`

**Fix:** D-1 (remove the guard after the event generic lands).

In h3v1 `getJWSSession`, the existingSession expiry check is:

```ts
if (session.expiresAt !== undefined && session.expiresAt < Date.now() && isEvent(event)) {
```

The `&& isEvent(event)` condition means that for CompatEvents (read-only events, e.g. WebSocket
upgrades), an expired cached session is silently returned as-is: `onExpire` never fires, nothing
is cleared, and the caller receives a token that MUST NOT be used per RFC 7519. There is no
mechanism for the caller to know the session is stale.

The guard was originally motivated by "you can't write a clearing cookie on a read-only event",
which is true — but that only applies to the cookie operation, not to the `onExpire` notification.
After D-1 and D-2, the correct behavior for all event types is:

- Fire `onExpire` unconditionally.
- Skip the cookie clearing if the response is not writable.
- Initialize and return a fresh empty session.

The `isEvent` guard on the expiry check should be removed entirely once D-1 is implemented.

**File:** `src/adapters/h3v1/session/jws.ts`, `src/adapters/h3v1/session/jwe.ts`
**Severity:** medium — expired sessions are silently returned as valid on CompatEvents; enterprise
hooks that enforce token lifetimes on WS upgrades receive no signal.

---

### I-B — `onRead` fires multiple times per request under concurrent `useSession` calls · `open` (docs)

Each call to `useJWSSession`/`useJWESession` triggers `getJWSSession`. Concurrent calls in the
same handler hit the existingSession path and fire `onRead` again. This is correct semantically
but enterprise hooks using `onRead` for rate limiting or audit logging receive duplicate signals.

**Fix:** document in hook JSDoc — implementors should deduplicate using `session.id` if needed.
No code change required.

**File:** all four adapter files.
**Severity:** low — informational.

---

## Summary table

| ID  | Hook               | Adapter | Severity    | Status      | Blocked by / Linked to                             |
| --- | ------------------ | ------- | ----------- | ----------- | -------------------------------------------------- |
| D-1 | all                | all     | —           | planned     | —                                                  |
| D-2 | onUpdate, onClear  | h3v2    | —           | planned     | D-1                                                |
| D-3 | onExpire, onError  | all     | —           | planned     | core: jws.ts, jwe.ts                               |
| O-1 | onUpdate           | h3v2    | high        | open        | D-1, D-2                                           |
| O-2 | onError            | all     | medium      | planned     | `structuredClone` (Node ≥17 / all target runtimes) |
| O-3 | onUpdate           | all     | low-medium  | planned     | `structuredClone`; implement with O-2              |
| O-4 | onRead/onExpire    | all     | high+medium | open        | —                                                  |
| O-5 | onExpire           | all     | medium      | open        | D-3                                                |
| O-6 | onExpire / onError | all     | low-medium  | open        | D-3                                                |
| O-7 | onClear            | h3v2    | high        | open        | D-1, D-2                                           |
| O-8 | onClear            | all     | low         | planned     | —                                                  |
| I-A | all                | h3v1    | low         | open        | D-1                                                |
| I-B | onRead             | all     | low         | open (docs) | —                                                  |
| I-C | onExpire           | h3v1    | medium      | open        | D-1                                                |
