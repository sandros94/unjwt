# Planned changes

## v0.7.0 — security & DX hardening

Findings from the 2026-04-16 full-codebase review. All milestones ship in a **single PR**
(`v0.7.0-security`), one commit per milestone, testable via `pkg.pr.new` once the branch
is stable. The maintainer squash-merges and tags the release. Every milestone must:

- keep the library type-first (no loss of inference, no `any` leaks);
- add **focused** regression tests for the new behavior (not exhaustive new suites);
- update `skills/unjwt/` reference docs when public signatures or types change;
- update `README.md` where user-visible behavior changes.

Semver: the aggregate batch is behavior-breaking for some callers — ships as `v0.7.0`.

---

### M1 — Claim validation hardening (S1 + S2) · `planned`

Combined into one PR because they share the same call site and tests.

**S1 — default claim validation on JSON-object payloads.**

- **File:** `src/core/jws.ts:283-292`, `src/core/jwe.ts:385-394`
- **Problem:** `validateJwtClaims` only runs when `options.validateClaims === true` **or**
  `protectedHeader.typ?.toLowerCase().includes("jwt")`. A signer who omits `typ` (valid
  per RFC 7515) silently disables `exp`/`nbf`/`iss`/`aud` checks on the verifier side.
  Security-critical validation gated on an attacker-controlled header.
- **Fix:** run `validateJwtClaims` whenever the decoded payload is a non-Uint8Array
  object and `options.validateClaims !== false`. Drop the `typ` gate from the condition.
  Keep the explicit `false` opt-out for non-JWT structured payloads.
- **Breaking:** tokens whose payload looks like a JWT but whose signer omitted `typ`
  and whose `exp` is in the past will now throw instead of silently passing.

**S2 — reject non-numeric `exp` / `nbf` / `iat`.**

- **File:** `src/core/utils/jwt.ts:224, 231, 240`
- **Problem:** `typeof === "number"` skips the comparison entirely when the claim is
  present but of the wrong type (`"2000-01-01"`, `null`, `true`, `NaN`). Token with
  `{exp:"expired"}` passes as non-expired.
- **Fix:** if the claim is present, require `Number.isFinite(value)`; otherwise throw
  `ERR_JWT_CLAIM_INVALID`. Only a missing claim skips the check.
- **Breaking:** any existing caller producing non-numeric date claims will fail
  verification (they should — this is an RFC 7519 §4.1.4 requirement).

**Tests:** add two focused cases per module — one for typ-absent-but-claims-present,
one for non-numeric `exp`. Verify existing claim-validation tests still pass without
modification.

---

### M2 — `crit` header scope (S3) · `planned`

- **File:** `src/core/utils/jwt.ts:266, 275, 306-317`
- **Problem:** `BASE_HEADER_PARAMS` treats `jku`, `jwk`, `x5c`, `x5t`, `x5u` as
  implicitly "understood" for `crit` validation, but unjwt does not process any of
  them at verify time (no JWKS fetch, no X.509 chain walk). A signer who lists these
  in `crit` satisfies the library without the verifier actually doing anything.
  Violates RFC 7515 §4.1.11.
- **Fix:** reduce the implicit set to parameters the library actively processes:
  `alg`, `typ`, `cty`, `kid`, `b64` (JWS); add `enc`, `iv`, `tag`, `p2s`, `p2c`,
  `epk`, `apu`, `apv` for JWE. Any other parameter listed in `crit` must be declared
  via `recognizedHeaders`.
- **Breaking:** callers currently producing tokens with `crit:["jku",…]` etc. will
  fail verification unless they pass `recognizedHeaders`. Documented as a deliberate
  tightening.

**Tests:** replace any test relying on the old implicit set with explicit
`recognizedHeaders`; add one negative test per registered-but-unprocessed param.

---

### M3 — JWKSet loop error discipline (S4) · `planned`

- **File:** `src/core/jws.ts:230-245`, `src/core/jwe.ts:334-353`
- **Problem:** `try { … } catch {}` around each candidate swallows everything,
  including `TypeError` from `checkSigCryptoKey`, malformed-JWK throws, and alg/key
  family mismatches. Defense-in-depth silently removed; any future regression in
  pre-crypto checks is masked.
- **Fix:** narrow the catch to expected signature/decryption failures only.
  - JWS: swallow `JWTError` with code `ERR_JWS_SIGNATURE_INVALID` and the WebCrypto
    verification `false` path; rethrow everything else.
  - JWE: swallow `JWTError` with codes `ERR_JWE_DECRYPTION_FAILED`,
    `ERR_JWE_KEY_UNWRAP_FAILED` (add if missing); rethrow malformed-key / alg errors.
- **Supporting work:** introduce `ERR_JWE_KEY_UNWRAP_FAILED` in `src/core/error.ts`
  if it doesn't exist, keep `JWTError` generics for the narrowing guard
  (`error.ts:82-91`).
- **Breaking:** only for callers who rely on the silent-retry behavior with malformed
  JWKSets — desirable surfacing of bugs.

**Tests:** add a test where a JWKSet contains one intentionally malformed JWK plus
one valid JWK — verify that the malformed key raises before reaching the valid one.
Ensure the standard "wrong kid, try next" happy path still works.

---

### M4 — Default algorithm allowlist in verify / decrypt (S5) · `planned`

- **File:** `src/core/jws.ts:193-196`, `src/core/jwe.ts:288-296`
- **Problem:** when `options.algorithms` is omitted, the token's own header chooses
  the algorithm. Standard advice across JWT libraries in 2026 is "always pin".
- **Fix design (type-first):**
  - When `key` is a single JWK/CryptoKey with a resolvable `alg` (or whose `kty`/
    `algorithm.name` uniquely determines a family), infer a default allowlist.
  - When `key` is a JWKSet, derive the allowlist from the union of key `alg` values;
    if any key lacks `alg`, require the caller to pass `algorithms` explicitly and
    throw `ERR_JWS_ALG_NOT_ALLOWED` with a clear message.
  - When `key` is a function, treat as JWKSet-equivalent (require explicit allowlist,
    because the lookup cannot be introspected ahead of time).
  - Expose a helper `inferAllowedAlgorithms(key): string[]` in `unjwt/utils` for
    callers who want to preview the inferred set.
- **Breaking:** tokens whose `alg` no longer matches the inferred allowlist will
  throw instead of attempting verification with a mismatched key.

**Tests:** one test per key shape (JWK, CryptoKey, JWKSet with homogeneous `alg`,
JWKSet with heterogeneous, lookup function). Verify the error points to the missing
`algorithms` option.

---

### M5 — PBES2 bounds (S6) · `planned`

- **File:** `src/core/jwk.ts:606-612`, `src/core/_crypto/_pbes2.ts:36-38`, types
  in `src/core/types/jwk.ts` for `UnwrapKeyOptions`.
- **Problem:** inbound `p2c` validated `>= 1`. No lower bound (allows weak wrapping),
  no upper bound (PBKDF2 DoS).
- **Fix:**
  - Default floor: `p2c >= 1000` (RFC 7518 §4.8.1.2 minimum). Default ceiling:
    `1_000_000`.
  - Add `minIterations` / `maxIterations` options on `UnwrapKeyOptions` and
    `JWEDecryptOptions` so callers can tune per threat model.
  - Throw `ERR_JWE_INVALID` (or new `ERR_JWE_PBES2_BOUNDS`) with a message that
    distinguishes "too low" from "too high".
- **Type-first note:** make sure the option fields are strongly typed as
  `number` (not `Integer` branded) and documented in JSDoc.
- **Breaking:** tokens produced with below-floor `p2c` will fail decryption. This is
  intended.

**Tests:** one above-ceiling, one below-floor, one at the floor. Reuse an existing
PBES2 fixture.

---

### M6 — Error-class normalization (D1) · `planned`

Low-risk diff, big DX win. Can ship last and be squashed cleanly.

- **Files:** `src/core/jwk.ts` (all `throw new Error(...)` / `throw new TypeError(...)`),
  `src/core/jwe.ts:110, 118, 423, 431, 437, 442`, `src/core/jws.ts:68`.
- **Problem:** README/`error.ts:42-45` promise "all errors are `JWTError`". Reality:
  dozens of bare `Error`/`TypeError` throws in `jwk.ts` and the JWE/JWS entry points.
- **Fix rule:**
  - Protocol / crypto / validation failures → `JWTError` with a typed code.
  - TypeScript contract violations (argument of wrong shape/type) → `TypeError`.
  - Nothing else.
  - Add the following codes to `JWTErrorCode` if missing: `ERR_JWS_ALG_MISSING`,
    `ERR_JWE_ALG_MISSING`, `ERR_JWE_ENC_MISSING`, `ERR_JWK_UNSUPPORTED`.
- **Type-first:** update the narrowing guard at `error.ts:82-91` to cover any new
  codes that carry structured `cause`.
- **Breaking:** any caller catching `TypeError` specifically for what is now
  `JWTError` will miss the throw. Document in CHANGELOG.

**Tests:** one test per new code to verify class + code. Don't re-test every existing
error path — trust existing suites to catch regressions on unchanged paths.

---

### M7 — PEM label enforcement (S9) · `planned`

- **File:** `src/core/_crypto/_pem.ts:20-26, 86-87`
- **Problem:** `fromPKCS8` / `fromSPKI` strip BEGIN/END markers but don't require them
  to be present. Raw base64 blobs and blobs with mismatched labels pass through until
  Web Crypto throws an opaque `DataError`. Defensive ergonomics, not an exploit.
- **Fix:** assert the exact expected label is present before stripping. Throw
  `JWTError("…", "ERR_JWK_INVALID")` (or a new `ERR_JWK_PEM_INVALID`) with a
  message that names both the expected label and the one found (if any).
- **Type-first:** no type changes expected; keep the existing signatures.
- **Breaking:** minor — callers feeding unlabeled base64 through these helpers now
  get a clear error instead of `DataError`.

**Tests:** one test per helper for (a) wrong label, (b) no label, (c) correct label.

---

### M8 — `clockTolerance` default (D2) · `planned`

- **File:** `src/core/utils/jwt.ts:176`, `src/core/types/jwt.ts:85`
- **Problem:** `clockTolerance` defaults to `0`, undocumented. Verifier clock drift is
  real; zero tolerance is surprising.
- **Fix:** bump default to `5` seconds. Document the default in JSDoc on
  `JWTClaimValidationOptions.clockTolerance` and in README under the verify snippet.
- **Breaking:** tokens that were previously rejected due to ≤5 s skew now verify.
  Callers can still pass `clockTolerance: 0` to opt back in.

**Tests:** one test confirming a 3 s skew now passes without explicit option, one
test confirming explicit `clockTolerance: 0` still rejects.

---

### M9 — `generateKey` return-type clarity (D3) · `planned`

- **File:** `src/core/jwk.ts:86-95`, `src/core/types/jwk.ts:99-122`
- **Problem:** `generateKey("A256GCM")` returns `CryptoKey` but
  `generateKey("A256CBC-HS512")` returns `Uint8Array`. The conditional return type is
  correct; the asymmetry is surprising at hover time.
- **Fix:** document the split prominently in the `generateKey` JSDoc with concrete
  examples. Verify the conditional return type at `types/jwk.ts:99-122` correctly
  narrows every `TAlg` case — tighten any fallthrough to `CryptoKey | Uint8Array`
  unions where one branch is provable. Leave runtime behavior unchanged.
- **Type-first:** audit the conditional type for each `TAlg`; ensure hover shows the
  concrete branch, not the union, whenever the generic is known.

**Tests:** add an `expectTypeOf` / `assertType` compile-time test per algorithm
family in an existing type-test file (or create `test/types.test-d.ts` if needed).

---

### M10 — `JWSSignOptions.protectedHeader` StrictOmit (D8) · `planned`

- **File:** `src/core/types/jws.ts:38` (and the JWS decrypt-side type if symmetric).
- **Problem:** JWS caller can pass `alg`/`b64` in `options.protectedHeader` and have
  them silently overwritten. JWE already uses `StrictOmit` to forbid this (`types/jwe.ts:94-97`).
- **Fix:** apply `StrictOmit<JWSHeaderParameters, "alg" | "b64">` to `JWSSignOptions.protectedHeader`.
- **Type-first:** ensure the `StrictOmit` helper is already in use in the codebase
  (`types/jwe.ts` imports it). If TS flags callers, the error message should point
  at the forbidden key — verify locally.
- **Breaking:** TS-only breaking change. Runtime behavior unchanged.

**Tests:** no runtime test. Rely on the type checker + one negative type-test if
there's a type-test file.

---

## Parking lot — defer to v0.8.0+ unless quick wins surface

These are from the same review but don't warrant v0.7.0 attention:

- **S7, S8** (`getJWKFromSet` single-key/duplicate-kid) — hardening, not exploitable
  via public `verify`/`decrypt` which already use `getJWKsFromSet`.
- **S10** (public/private intent on `importKey`) — API-shape change. **Dedicated
  design discussion scheduled after M10 ships** — remind the maintainer when the
  v0.7.0 branch is ready to merge.
- **D4** (importKey overload cleanup) — API-shape change, target v0.8.0.
- **D5** (document GCM→GCMKW coercion) — can ship as a README patch any time.
- **D7** (`Uint8Array.toBase64` vs `Buffer`) — decision: **keep the Buffer fastpath**.
  Maintainer benchmarks on Node 22/24, Deno 2.x, Bun 1.3 show substantial perf boost.
  Action item: add a short comment at `utils/index.ts` explaining the fastpath so
  future cleanup doesn't remove it, and confirm the `Uint8Array.toBase64` fallback
  runs in `globalThis.Buffer`-less environments (no action needed in v0.7.0 unless
  incidentally touched).

## Deferred to later major versions

- **Drop `getJWKFromSet` (D6)** — maintainer will remove directly in a future release,
  not part of v0.7.0.

## New implementations

### JWE JSON Serialization (RFC 7516 §3.3)

The primitives that enable multi-recipient JWE are all in place:

- `deriveSharedSecret` — ECDH derivation per recipient
- `wrapKey`/`unwrapKey` ECDH-ES — wraps/unwraps CEK per recipient
- `getJWKsFromSet` — locates recipient keys from a JWKS

A future utility to derive all recipient keys and perform encryption/decryption, such as `encryptMulti(payload, recipients[], options)` / `decryptMulti(jweJson, key)`, sits naturally above these without requiring further core changes.
