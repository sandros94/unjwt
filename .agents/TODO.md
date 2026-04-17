# Planned changes

## v0.7.0 — security & DX hardening

Milestones M1–M10 of the 2026-04-16 security & DX refactor are complete on the
`v0.7.0-security` branch, one commit per milestone. Before the PR is squash-merged
and tagged, the items below are still open.

### M11 — `importKey` public/private intent (S10) · `planned`

`importKey` has no `expect: "public" | "private"` hint; `jwkTokey` derives Web Crypto
`keyUsages` purely from the JWK's shape (`d` present → `["sign"]`, else `["verify"]`).
A caller who accidentally passes a private JWK to a verify / encrypt path imports
the private material into that context before any downstream check catches the
usage mismatch.

**Fix — both layers:**

1. **Public-facing (Option A):** add `expect?: "public" | "private"` to `importKey`'s
   options object. Strict rejection semantics:

- `expect: "public"` + JWK contains `d` → throw `ERR_JWK_INVALID` with a clear
  message ("private JWK passed to a public-key context; strip `d`/CRT fields
  before import").
- `expect: "private"` + JWK lacks `d` → throw `ERR_JWK_INVALID` ("public JWK
  passed to a private-key context").
- `expect` omitted → current shape-driven behaviour.
- Not applicable to symmetric (`oct`) JWKs — ignored there.

2. **Implicit threading (Option B):** entry points pin `expect` automatically:

- `verify()` → `{ expect: "public" }` on the resolved key / candidates.
- `encrypt()` asymmetric algs (RSA-OAEP\*, ECDH-ES\*) → `{ expect: "public" }`.
- `sign()` → `{ expect: "private" }`.
- `decrypt()` asymmetric algs → `{ expect: "private" }`.
- JWKSet paths apply element-wise to each candidate.

**No silent stripping.** Callers who deliberately want to feed a private JWK to a
public-key context can strip `d`/CRT fields themselves in one line (`const { d, p,
q, dp, dq, qi, ...pub } = jwk`). Silent stripping masks genuine mistakes.

**Cache:** `WeakMapJWKCache` key becomes `(jwk, alg, expect)` so the same JWK
imported as public vs. private doesn't alias.

**Type-first:** where feasible, narrow the return type so `expect: "public"` yields
a `CryptoKey` with `readonly usages: readonly ["verify" | "encrypt" | …]` — making
downstream usage mistakes unrepresentable at the call site.

**Breaking:** callers passing a private JWK to `verify`/`encrypt` (or a public JWK
to `sign`/`decrypt`) now throw immediately instead of relying on a later crypto
error. This is the intended hardening.

**Tests:** one per matrix cell — `{ public, private } × { expect: public, expect:
private, omitted }` — plus one test per entry point confirming the implicit
threading rejects the wrong-shape input.

---

### Pre-merge audit

- [ ] Run `pnpm vitest run --coverage --coverage.skipFull`; eyeball gaps around the
      M1–M11 surface changes.
- [ ] Prune regression tests that duplicate pre-existing behaviour tests — several
      M1–M11 commits added focused tests that may overlap with earlier coverage.
- [ ] Reconfirm MEMORY.md's "genuinely unreachable lines" list; some of those paths
      changed shape across v0.7.0 (especially `jwk.ts` after M6 / M7.5 / M11 and the
      `jws.ts`/`jwe.ts` loops after M3 / M11).
- [ ] Exercise the deprecated `importFromPEM` / `exportToPEM` aliases at least once
      (a regression test already lives in `test/jwk.test.ts` — verify it still runs
      after the audit's pruning pass).
- [ ] Publish via `pkg.pr.new` and smoke-test in a downstream Nuxt/Nitro project
      before tagging.

---

## Parking lot — v0.8.0+

From the same 2026-04-16 review, not scoped for v0.7.0:

- **S7, S8** — `getJWKFromSet` single-key / duplicate-kid hardening. `verify`/`decrypt`
  already migrated to `getJWKsFromSet`; exposure is limited to direct callers.
- **D4** — `importKey` overload cleanup (unify positional vs. options-object shapes).
- **D5** — README patch documenting the GCM → GCMKW coercion on JWK inputs.
- **D7** — `Uint8Array.toBase64` vs `Buffer` fastpath. **Decision: keep the Buffer
  fastpath** — maintainer benchmarks on Node 22/24, Deno 2.x, Bun 1.3 show substantial
  gains. Remaining action: short comment in `utils/index.ts` explaining the fastpath
  so a future "cleanup" PR doesn't remove it.

## Deferred to later major versions

- **Remove `importFromPEM` / `exportToPEM` deprecated aliases** — retained in v0.7.0
  for migration ergonomics. Drop in v1.0.0 or earlier-signalled major.
- **Remove `getJWKFromSet`** (D6) — already `@deprecated`; drop when convenient.

## New implementations

### JWE JSON Serialization (RFC 7516 §3.3)

The primitives that enable multi-recipient JWE are in place:

- `deriveSharedSecret` — ECDH derivation per recipient.
- `wrapKey` / `unwrapKey` ECDH-ES — wraps/unwraps CEK per recipient.
- `getJWKsFromSet` — locates recipient keys from a JWKS.

A utility such as `encryptMulti(payload, recipients[], options)` /
`decryptMulti(jweJson, key)` sits naturally above these without requiring further core
changes.
