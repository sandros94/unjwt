# Planned changes

## v0.7.0 — pre-merge audit

All M1–M13 milestones of the 2026-04-16 security & DX refactor are shipped on the
`v0.7.0-security` branch, one commit per milestone. Remaining before squash-merge:

- [ ] Run `pnpm vitest run --coverage --coverage.skipFull`; eyeball gaps around the M1–M13 surface changes.
- [ ] Prune regression tests that duplicate pre-existing behaviour tests — several M-commits added focused tests that may overlap with earlier coverage.
- [ ] Reconfirm MEMORY.md's "genuinely unreachable lines" list; many paths changed shape across v0.7.0 (especially `jwk.ts` after M6 / M7.5 / M11 / M12 / M13 and the `jws.ts`/`jwe.ts` loops after M3 / M11 / M13).
- [ ] Exercise the deprecated `importFromPEM` / `exportToPEM` aliases at least once (regression test already lives in `test/jwk.test.ts` — verify it still runs after the audit's pruning pass).
- [ ] Publish via `pkg.pr.new` and smoke-test in a downstream Nuxt/Nitro project before tagging.
- [ ] Refresh the PR description to match what actually landed (it was drafted before M7.5 / M11 / M12 / M13 and the revised M8 scope).
- [ ] Draft CHANGELOG for v0.7.0.

---

## Parking lot — v0.8.0+

- **S7, S8** — `getJWKFromSet` single-key / duplicate-kid hardening. Scoped out of v0.7.0 intentionally; the function is already `@deprecated`.

## Deferred to later major versions

- **Remove `importFromPEM` / `exportToPEM` deprecated aliases** — retained in v0.7.0 for migration ergonomics. Drop in v1.0.0 or earlier-signalled major.
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
