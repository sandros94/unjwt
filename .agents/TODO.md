# Planned changes

## Deferred to later major versions

- **Remove `importFromPEM` / `exportToPEM` deprecated aliases** — already `@deprecated`, drop when convenient.
- **Remove `getJWKFromSet`** — already `@deprecated`, drop when convenient.

## New implementations

### JWE JSON Serialization (RFC 7516 §3.3)

The primitives that enable multi-recipient JWE are in place:

- `deriveSharedSecret` — ECDH derivation per recipient.
- `wrapKey` / `unwrapKey` ECDH-ES — wraps/unwraps CEK per recipient.
- `getJWKsFromSet` — locates recipient keys from a JWKS.

A utility such as `encryptMulti(payload, recipients[], options)` / `decryptMulti(jweJson, key)` sits naturally above these without requiring further core changes.
