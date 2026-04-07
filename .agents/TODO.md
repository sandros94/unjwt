# Planned changes

## New implementations

### JWE JSON Serialization (RFC 7516 §3.3)

The primitives that enable multi-recipient JWE are all in place:

- `deriveSharedSecret` — ECDH derivation per recipient
- `wrapKey`/`unwrapKey` ECDH-ES — wraps/unwraps CEK per recipient
- `getJWKsFromSet` — locates recipient keys from a JWKS

A future utility to derive all recipient keys and perform encryption/decryption, such as `encryptMulti(payload, recipients[], options)` / `decryptMulti(jweJson, key)`, sits naturally above these without requiring further core changes.
