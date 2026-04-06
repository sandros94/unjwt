# v0.6.0 Breaking-Release — Status

> Last updated after all 12 planned implementation commits.

---

## Committed — all shipped

| Commit    | Message                                                                          |
| --------- | -------------------------------------------------------------------------------- |
| `5683425` | refactor: promote jose fork to internal `_crypto/` implementation                |
| `75478c2` | fix(security): make sanitizeObject non-mutating                                  |
| `6278677` | feat(jwk): configurable JWK import cache via JWKCacheAdapter                     |
| `a5e4c3e` | feat!: type system overhaul                                                      |
| `793f716` | fix!(security): PBES2 iterations default, alg:none guard, kid precedence         |
| `fe7697f` | feat!(jwk): unwrapKey — format discriminant replaces returnAs boolean            |
| `a39b3b8` | feat(jwk): full ECDH-ES support in wrapKey/unwrapKey + deriveSharedSecret export |
| `4d0b4bc` | feat(jwe): wire dir (direct key agreement) algorithm                             |
| `17dd93b` | feat(jwk): importKey — opt-in CryptoKey output for oct JWKs                      |
| `008c200` | feat(jwk): getJWKFromSet single-key auto-resolve + getAllJWKsFromSet             |
| `7738a7e` | feat!(jwk): rename PEM functions + collapse positional params to options object  |
| `a19ee4a` | refactor: extract `_buildJWSHeader`/`_buildJWEHeader` internal utilities         |

---

## Checklist — final state

### Security (P0) — all done ✅

- [x] S-1 Raise PBES2 `p2c` default to 600,000
- [x] S-2 Remove `"none"` from `JWKAlgorithm` + runtime guard in `sign()`
- [x] S-3 Make `sanitizeObject` non-mutating; add missing sanitization in `jwe.ts` encrypt
- [x] S-4 Fix `kid` precedence (user header > JWK fallback) in `sign()` and `encrypt()`

### DX / API Shape (P1) — all done ✅

- [x] D-3 `importJWKFromPEM` → `importFromPEM` + options object; `exportJWKToPEM` → `exportToPEM`
- [x] D-4 Remove deprecated `critical` from `JWTClaimValidationOptions`
- [x] D-5 Rename `requiredHeaders` → `recognizedHeaders`
- [x] D-6 Full ECDH-ES implementation in `wrapKey`/`unwrapKey`; `deriveSharedSecret` exported
- [x] D-7 `getJWKFromSet` auto-resolves single-key sets; clearer multi-key error message
- [x] D-8 Remove `returnAs` from `UnwrapKeyOptions`; replace with `format: "cryptokey" | "raw"` discriminant
- [x] D-9 `importKey` opt-in `{ asCryptoKey: true }` overload for `JWK_oct`
- [x] D-10 Remove `toJWK: object` from `GenerateKeyOptions` and `DeriveKeyOptions`; `generateJWK`/`deriveJWKFromPassword` refactored to post-merge pattern

### Types (P1/P2) — all done ✅

- [x] T-1 `JWEHeaderParameters.alg`/`enc` strengthened to `KeyManagementAlgorithm | (string & {})` / `ContentEncryptionAlgorithm | (string & {})`
- [x] T-2 `JWEProtectedHeader` added; `JWEDecryptResult.protectedHeader` uses it
- [x] T-3 `JWS_SIGN_EXTRA` removed; `JWSAlgorithm` uses `JWK_OKP_SIGN` directly
- [x] T-4 `JWK_Pair` / `GenerateJWKReturn` inference verified and correct
- [x] T-6 AES-CBC composite key TODO comment clarified
- [x] T-7 `"dir"` added to `KeyManagementAlgorithm`; fully wired in `encrypt()`/`decrypt()`
- [x] T-8 `JWKSet` added to `JWEKeyLookupFunction` return union (parity with JWS); runtime handling wired in `decrypt()`

### Code Cleanup (P2) — all done ✅

- [x] C-1 `validateKeyLength` (jws.ts) + `checkKeyLength` (\_sign-verify.ts) merged into `checkSigningKeyLength`; now throws `JWTError`
- [x] C-2 `_buildJWSHeader` / `_buildJWEHeader` private helpers extracted in jws.ts / jwe.ts
- [x] C-5 RSA-OAEP double-import in `wrapKey` fixed; uses `encryptRSAES` directly
- [x] C-6 `clearJWKCache()` exported

### JWK Cache (P1) — done ✅

- [x] `JWKCacheAdapter` interface, `WeakMapJWKCache` class, `configureJWKCache()`, `clearJWKCache()` all exported from `unjwt/jwk` and top-level `unjwt`

### Jose Fork (P2) — done ✅

- [x] J-1 `buffer_utils.ts` inlined (`uint32be` → `_ecdh.ts`, `uint64be` → `_aes.ts`)
- [x] J-2 `checkSigCryptoKey` / `checkEncCryptoKey` split per algorithm file; `checkSigningKeyLength` added to `_sign-verify.ts`

### Additional changes made beyond the original plan

- `enc?: ContentEncryptionAlgorithm` added to `JWKParameters` — non-standard field already read at runtime by the library; now properly typed
- `JWK_Symmetric` accepted as a valid key type in the `"dir"` encrypt overload (alongside `CryptoKey | Uint8Array`)
- `getJWKsFromSet(jwkSet, filter?)` exported from `unjwt/jwk` and top-level `unjwt`; `getJWKFromSet` deprecated
- `JWSKeyLookupFunction` / `JWEKeyLookupFunction` merged into `JWKLookupFunction` (+ `JWKLookupFunctionHeader`) in `types/jwk.ts`
- `validateJWT` renamed to `validateClaims` in `JWSVerifyOptions` and `JWEDecryptOptions`

---

## Tentative — deferred, not scheduled

### T-A — `sign()`/`encrypt()` overload reduction — done ✅

`JOSEPayload = string | Uint8Array | Record<string, unknown>` introduced in `types/jwt.ts`.
`sign` reduced 7 → 3, `encrypt` reduced 7 → 4 (dir overload kept — semantically distinct).
`JWSVerifyResult<T>` and `JWEDecryptResult<T>` bounds updated to `T extends JOSEPayload`.
`getPlaintextBytes` updated to `Record<string, unknown>`.

---

## Deferred to minor release

### J-3 — `getSignVerifyKey` Uint8Array path audit (P2) — done ✅

Audit confirmed: no external path bypasses `importKey`, but `importKey` for `JWK_oct`/`Uint8Array`/`string` returns raw bytes which still reached `getSignVerifyKey`'s on-the-fly import. Fixed by moving conversion + length validation into a private `_resolveSigningKey` helper in `jws.ts`. `_sign-verify.ts` `sign()`/`verify()` now accept `CryptoKey` only; `getSignVerifyKey` and `checkSigningKeyLength` removed.

---

## Downstream: H3 Adapter Impact

| Core commit                                                         | Required adapter change                                                                          |
| ------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------ |
| Commit 4: `critical` removed                                        | Replace `critical: [...]` with `recognizedHeaders: [...]` in all session config options          |
| Commit 4: `requiredHeaders` → `recognizedHeaders`                   | Same rename in all `JWTClaimValidationOptions` usages                                            |
| Commit 4: `JWEDecryptResult.protectedHeader` → `JWEProtectedHeader` | Hook callsites referencing `protectedHeader` gain stronger types (additive, no migration)        |
| Commit 5: `p2c` default change                                      | JWE sessions using password-based keys will see higher first-use CPU; document in adapter README |
| Commit 11: PEM rename                                               | Any adapter-level `importJWKFromPEM`/`exportJWKToPEM` usage → `importFromPEM`/`exportToPEM`      |

---

## Future Considerations (post-v0.6)

### JWE JSON Serialization (RFC 7516 §3.3)

The v0.6 primitives that enable multi-recipient JWE are all in place:

- `deriveSharedSecret` — ECDH derivation per recipient
- `wrapKey`/`unwrapKey` ECDH-ES — wraps/unwraps CEK per recipient
- `getAllJWKsFromSet` — locates recipient keys from a JWKS

A future `encryptMulti(payload, recipients[], options)` / `decryptMulti(jweJson, key)` API sits naturally above these without requiring further core changes.
