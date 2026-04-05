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
- `getAllJWKsFromSet(jwkSet, filter?)` exported from `unjwt/jwk` and top-level `unjwt`

---

## Tentative — deferred, not scheduled

### T-A — `sign()`/`encrypt()` overload reduction

Reduce the 7 sign / 5 encrypt overloads by removing the `JWTClaims`-specific variants.
Requires confirming IntelliSense does not degrade before committing.

### T-B — `ExpiresIn` unit case normalization

Normalize mixed-case short units (`"D"`, `"W"`, `"M"`, `"Y"`) to lowercase.
Requires deciding whether to keep uppercase as deprecated aliases or drop them entirely.

---

## Deferred to minor release

### D-11 — `validateJWT` → `validateClaims` rename (P2)

`validateJWT` is a confusing tri-state. Renaming and improving its JSDoc can be a non-breaking minor-release improvement (new name alongside old, old deprecated).

### J-3 — `getSignVerifyKey` Uint8Array path audit (P2)

Audit whether any external path still passes `Uint8Array` directly to `_sign-verify.ts`'s `sign()`/`verify()` bypassing `importKey`. If no path does, simplify `getSignVerifyKey` by removing the import-on-the-fly branch.

---

## Post-release: Documentation Session

Run a dedicated session once v0.6.0 is tagged:

- **`README.md`** — rewrite all API references to reflect the v0.6 surface. No migration notes — document the current API only. Key changes to cover: `recognizedHeaders`, `generateJWK` (no object `toJWK`), `deriveJWKFromPassword`, `configureJWKCache` / `clearJWKCache` / `WeakMapJWKCache`, `importFromPEM` / `exportToPEM`, `unwrapKey` format discriminant, `getAllJWKsFromSet`, `deriveSharedSecret`, `"dir"` alg, `importKey` `asCryptoKey` overload, `JWKParameters.enc`.
- **`skills/unjwt/`** — update all reference docs to match the new public signatures, types, and function names. Remove any mention of removed APIs.

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
