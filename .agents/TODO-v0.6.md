# v0.6.0 Breaking-Release — Implementation Plan

> **Scope:** `unjwt/jwk`, `unjwt/jws`, `unjwt/jwe` and their internal layers.
> H3 adapters are excluded but noted where they require downstream updates.
>
> **Approach:** proper full implementations, not quick fixes. Each commit is
> independently buildable, testable, and reviewable. Order is inner-most
> (no dependencies) → outer-most (public API surface).
>
> **Review protocol:** if anything looks wrong during development, raise a review
> session — treat the working branch as uncommitted until you are satisfied.

---

## Decisions Log

| #   | Topic                           | Decision                                                                            |
| --- | ------------------------------- | ----------------------------------------------------------------------------------- |
| Q1  | `jose/` fork restructuring      | Rename to `src/core/_crypto/`, merge small files into functional groups (C)         |
| Q2  | `sanitizeObject` copy semantics | Shallow copy at top level, deep recursive copy before traversing (A)                |
| Q3  | ECDH-ES implementation          | All four variants in `wrapKey`/`unwrapKey`; export `deriveSharedSecret` (A)         |
| Q4  | `unwrapKey` API                 | Single function, `format: "cryptokey" \| "raw"` discriminant (B)                    |
| Q5  | `dir` algorithm                 | Add to `KeyManagementAlgorithm`, fully wire `encrypt`/`decrypt` (A)                 |
| Q6  | `getJWKFromSet`                 | Single-key auto-resolve + throw on multi-key/no-kid + add `getAllJWKsFromSet` (A+C) |
| Q7  | `importKey` oct                 | Keep `Uint8Array` default, add `{ asCryptoKey: true }` overload (A)                 |
| Q8  | JWK cache                       | Module-level `configureJWKCache` + exported `WeakMapJWKCache` class (A)             |
| Q9  | `getAllJWKsFromSet` export      | Both `unjwt/jwk` and top-level barrel (B)                                           |
| Q10 | `_crypto/` tests                | Add `test/crypto.test.ts` for promoted primitives (B)                               |
| Q11 | `deriveSharedSecret` export     | Both `unjwt/jwk` and top-level barrel; name: `deriveSharedSecret` (B)               |

---

## Commit Sequence

---

### Commit 1 — Internal crypto reorganization

**Purpose:** Take full ownership of all cryptographic primitives. Pure internal restructure — zero public API change.

**`src/core/jose/` is removed. `src/core/_crypto/` is created with 8 focused modules.**

#### File mapping

| Removed (`jose/`)                             | Absorbed into (`_crypto/`) |
| --------------------------------------------- | -------------------------- |
| `sign-verify.ts`                              | `_sign-verify.ts`          |
| `crypto_key.ts` → `checkSigCryptoKey`         | `_sign-verify.ts`          |
| `crypto_key.ts` → `checkEncCryptoKey` (AES)   | `_aes.ts`                  |
| `crypto_key.ts` → `checkEncCryptoKey` (RSA)   | `_rsa.ts`                  |
| `crypto_key.ts` → `checkEncCryptoKey` (ECDH)  | `_ecdh.ts`                 |
| `crypto_key.ts` → `checkEncCryptoKey` (PBES2) | `_pbes2.ts`                |
| `encrypt-decrypt.ts`                          | `_aes.ts`                  |
| `cek-iv.ts`                                   | `_aes.ts`                  |
| `aesgcmkw.ts`                                 | `_aes.ts`                  |
| `buffer_utils.ts` → `uint64be`                | `_aes.ts` (CBC MAC path)   |
| `buffer_utils.ts` → `uint32be`                | `_ecdh.ts` (concat KDF)    |
| `rsaes.ts`                                    | `_rsa.ts`                  |
| `ecdhes.ts`                                   | `_ecdh.ts`                 |
| `pbes2kw.ts` → PBES2 derivation               | `_pbes2.ts`                |
| `pbes2kw.ts` → AES-KW wrap/unwrap helpers     | `_aes.ts`                  |
| `jwk_to_key.ts`                               | `_key-codec.ts`            |
| `key_to_jwk.ts`                               | `_key-codec.ts`            |
| `encrypt_key.ts`                              | `_key-encryption.ts`       |
| `asn1.ts`                                     | `_pem.ts`                  |

#### New structure

```
src/core/_crypto/
  index.ts            — re-exports everything consumed outside this directory
  _aes.ts             — AES-GCM enc/dec, AES-CBC enc/dec, AES-KW wrap/unwrap,
                        AES-GCMKW, CEK/IV generation, AES CryptoKey validation
  _rsa.ts             — RSA-OAEP enc/dec, RSA CryptoKey validation
  _ecdh.ts            — ECDH-ES key derivation, concat KDF (NIST SP 800-56A),
                        ECDH-allowed check, ECDH CryptoKey validation
  _pbes2.ts           — PBES2 PBKDF2 key derivation, PBES2 CryptoKey validation
  _sign-verify.ts     — HMAC/RSA/ECDSA/EdDSA sign + verify, subtle algorithm
                        mapping, signature CryptoKey validation
  _key-codec.ts       — JWK → CryptoKey (subtleMapping + importKey via subtle),
                        CryptoKey → JWK (exportKey via subtle)
  _key-encryption.ts  — JWE key management dispatcher (encryptKey, normalizeKey)
  _pem.ts             — SPKI/PKCS8/X.509 PEM import + export, ASN.1 parser
```

#### Also done in this commit

- **C-1:** Merge `checkKeyLength` (from old `sign-verify.ts`) with `validateKeyLength` (from `jws.ts`) into `_sign-verify.ts`. Remove the duplicate from `jws.ts`.
- **C-5:** Fix the RSA-OAEP path in `wrapKey`: remove the unnecessary intermediate `crypto.subtle.importKey` and call `encryptRSAES` from `_rsa.ts` directly with the raw CEK bytes.
- Strip all "fork of panva/jose" attribution headers; replace with a single top-of-file note in `_crypto/index.ts` acknowledging the original source and stating independent ownership.
- Update all imports across `jws.ts`, `jwe.ts`, `jwk.ts`, `utils/index.ts`.
- Update `build.config.ts` if `jose/index` was an explicit entry point (it is — replace with `_crypto/index`).

#### Tests added

**`test/crypto.test.ts`** — unit tests for all promoted primitives:

- `_aes`: AES-GCM enc/dec roundtrip, AES-CBC enc/dec roundtrip, AES-KW wrap/unwrap roundtrip, AES-GCMKW wrap/unwrap roundtrip, CEK/IV generation lengths
- `_rsa`: RSA-OAEP enc/dec roundtrip
- `_ecdh`: `deriveECDHESKey` roundtrip (P-256, P-384, X25519), `concatKdf` output length
- `_pbes2`: PBES2 derivation determinism (same salt+password+alg → same bytes)
- `_sign-verify`: sign/verify roundtrip for all supported algorithms
- `_key-codec`: JWK → CryptoKey → JWK roundtrip for RSA, EC, OKP, oct
- `_pem`: PEM import/export roundtrip for RSA, EC

#### Commit message

```
refactor: promote jose fork to internal _crypto/ implementation

Take full ownership of all cryptographic primitives originally forked
from panva/jose. The src/core/jose/ directory is replaced by
src/core/_crypto/ with a cleaner, functionally-grouped structure.

Files merged: 14 source files → 8 modules
  _aes.ts         — AES-GCM/CBC/KW/GCMKW + CEK/IV generation
  _rsa.ts         — RSA-OAEP encrypt/decrypt
  _ecdh.ts        — ECDH-ES key derivation + concat KDF
  _pbes2.ts       — PBES2/PBKDF2 key derivation
  _sign-verify.ts — HMAC/RSA/ECDSA/EdDSA sign + verify
  _key-codec.ts   — JWK ↔ CryptoKey conversion
  _key-encryption.ts — JWE key management dispatcher
  _pem.ts         — PEM/SPKI/PKCS8/X.509 + ASN.1

Also:
- Consolidate duplicate validateKeyLength/checkKeyLength → _sign-verify.ts (C-1)
- Fix RSA-OAEP double-import in wrapKey; use encryptRSAES directly (C-5)
- Add test/crypto.test.ts covering all promoted primitives

No public API changes. All imports updated. Build config updated.
```

---

### Commit 2 — `sanitizeObject`: non-mutating copy-based implementation

**Purpose:** Fix the silent mutation of user-supplied options objects. Security fix (S-3).

#### Implementation

The function must return a new object. The deep traversal copies each nested object before stripping dangerous keys, so no node in the input tree is ever modified:

```ts
export function sanitizeObject<T extends Record<string, unknown> | undefined>(obj: T): T {
  if (!obj || typeof obj !== "object") return obj;
  return _sanitizeCopy(obj as Record<string, unknown>, new WeakSet()) as T;
}

function _sanitizeCopy(
  current: Record<string, unknown>,
  seen: WeakSet<object>,
): Record<string, unknown> {
  seen.add(current);
  const result: Record<string, unknown> = Array.isArray(current) ? [] : {};
  for (const [key, value] of Object.entries(current)) {
    if (key === "__proto__" || key === "prototype" || key === "constructor") continue;
    if (value && typeof value === "object" && !seen.has(value as object)) {
      result[key] = _sanitizeCopy(value as Record<string, unknown>, seen);
    } else {
      result[key] = value;
    }
  }
  return result;
}
```

#### Also done in this commit

- **S-3 (JWE gap):** Add `sanitizeObject` call on the user-provided `additionalProtectedHeader` inside `jwe.ts`'s `encrypt()`. Currently it is spread directly with no sanitization.
- Review every `sanitizeObject` callsite and ensure no code still expects mutation-in-place semantics (all callers either JSON.parse fresh objects or user-provided options — both are now correctly handled by copy semantics).

#### Tests

- Add edge-case tests in `test/utils.test.ts`: verify that the input object is unchanged after `sanitizeObject`, and that `__proto__`/`prototype`/`constructor` keys are stripped at all nesting depths.

#### Commit message

```
fix(security): make sanitizeObject non-mutating

sanitizeObject previously modified its argument in-place and returned
the same reference. When called with a user-supplied protectedHeader
option, this silently mutated the caller's object.

- Rewrite to produce a deep structural copy; dangerous keys are stripped
  from the copy, never from the input
- Add sanitization of user-provided additionalProtectedHeader in
  jwe.ts encrypt() — this path was previously unsanitized entirely
- Callers passing freshly JSON.parse'd objects are unaffected in
  behaviour; callers passing reused option objects no longer have
  their objects modified

BREAKING: code that relied on the mutated reference being the same
object will now receive a new object. This was an undocumented
side-effect; the new behaviour is correct.
```

---

### Commit 3 — JWK import cache: configurable adapter

**Purpose:** Preserve the WeakMap performance win while giving developers full control over cache lifetime and strategy.

#### Implementation

```ts
// src/core/types/jwk.ts (or a new src/core/types/_cache.ts, re-exported)
export interface JWKCacheAdapter {
  get(jwk: JWK, alg: string): CryptoKey | undefined;
  set(jwk: JWK, alg: string, key: CryptoKey): void;
}

// src/core/jwk.ts
export class WeakMapJWKCache implements JWKCacheAdapter {
  private readonly _map = new WeakMap<object, Record<string, CryptoKey>>();
  get(jwk: JWK, alg: string): CryptoKey | undefined {
    return this._map.get(jwk)?.[alg];
  }
  set(jwk: JWK, alg: string, key: CryptoKey): void {
    let entry = this._map.get(jwk);
    if (!entry) {
      this._map.set(jwk, { [alg]: key });
    } else {
      entry[alg] = key;
    }
  }
}

let _activeCache: JWKCacheAdapter | false = new WeakMapJWKCache();

/** Replace or disable the JWK import cache. Pass `false` to disable. */
export function configureJWKCache(cache: JWKCacheAdapter | false): void {
  _activeCache = cache;
}

/** Reset the cache to a fresh WeakMapJWKCache (useful in tests). */
export function clearJWKCache(): void {
  _activeCache = new WeakMapJWKCache();
}
```

`importKey` is updated to use `_activeCache` via the adapter interface instead of directly accessing the WeakMap. Hot path overhead is unchanged (one property read on the module-level variable, one `.get()` call).

#### Why `jwk: JWK` in the adapter interface

The adapter receives the full JWK object, not a pre-computed string key, so each implementation can choose its own keying strategy:

- `WeakMapJWKCache` uses the object reference (GC-friendly, no string hashing needed)
- A `kid`-keyed cache extracts `jwk.kid` and uses it as a string key
- A content-hash cache computes a digest of `jwk.k` or `jwk.n`+`jwk.e`

If the library pre-computed a string key, it would impose a strategy that breaks `WeakMapJWKCache`'s garbage-collection semantics and would require a mandatory `kid` on all keys.

#### Why `WeakMapJWKCache` uses `Record<string, CryptoKey>` not `Map<string, CryptoKey>`

The inner value is a plain object, not a `Map`. This is intentional:

- The typical entry has 1–2 algorithm strings per JWK. For that cardinality V8 applies hidden
  class optimisation to plain objects with a stable, small key set. `Map` has higher constant
  overhead that only pays off at larger key counts.
- No alternative structure improves on `WeakMap<JWK, Record<string, CryptoKey>>`: a flat
  compound key is not possible in the language, and a nested `WeakMap` cannot use string alg
  identifiers as keys.

#### Cache hit semantics — document prominently in JSDoc

The `WeakMapJWKCache` (and the default module-level cache) uses **reference equality** for the
outer key. A cache hit only occurs when the exact same JWK object variable is passed to
`importKey` again. Reconstructing a structurally identical JWK object (e.g. `{ ...jwk }`) will
miss the cache. This is the expected and correct behaviour — document it explicitly so developers
who construct JWK objects dynamically understand why they get no cache benefit.

#### Exports

- `WeakMapJWKCache`, `JWKCacheAdapter`, `configureJWKCache`, `clearJWKCache` from `unjwt/jwk`
- `WeakMapJWKCache`, `JWKCacheAdapter`, `configureJWKCache`, `clearJWKCache` from top-level `unjwt`

#### Tests

Add cache-specific tests in `test/jwk.test.ts`:

- Default WeakMap cache: same JWK object → same CryptoKey reference
- `clearJWKCache()`: same object after clear → new CryptoKey reference
- Custom adapter: verify `get`/`set` are called with correct args
- `configureJWKCache(false)`: no cache — verify no stale returns

#### Commit message

```
feat(jwk): configurable JWK import cache via JWKCacheAdapter

Replace the private module-level WeakMap with a public adapter
interface, enabling developers to supply their own cache implementation
(LRU, Redis-backed wrapper, test spy, etc.) while preserving the
default WeakMap behaviour and its GC-friendly semantics.

- Add JWKCacheAdapter interface { get(jwk, alg), set(jwk, alg, key) }
- Add WeakMapJWKCache as the default exported implementation
- Add configureJWKCache(cache | false) to swap or disable the cache
- Add clearJWKCache() for test environments
- Export all four from unjwt/jwk and top-level unjwt

Default behaviour is unchanged. No migration required for code that
does not need custom cache control.
```

---

### Commit 4 — Type system overhaul

**Purpose:** All breaking type changes in one commit so downstream consumers have a single migration point for type-level breaks.

**This commit is pure type changes. No runtime behaviour changes.**

#### Changes in `src/core/types/jwk.ts`

1. **Remove `"none"` from `JWKAlgorithm`.** No handler exists; its presence only allows user code to pass it without a compile error.
2. **Add `"dir"` to `KeyManagementAlgorithm`** (was `// TODO: | "dir"`). The crypto layer already handles it.
3. **Remove `returnAs` from `UnwrapKeyOptions`.** Replaced by `format` in Commit 6.
4. **Remove `toJWK: object` variant from `GenerateKeyOptions`.** The `object` path in `toJWK` had confusing semantics. `generateJWK(alg, jwkParams)` is the clean alternative. Keep `toJWK?: boolean` for raw boolean control; remove the object variant. Update `GenerateKeyReturn` conditional types accordingly.
5. **Fix `GenerateKeyReturnJWK` AES-CBC TODO comment.** The single `JWK_oct` return is correct — the composite key material is stored as one `JWK_oct` and split internally during enc/dec. Replace the TODO with a clarifying note.
6. **Verify `JWK_Pair` inference precision.** Check that `GenerateJWKReturn<"ES256">` resolves to exactly `{ publicKey: JWK_EC_Public; privateKey: JWK_EC_Private }` without widening. Fix any conditional type gaps.

#### Changes in `src/core/types/jwe.ts`

7. **Strengthen `JWEHeaderParameters.alg/enc`:**
   ```ts
   alg?: KeyManagementAlgorithm | (string & {});
   enc?: ContentEncryptionAlgorithm | (string & {});
   ```
   The `(string & {})` escape hatch preserves assignability from external/unknown token headers without narrowing to `string`.
8. **Add `JWEProtectedHeader`** — post-decrypt result header type with required, strongly typed `alg` and `enc`:
   ```ts
   export interface JWEProtectedHeader extends JWEHeaderParameters {
     alg: KeyManagementAlgorithm;
     enc: ContentEncryptionAlgorithm;
   }
   ```
9. **Add `JWKSet` to `JWEKeyLookupFunction` return union** (parity with `JWSKeyLookupFunction`).
10. **Update `JWEDecryptResult.protectedHeader`** to use `JWEProtectedHeader`.

#### Changes in `src/core/types/jws.ts`

11. **Replace `JWS_SIGN_EXTRA`** (private alias duplicating `JWK_OKP_SIGN`) with direct use of `JWK_OKP_SIGN`:
    ```ts
    export type JWSAlgorithm = JWK_HMAC | JWK_RSA_SIGN | JWK_RSA_PSS | JWK_ECDSA | JWK_OKP_SIGN;
    ```

#### Changes in `src/core/types/jwt.ts`

12. **Remove deprecated `critical` from `JWTClaimValidationOptions`.** Already deprecated; v0.6 drops it.
13. **Rename `requiredHeaders` → `recognizedHeaders`** across the type definition and all option interfaces that extend `JWTClaimValidationOptions` (`JWSVerifyOptions`, `JWEDecryptOptions`).

#### Callsite updates (runtime files — same commit)

All references to `critical`, `requiredHeaders`, `returnAs`, and `toJWK: { ... }` in `jws.ts`, `jwe.ts`, `jwk.ts`, and `utils/jwt.ts` are updated to match the new names and shapes. The `validateCriticalHeadersJWS` and `validateCriticalHeadersJWE` function signatures are updated to use `recognizedHeaders`.

#### Commit message

```
feat!: type system overhaul

Consolidated breaking type changes. Runtime behaviour is unchanged
in this commit; all changes are type-level only.

Types/jwk.ts:
  - Remove "none" from JWKAlgorithm (algorithm confusion attack vector)
  - Add "dir" to KeyManagementAlgorithm (crypto already supported it)
  - Remove returnAs from UnwrapKeyOptions (replaced by format: discriminant)
  - Remove toJWK: object from GenerateKeyOptions (use generateJWK() instead)
  - Fix misleading AES-CBC composite key TODO comment
  - Verify JWK_Pair / GenerateJWKReturn inference precision

Types/jwe.ts:
  - Strengthen JWEHeaderParameters.alg/enc with union + (string & {}) escape
  - Add JWEProtectedHeader (alg/enc required, strongly typed) for decrypt results
  - Use JWEProtectedHeader in JWEDecryptResult.protectedHeader
  - Add JWKSet to JWEKeyLookupFunction return union (parity with JWS)

Types/jws.ts:
  - Replace private JWS_SIGN_EXTRA alias with JWK_OKP_SIGN

Types/jwt.ts:
  - Remove deprecated critical from JWTClaimValidationOptions
  - Rename requiredHeaders → recognizedHeaders (semantic: "understood", not "must-be-present")

Migration:
  critical → recognizedHeaders
  requiredHeaders → recognizedHeaders
  unwrapKey(…, { returnAs: false }) → unwrapKey(…, { format: "raw" })    [Commit 6]
  generateKey(alg, { toJWK: { kid } }) → generateJWK(alg, { kid })
```

---

### Commit 5 — Security hardening

**Purpose:** S-1 (PBES2 default), S-2 (alg:none runtime guard), S-4 (kid precedence).

#### Changes

**S-1 — Raise PBES2 `p2c` default to `600_000`**

In `jwe.ts` `encrypt()`:

```ts
// before
else if (alg?.startsWith("PBES2")) jweKeyManagementParams.p2c = 2048;
// after
else if (alg?.startsWith("PBES2")) jweKeyManagementParams.p2c = 600_000;
```

Same default in `jwk.ts`'s `wrapKey` PBES2 path. Document in JSDoc that lowering this value is an interoperability option, not a recommended optimization.

**S-2 — `alg: "none"` runtime guard in `sign()`**

Even though `"none"` is removed from the type, a caller could use `as any` or receive an alg from an external source. Belt-and-suspenders guard at the top of `sign()`:

```ts
if (alg === "none") {
  throw new JWTError('"none" is not a valid signing algorithm', "ERR_JWS_ALG_NOT_ALLOWED");
}
```

**S-4 — Correct `kid` precedence in `sign()` and `encrypt()`**

User-set `protectedHeader.kid` wins; JWK's `kid` is used only as a fallback:

```ts
// before (JWK kid overwrites user kid)
const protectedHeader = {
  ...safeAdditionalHeader,
  ...(isJWK(key) && key.kid ? { kid: key.kid } : {}),
  alg,
};

// after (user kid preserved if set)
const protectedHeader = {
  ...(isJWK(key) && key.kid ? { kid: key.kid } : {}),
  ...safeAdditionalHeader,
  alg,
};
```

Apply the same inversion in `jwe.ts`'s `encrypt()`.

#### Commit message

```
fix!(security): PBES2 iterations default, alg:none guard, kid precedence

S-1 — Raise PBES2 p2c default: 2_048 → 600_000
  OWASP 2024 recommends 600,000 iterations for PBKDF2-SHA256. The
  previous default was ~300× below this threshold. Tokens issued with
  the new default require ~300× more CPU to brute-force per unique
  password. Explicitly passing a lower p2c still works (interop).

S-2 — Runtime guard for alg: "none" in sign()
  Belt-and-suspenders guard alongside the type-level removal in
  Commit 4. Any code bypassing the type system with `as any` or
  receiving alg from an external source will get a clear JWTError.

S-4 — Correct kid precedence in sign() and encrypt()
  Previously the JWK's kid was spread after the user-provided
  protectedHeader, silently overwriting any user-set kid. The
  correct precedence is: user-set kid > JWK kid fallback.

BREAKING (S-4): code that relied on JWK.kid overriding a user-set
protectedHeader.kid must now leave protectedHeader.kid unset.
BREAKING (S-1): new default p2c is 600_000. Tokens with a custom
lower p2c continue to work normally; only newly issued tokens change.
```

---

### Commit 6 — `unwrapKey`: `format` discriminant replaces `returnAs`

**Purpose:** Remove the `returnAs: boolean` implementation leak. Provide proper TypeScript narrowing on the return type. D-8.

#### Implementation

```ts
export async function unwrapKey(
  alg: KeyManagementAlgorithm,
  wrappedKey: Uint8Array,
  unwrappingKey: CryptoKey | JWK | string | Uint8Array,
  options: UnwrapKeyOptions & { format: "raw" },
): Promise<Uint8Array>;
export async function unwrapKey(
  alg: KeyManagementAlgorithm,
  wrappedKey: Uint8Array,
  unwrappingKey: CryptoKey | JWK | string | Uint8Array,
  options?: UnwrapKeyOptions & { format?: "cryptokey" },
): Promise<CryptoKey>;
```

Both overloads share a single implementation body. The `format` field in `UnwrapKeyOptions` replaces the removed `returnAs` field (done in Commit 4's type work).

#### Commit message

```
feat!(jwk): unwrapKey — format discriminant replaces returnAs boolean

returnAs: boolean was an implementation detail leaking into the public
API with non-obvious semantics (true = CryptoKey, false = Uint8Array).

Replace with a typed format discriminant that gives TypeScript full
return-type narrowing:

  // before
  const raw = await unwrapKey(alg, wrapped, key, { returnAs: false });
  // TS inferred: CryptoKey (wrong — was typed poorly)

  // after
  const raw = await unwrapKey(alg, wrapped, key, { format: "raw" });
  // TS infers: Promise<Uint8Array>  ✓

  const cryptoKey = await unwrapKey(alg, wrapped, key);
  // default: format: "cryptokey" → Promise<CryptoKey>  ✓

BREAKING: replace returnAs: false with format: "raw",
          returnAs: true (or omitted) with format: "cryptokey" (or omit).
```

---

### Commit 7 — Full ECDH-ES implementation + `deriveSharedSecret` export

**Purpose:** Complete ECDH-ES support in all public key management functions; expose the low-level derivation primitive for advanced use cases. D-6.

#### Background (for implementation reference)

ECDH-ES key agreement always involves two parties at the cryptographic level:

- **Sender:** generates (or receives) an ephemeral key pair
- **Recipient:** holds a long-term static key pair
- ECDH(ephemeral_private, recipient_public) → raw shared secret → concat KDF → derived key material

For multi-recipient scenarios (N servers sharing one encrypted payload), the pattern is:

1. Generate one random CEK
2. For each recipient: run ECDH-ES+A\*KW once with their public key → wrap the same CEK
3. Package all wrapped keys + one ciphertext as JWE JSON Serialization (`recipients[]`)

`deriveSharedSecret` is the building block for step 2. Full JWE JSON Serialization is tracked for a future release (see Future Considerations).

#### `deriveSharedSecret` signature

```ts
export async function deriveSharedSecret(
  /** The recipient's static public key (or sender's ephemeral public key on decrypt). */
  publicKey: CryptoKey | JWK_EC_Public,
  /** The sender's ephemeral private key (or recipient's static private key on decrypt). */
  privateKey: CryptoKey | JWK_EC_Private,
  /** The algorithm identifier used in the concat KDF info structure. */
  alg: JWK_ECDH_ES | ContentEncryptionAlgorithm,
  options?: {
    /** Key length in bits. Derived from alg when omitted. */
    keyLength?: number;
    /** Agreement PartyUInfo (apu) — identifies the producer. */
    partyUInfo?: Uint8Array;
    /** Agreement PartyVInfo (apv) — identifies the consumer. */
    partyVInfo?: Uint8Array;
  },
): Promise<Uint8Array>;
```

#### `WrapKeyOptions` additions

```ts
export interface WrapKeyOptions {
  // existing fields ...
  ecdh?: {
    ephemeralKey?:
      | CryptoKey // private CryptoKey
      | JWK_EC_Private
      | CryptoKeyPair
      | { publicKey: CryptoKey | JWK_EC_Public; privateKey: CryptoKey | JWK_EC_Private };
    partyUInfo?: Uint8Array;
    partyVInfo?: Uint8Array;
  };
}
```

#### `WrapKeyResult` additions (already typed, now implemented)

```ts
export interface WrapKeyResult {
  encryptedKey: Uint8Array; // empty Uint8Array for bare ECDH-ES
  epk?: JWK_EC_Public;
  apu?: string; // base64url
  apv?: string; // base64url
  // existing iv/tag/p2s/p2c remain
}
```

#### `wrapKey` ECDH-ES behaviour

- **`ECDH-ES` (direct):** `encryptKey` in `_key-encryption.ts` is reused. Returns `{ encryptedKey: new Uint8Array(0), epk, apu?, apv? }` per RFC 7516 §4.6. The `keyToWrap` argument is ignored (direct agreement: the derived material IS the CEK, not something wrapping it). This is spec-compliant; the function semantically "wraps nothing" and returns the derivation parameters.
- **`ECDH-ES+A128KW`, `+A192KW`, `+A256KW`:** Full implementation. ECDH derives a KEK; AES-KW wraps the caller-supplied `keyToWrap`. Returns `{ encryptedKey, epk, apu?, apv? }`.

#### `unwrapKey` ECDH-ES behaviour

Matches existing internal `jwk.ts` implementation but now properly wired through the `format` discriminant from Commit 6.

#### Exports

- `deriveSharedSecret` from `unjwt/jwk`
- `deriveSharedSecret` from top-level `unjwt` barrel

#### Tests

- `test/jwk.test.ts`: wrapKey/unwrapKey roundtrip for all four ECDH-ES variants (P-256, X25519)
- `test/crypto.test.ts`: `deriveSharedSecret` roundtrip — derive on both sides, assert equal output

#### Commit message

```
feat(jwk): full ECDH-ES implementation + deriveSharedSecret public export

- Implement all four ECDH-ES variants in wrapKey and unwrapKey:
    ECDH-ES (direct): returns { encryptedKey: Uint8Array(0), epk, ... }
      per RFC 7516 §4.6 — no encrypted key in direct key agreement
    ECDH-ES+A128KW/A192KW/A256KW: ECDH derives KEK → AES-KW wraps caller's key
- Add WrapKeyOptions.ecdh for ephemeral key material + apu/apv
- Export deriveSharedSecret(publicKey, privateKey, alg, options?)
    Low-level ECDH-ES key derivation primitive for advanced use cases:
    multi-recipient JWE, custom hybrid protocols, future JWE JSON
    Serialization support
- Export from unjwt/jwk and top-level unjwt barrel

Note: multi-recipient JWE (N servers sharing one ciphertext) can be
constructed today using deriveSharedSecret + wrapKey once per recipient.
Full JWE JSON Serialization (RFC 7516 §3.3) is tracked separately.
```

---

### Commit 8 — `dir` algorithm: full wiring in `encrypt`/`decrypt`

**Purpose:** The `"dir"` algorithm was supported in the internal key management layer but never reachable via the public API. T-7 / was tagged `// TODO: | "dir"`.

#### `encrypt()` changes

When `alg === "dir"`:

- The provided `key` IS the CEK — no wrapping step
- `enc` must be provided explicitly (no default inference; there is no key structure to infer from)
- `encryptedKey` field in the JWE output is the empty string (spec-compliant)
- The key type must be `CryptoKey | Uint8Array` for `"dir"` (not a password string, not a JWK with private material)
- Overload added to enforce this at the type level

```ts
// dir-specific overload
encrypt(
  payload,
  key: CryptoKey | Uint8Array,
  options: JWEEncryptOptions & { alg: "dir"; enc: ContentEncryptionAlgorithm },
): Promise<string>
```

#### `decrypt()` changes

When `alg === "dir"` from the protected header:

- The provided key is used directly as the CEK
- Skip the `unwrapKey` step entirely
- Pass the key directly to the content decryption function

#### `wrapKey`/`unwrapKey` changes

`"dir"` added to both switch statements as a no-op / identity case with a clear comment. `wrapKey("dir", cek, key)` returns the key material unchanged (semantically: "the key IS the CEK"). `unwrapKey("dir", …, key)` similarly returns the key directly.

#### Tests

- `test/jwe.test.ts`: `dir` round-trip with AES-GCM enc variants and AES-CBC-HS enc variants

#### Commit message

```
feat(jwe): wire dir (direct key agreement) algorithm

"dir" was handled by the internal key management layer (encryptKey)
but was never reachable via the public encrypt/decrypt API. The type
was also commented out in KeyManagementAlgorithm (fixed in Commit 4).

- encrypt(): when alg is "dir", the provided key is the CEK directly;
  encryptedKey field is empty; enc must be provided explicitly
- decrypt(): when alg is "dir", skip key unwrapping; use provided key
  as CEK directly for content decryption
- wrapKey/unwrapKey: "dir" is a no-op (identity); key IS the CEK
- New overload enforces key type CryptoKey | Uint8Array for "dir"
  (strings and JWKs are not valid direct-encryption CEKs)
- Add round-trip tests for dir + A128GCM, A256GCM, A128CBC-HS256
```

---

### Commit 9 — `importKey`: opt-in `CryptoKey` output for `oct` JWKs

**Purpose:** Allow callers who need a non-extractable CryptoKey from an `oct` JWK without calling `crypto.subtle` directly. D-9.

#### New overload

```ts
export async function importKey(
  key: JWK_oct,
  options: { asCryptoKey: true; algorithm: string | Algorithm; usage: KeyUsage[] },
): Promise<CryptoKey>;
```

Default behaviour (`importKey(jwk: JWK_oct)` → `Uint8Array`) is unchanged.

#### Commit message

```
feat(jwk): importKey — opt-in CryptoKey output for oct JWKs

importKey(jwk: JWK_oct) returns Uint8Array by default (no change).
A new overload accepts { asCryptoKey: true, algorithm, usage } to
return a non-extractable CryptoKey instead, for use cases where raw
key bytes must not be accessible (e.g. HSM-backed SubtleCrypto).

  const key = await importKey(jwk, { asCryptoKey: true, algorithm: "AES-GCM", usage: ["encrypt"] });
  // → CryptoKey (non-extractable by default)
```

---

### Commit 10 — `getJWKFromSet` + `getAllJWKsFromSet`

**Purpose:** Fix the overly strict `kid` requirement for single-key sets; add `getAllJWKsFromSet` for multi-key use cases. D-7, Q6.

#### `getJWKFromSet` changes

- **Single-key JWKSet, no `kid` in header:** return the only key directly. No error.
- **Multi-key JWKSet, no `kid` in header:** throw `JWTError("ERR_JWK_KEY_NOT_FOUND")` with a message that explicitly names the fix: add `kid` to the token's protected header and to the matching JWK.

#### New: `getAllJWKsFromSet`

```ts
export function getAllJWKsFromSet(
  jwkSet: JWKSet,
  filter?: {
    /** Filter by key ID. */
    kid?: string;
    /** Filter by algorithm. */
    alg?: string;
    /** Filter by key type. */
    kty?: string;
  },
): JWK[];
```

Returns all JWKs from the set that match the optional filter. An empty filter returns all keys. Useful for:

- Multi-key verification retry (try each key until one verifies)
- Building multi-recipient JWE JSON structures
- Key rotation tooling

#### Exports

- `getAllJWKsFromSet` from `unjwt/jwk`
- `getAllJWKsFromSet` from top-level `unjwt` barrel

#### Commit message

```
feat(jwk): getJWKFromSet single-key auto-resolve + getAllJWKsFromSet

getJWKFromSet changes:
- Single-key JWKSets: return the only key when the header has no kid
  (removes the unnecessary strict requirement for this common case)
- Multi-key JWKSets with no kid: throw JWTError(ERR_JWK_KEY_NOT_FOUND)
  with a message that names the fix (add kid to token + matching JWK)

New getAllJWKsFromSet(jwkSet, filter?):
- Returns all JWKs matching an optional { kid?, alg?, kty? } filter
- No filter → returns all keys in the set
- Use cases: multi-key verification retry, key rotation tooling,
  constructing multi-recipient JWE JSON Serialization structures
- Exported from unjwt/jwk and top-level unjwt
```

---

### Commit 11 — PEM function rename + options object API

**Purpose:** Shorter, clearer names; remove the awkward positional parameter chain. D-3.

#### Renames

| Before             | After           |
| ------------------ | --------------- |
| `importJWKFromPEM` | `importFromPEM` |
| `exportJWKToPEM`   | `exportToPEM`   |

#### `importFromPEM` signature change

Before:

```ts
importJWKFromPEM(pem, pemType, alg, importOptions?, jwkExtras?)
```

After:

```ts
importFromPEM(
  pem: string,
  pemType: "pkcs8" | "spki" | "x509",
  alg: JWKPEMAlgorithm,
  options?: {
    /** Passed to crypto.subtle.importKey. Default: false for private, true for public. */
    extractable?: boolean;
    /** Additional JWK properties merged into the exported key. */
    jwkParams?: Omit<JWKParameters, "alg" | "kty" | "key_ops" | "ext">;
  },
): Promise<T extends JWK>
```

`exportToPEM` keeps its current positional shape (the optional `alg` parameter sits naturally at the end).

#### Commit message

```
feat!(jwk): rename PEM functions + collapse positional params to options object

importJWKFromPEM → importFromPEM
exportJWKToPEM   → exportToPEM

importFromPEM collapses the two trailing positional parameters
(importOptions, jwkExtras) into a single options object:

  // before
  await importJWKFromPEM(pem, "pkcs8", "RS256", { extractable: false }, { kid: "k1" })

  // after
  await importFromPEM(pem, "pkcs8", "RS256", { extractable: false, jwkParams: { kid: "k1" } })

exportToPEM is unchanged except for the name.

BREAKING: rename all call sites. If only importOptions was used (no
jwkExtras), the migration is: third argument becomes options.extractable.
```

---

### Commit 12 — Extract `_buildJWSHeader`/`_buildJWEHeader` + consolidate header logic

**Purpose:** Single source of truth for protected header construction across `jws.ts` and `jwe.ts`. C-2. Resolves the remaining callsite inconsistencies from Commits 2 and 5.

#### New file: `src/core/utils/_header.ts`

```ts
// Internal utility — not exported from any public path
// _ prefix per project convention

export function buildJWSHeader(
  alg: JWSAlgorithm,
  key: CryptoKey | JWK_Symmetric | JWK_Private | Uint8Array,
  userHeader: JWSHeaderParameters | undefined,
  payload: unknown,
): JWSProtectedHeader

export function buildJWEHeader(
  alg: KeyManagementAlgorithm,
  enc: ContentEncryptionAlgorithm,
  key: CryptoKey | JWK | string | Uint8Array,
  userHeader: Omit<JWEHeaderParameters, "alg" | "enc" | ...> | undefined,
  payload: unknown,
  keyManagementParams: JWEKeyManagementHeaderParameters,
): JWEProtectedHeader
```

Each function:

1. Calls `sanitizeObject(userHeader)` (non-mutating copy from Commit 2)
2. Applies `kid` with correct precedence (Commit 5): JWK kid as default, user-set kid wins
3. Sets required `alg`/`enc`
4. Calls `applyTypCtyDefaults` on the final object

`applyTypCtyDefaults` remains a mutation-based helper but only receives freshly-constructed objects from within `_header.ts`, never user input — document this contract explicitly.

#### Commit message

```
refactor: extract _buildJWSHeader/_buildJWEHeader internal utilities

Consolidate the repeated protected-header construction logic from
jws.ts and jwe.ts into src/core/utils/_header.ts.

This is the single location where all header assembly invariants
are enforced:
  - sanitizeObject on user-provided additionalProtectedHeader
    (non-mutating, from Commit 2)
  - kid precedence: user-set > JWK fallback (from Commit 5)
  - alg/enc/typ/cty defaults

No behaviour change. All existing tests pass.
```

---

## Post-release: Documentation Session

Once all commits are done and v0.6.0 is tagged, run a dedicated session to:

- **`README.md`** — rewrite all API references to reflect the v0.6 surface:
  `recognizedHeaders`, `generateJWK` (no object `toJWK`), `deriveJWKFromPassword`,
  `configureJWKCache`/`clearJWKCache`/`WeakMapJWKCache`, `importFromPEM`/`exportToPEM`,
  `unwrapKey` format discriminant, `getAllJWKsFromSet`, `deriveSharedSecret`, `"dir"` alg.
  No migration notes — document the current API only.

- **`skills/unjwt/`** — update all reference docs to match the new public signatures,
  types, and function names. Remove any mention of removed APIs (`critical`,
  `requiredHeaders`, `returnAs`, `toJWK: object`, etc.).

---

## Tentative Items (tracked, not scheduled)

These two changes require a dedicated decision session before implementation. They are not part of the v0.6 commit sequence until confirmed.

### T-A — `sign()`/`encrypt()` overload reduction

**Current concern:** The seven overloads in `sign()` and five in `encrypt()` include `JWTClaims`-specific variants that produce no additional type safety (since `JWTClaims extends Record<string, unknown>`). The real dimension is `alg`-required vs `alg`-inferred.

**Proposed reduction (2 overloads each):**

- JWK key → `alg?` (inferred from JWK)
- CryptoKey | Uint8Array → `alg` required

**Concern to resolve before committing:** Verify that removing the `JWTClaims`-specific overloads does not degrade IntelliSense in common JWT usage (VSCode autocomplete on `payload.exp` etc.). May require a `JWTClaims | string | Uint8Array | Record<string, any>` union instead of separate overloads.

### T-B — `ExpiresIn` unit case normalization

**Current concern:** Mixed case sensitivity (`"D"` for day, `"s"` for second, `"m"` for minute, etc.) is a footgun.

**Proposed:** Normalize all short forms to lowercase in the type union; keep the regex case-insensitive for runtime tolerance. May want to keep uppercase aliases for a deprecation cycle.

**Concern to resolve:** Whether to keep the uppercase forms as non-recommended aliases (additive, not breaking) or drop them entirely (breaking, simpler type).

---

## Downstream: H3 Adapter Impact

Once the core commits above land, the following adapter updates are required (tracked in `.agents/vision/adapters-hooks.md`):

| Core commit                                                         | Required adapter change                                                                          |
| ------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------ |
| Commit 4: `critical` removed                                        | Replace `critical: [...]` with `recognizedHeaders: [...]` in all session config options          |
| Commit 4: `requiredHeaders` → `recognizedHeaders`                   | Same rename in all `JWTClaimValidationOptions` usages                                            |
| Commit 4: `JWEDecryptResult.protectedHeader` → `JWEProtectedHeader` | Hook callsites referencing `protectedHeader` gain stronger types (additive)                      |
| Commit 5: `p2c` default change                                      | JWE sessions using password-based keys will see higher first-use CPU; document in adapter README |
| Commit 11: PEM rename                                               | Any adapter-level PEM usage (unlikely but check)                                                 |

---

## Future Considerations (post-v0.6)

### JWE JSON Serialization (RFC 7516 §3.3)

Multi-recipient encryption — where one ciphertext is decryptable by N parties each with their own wrapped key — requires the JWE JSON Serialization format. The `recipients: [{ header, encrypted_key }]` structure is not supported in Compact Serialization.

The v0.6 changes lay the complete foundation:

- `deriveSharedSecret` (Commit 7) — the ECDH derivation primitive per recipient
- `wrapKey`/`unwrapKey` ECDH-ES (Commit 7) — wraps/unwraps CEK per recipient
- `getAllJWKsFromSet` (Commit 10) — locates recipient keys from a JWKS

A future `encryptMulti(payload, recipients[], options)` / `decryptMulti(jweJson, key)` API would sit above these primitives without requiring changes to the core crypto layer.

### `validateClaims` rename (tracked as D-11, P2)

`validateJWT` is a tri-state (`true` | `false` | `undefined`-with-typ-heuristic) that confuses callers. Renaming to `validateClaims` and improving its JSDoc is a low-priority DX improvement that can be slipped into a minor release.
