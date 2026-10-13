# JWE Reference (unjwt/jwe)

JSON Web Encryption ([RFC 7516](https://www.rfc-editor.org/rfc/rfc7516.txt)) — encrypt and decrypt data.

Import: `import { encrypt, decrypt } from "unjwt/jwe"` — or `from "unjwt"`

## Algorithms

### Key Management (`alg`)

| Family           | Identifiers                                                             |
| ---------------- | ----------------------------------------------------------------------- |
| Direct           | `dir`                                                                   |
| RSA-OAEP         | `RSA-OAEP` (SHA-1 OAEP), `RSA-OAEP-256`, `RSA-OAEP-384`, `RSA-OAEP-512` |
| AES Key Wrap     | `A128KW`, `A192KW`, `A256KW`                                            |
| AES-GCM Key Wrap | `A128GCMKW`, `A192GCMKW`, `A256GCMKW`                                   |
| PBES2            | `PBES2-HS256+A128KW`, `PBES2-HS384+A192KW`, `PBES2-HS512+A256KW`        |
| ECDH-ES          | `ECDH-ES`, `ECDH-ES+A128KW`, `ECDH-ES+A192KW`, `ECDH-ES+A256KW`         |

Type: `KeyManagementAlgorithm`

`RSA-OAEP` is SHA-1 OAEP (RFC 7518 §4.3): supported, and inferred from a key that declares it, so tokens from systems that only speak `RSA-OAEP` interoperate. `RSA-OAEP-256` is the choice for new deployments.

### Content Encryption (`enc`)

| Family              | Identifiers                                       |
| ------------------- | ------------------------------------------------- |
| AES-GCM             | `A128GCM`, `A192GCM`, `A256GCM`                   |
| AES-CBC + HMAC-SHA2 | `A128CBC-HS256`, `A192CBC-HS384`, `A256CBC-HS512` |

Type: `ContentEncryptionAlgorithm`

## `encrypt(payload, key, options?)`

Produces a JWE Compact Serialization token.

**Parameters:**

- `payload` — `string | Uint8Array | Record<string, any>`
- `key`
  - `string` → PBES2 password, and nothing else (infers `alg = "PBES2-HS256+A128KW"`). A string under any
    other `alg` — `"dir"`, `"A256KW"`, … — throws `ERR_JWK_INVALID` (`"String keys are not accepted: …"`)
    rather than being used as raw key bytes. JWE is the only family that takes a string at all, and PBKDF2
    is the only thing it does with one
  - `JWEEncryptJWK` → infers `alg`/`enc` from key properties. Narrows by family: `JWK_oct` with a JWE symmetric `alg` (AES-KW, AES-GCM, AES-GCM-KW, AES-CBC-HMAC, PBES2, `"dir"`) or an asymmetric _public_ JWK whose `alg` is RSA-OAEP or ECDH-ES. HMAC / signing-family JWKs are rejected at the type level.
  - `CryptoKey | Extract<JWEEncryptJWK, { kty: "oct" }> | Uint8Array` with `alg: "dir"` → used directly as the CEK. An `oct` JWK whose `alg` is a content encryption algorithm (`A*GCM`, `A*CBC-HS*`) _is_ a CEK: it infers `alg: "dir"` with that same algorithm as `enc`, and serves no other `enc`. One declaring a key wrapping `alg` is refused
  - `Uint8Array` → infers nothing; bytes carry no role, so `alg` is required and `encrypt` throws `ERR_JWE_ALG_MISSING` without one. The matching `decrypt` must then be given the same `algorithms: [alg]`
  - `CryptoKey` with other algorithms → requires explicit `alg` and `enc`
- `options?: JWEEncryptOptions`
  - `alg?: KeyManagementAlgorithm`
  - `enc?: ContentEncryptionAlgorithm` — defaults to `A256GCM`; under `alg: "dir"` it comes from the CEK's own `alg` (or its `enc` hint) and is required when the key carries neither
  - `protectedHeader?` — additional header params (excludes `alg`/`enc`/`iv`/`tag`/`p2s`/`p2c`/`epk`/`apu`/`apv`; `zip` is typed `never` and rejected at runtime with `ERR_INVALID_OPTION`). A `crit` is held to the rules `decrypt` applies, as `ERR_INVALID_OPTION`: a non-empty array of strings, no registered parameter, and every entry present in the header being built. A header that is not an object (a string, an array, `null`) or that `JSON.stringify` refuses (a `BigInt`, a circular reference) is `ERR_INVALID_OPTION` too. An object payload without `typ` gets `typ: "JWT"`; no `cty` is added (RFC 7519 §5.2 keeps it for nested JWTs, as `"JWT"`), and one set here is kept as given
  - `expiresIn?: ExpiresIn` — sets `exp` claim
  - `currentDate?: Date`
  - `cek?: Uint8Array` — custom Content Encryption Key; must be exactly the size `enc` names, or `ERR_INVALID_OPTION`
  - `contentEncryptionIV?: Uint8Array` — custom IV; must be exactly the length `enc` names, or `ERR_INVALID_OPTION`
  - `p2s?: Uint8Array`, `p2c?: number` — PBES2 salt and iteration count (default `p2c` is `600_000`). `p2s` must be 8 or more octets and `p2c` a positive integer between `1000` and `600_000` — the bounds `decrypt` enforces by default — or the call throws `ERR_INVALID_OPTION`. `p2c: 0` is rejected, never replaced by the default
  - `keyManagementIV?: Uint8Array` — IV for AES-GCM key wrapping
  - `ecdh?` — `{ ephemeralKey?, partyUInfo?, partyVInfo? }` for ECDH-ES. The content encryption algorithm is the top-level `enc`; `wrapKey` is the one that takes `ecdh.enc`. `partyUInfo` / `partyVInfo` must be `Uint8Array`s of at most `1024` bytes — the bound `decrypt` applies to the `apu` / `apv` it reads — else `ERR_INVALID_OPTION`.

An unsupported or misspelled `alg` / `enc` is refused before any key work, with the same code and message `decrypt` uses for the same string: `ERR_JWE_ALG_NOT_ALLOWED` for a key management algorithm (including `"none"`), `ERR_JWE_INVALID` for a content encryption algorithm.

**Returns:** `Promise<string>` — JWE compact token

```ts
import { encrypt } from "unjwt/jwe";
import { generateJWK, generateKey } from "unjwt/jwk";

// Password-based (PBES2, simplest)
const token = await encrypt({ secret: "data" }, "my-password");

// Symmetric key (AES Key Wrap)
const aesKey = await generateJWK("A128KW");
const token2 = await encrypt({ secret: "data" }, aesKey);

// Asymmetric (RSA-OAEP)
const rsaKeys = await generateJWK("RSA-OAEP-256");
const token3 = await encrypt({ secret: "data" }, rsaKeys.publicKey);

// Direct encryption (dir) — key IS the CEK
const cek = await generateKey("A256GCM");
const token4 = await encrypt({ secret: "data" }, cek, { alg: "dir", enc: "A256GCM" });

// Direct encryption with a CEK JWK — `alg: "dir"` and `enc` both come from the key
const cekJwk = await generateJWK("A256GCM");
const token5 = await encrypt({ secret: "data" }, cekJwk); // alg = "dir", enc = "A256GCM"

// ECDH-ES
const ecKeys = await generateJWK("ECDH-ES+A256KW");
const token6 = await encrypt({ secret: "data" }, ecKeys.publicKey);
```

## `decrypt(jwe, key, options?)`

Decrypts a JWE token.

**Parameters:**

- `jwe` — `string` — the JWE compact token
- `key` — `CryptoKey | JWEDecryptJWK | JWKSet | string | Uint8Array | JWKLookupFunction`
  - `JWEDecryptJWK` is the private-side counterpart of `JWEEncryptJWK`. The key is imported with `expect: "private"`, so a public asymmetric JWK throws `ERR_JWK_INVALID`; `encrypt` mirrors this with `expect: "public"` and refuses one that still carries `d`.
  - `string` is a PBES2 password only — under any other `alg` it throws `ERR_JWK_INVALID`.
  - `JWKSet` stays fully permissive (`JWK[]`) — wire JWKS can carry any key shape; runtime filters per header.
  - For `alg: "dir"`, pass the raw CEK (`CryptoKey`, `JWK_oct`, or `Uint8Array`)
  - `JWKSet`: accepted directly or returned from a `JWKLookupFunction`; multi-key retry applies in both cases. A set is public-key material, so an entry is a candidate only when it is a JWK, is not `oct` (unless `allowSymmetricJWKSet`), its `kid` matches the header (or the header carries none), its `alg` matches (or it declares none), its `use` is absent or `"enc"`, and its `key_ops` is absent or contains one of `unwrapKey` / `decrypt` / `deriveBits` / `deriveKey`
    - Token has `kid` — only keys with that exact `kid` are tried (fast path, no retry)
    - Token has no `kid` — every candidate is tried in order; first to succeed wins
    - A candidate that cannot open the token — unusable key material as much as a failed unwrap — only means "try the next one"; when none succeeds, `ERR_JWE_DECRYPTION_FAILED` carries the per-candidate `JWTError`s (one per tried key, in order) as its `cause`
    - No matching candidates — throws `JWTError("ERR_JWK_KEY_NOT_FOUND")` before any crypto attempt
  - `JWKLookupFunction`: `(header, token) => key | JWKSet | Promise<key | JWKSet>` for dynamic key resolution
- `options?: JWEDecryptOptions`
  - `algorithms?: KeyManagementAlgorithm[]` — allowlist of key management algorithms. When omitted, the allowlist is inferred from the key shape via `inferJWEAllowedAlgorithms`; pass explicitly when the key carries no usable metadata. A raw `Uint8Array` is such a key: it declares nothing, so `decrypt(jwe, rawBytes, { algorithms: ["A256KW"] })` names the `alg` the matching `encrypt` call was given. A password `string` still infers the PBES2 family alone
  - `allowSymmetricJWKSet?: boolean` — default `false`. A JWK Set is treated as public-key material: its `oct` entries are ignored, both as candidates and for inference. `true` admits them, and is only appropriate for a set the application itself controls, never for one fetched from a `jwks_uri`

A `JWKLookupFunction` that throws surfaces as `ERR_JWK_KEY_NOT_FOUND` with the thrown value as its `cause`; one that returns `undefined` or `null` is `ERR_JWK_KEY_NOT_FOUND` too. The `kid` named in a key-not-found message is JSON-quoted and cut at 64 characters. A token that is not a string throws `ERR_JWE_INVALID` (`"Invalid JWE: token must be a string."`).

- `encryptionAlgorithms?: ContentEncryptionAlgorithm[]` — allowlist of content encryption algorithms
- `payload?: "json" | "string" | "bytes"` — what the payload is, declared by the caller. Defaults to `"json"`: the plaintext must be UTF-8 JSON naming a non-null, non-array object, or `ERR_JWE_INVALID` (`"Invalid JWE: Payload is not a JSON object."`). `"string"` returns UTF-8 text (invalid UTF-8 → `ERR_JWE_INVALID`), `"bytes"` returns `Uint8Array<ArrayBuffer>`. The decrypted content never decides its own shape, and `typ`/`cty` never pick it
- `validateClaims?: boolean` — `false` skips JWT claim validation. `undefined` (default) and `true` both validate under `payload: "json"`; `true` together with `payload: "string"` / `"bytes"` throws `ERR_INVALID_OPTION` (`'"validateClaims" requires payload: "json".'`) rather than silently not running
- `forceUint8Array?: boolean` — **deprecated** alias of `payload: "bytes"` (removed in v0.9.0). Passing both with conflicting values throws `ERR_INVALID_OPTION`
- `returnCek?: boolean` — include raw `cek` and `aad` in result. A CEK that cannot leave Web Crypto — a non-extractable `CryptoKey` under `dir`, or one unwrapped under `extractable: false` — throws `ERR_INVALID_OPTION` (`'"returnCek" requires an extractable content encryption key.'`)
- `extractable?: boolean` — whether the unwrapped CEK `CryptoKey` is extractable; defaults to `true`, and `false` is honoured
- `minIterations?: number` — minimum accepted PBES2 `p2c` on unwrap. Defaults to `1000` (RFC 7518 §4.8.1.2)
- `maxIterations?: number` — maximum accepted PBES2 `p2c` on unwrap. Defaults to `600_000` — the `p2c` a producer mints by default — to cap PBKDF2 DoS potential; raise it to open a token minted at a higher cost. It bounds a single unwrap; `limits.pbes2Iterations` bounds the whole call
- `limits?: { keyCandidates?: number; pbes2Iterations?: number }` — bounded work per call. `keyCandidates` defaults to `8`: a set still leaving more candidates after `kid`/`alg`/`use` filtering throws `ERR_JWK_KEY_NOT_FOUND` (`'12 candidate keys exceed the limit of 8; narrow the JWK Set with a "kid".'`) before the first import. `pbes2Iterations` defaults to `2_400_000` — four attempts at the `600_000` `p2c` a producer mints by default, so an envelope written entirely at the defaults is still openable by its fourth PBES2 recipient — and is a budget for the **whole call**, summed across every PBES2 attempt (compact unwrap, per recipient, per JWK Set candidate); an attempt whose `p2c` falls outside `minIterations`/`maxIterations` throws that bound, and one that no longer fits throws `ERR_JWE_INVALID` (`"PBES2 iteration budget of 2400000 exhausted."`); either spends nothing, so a recipient the caller does hold a key for is still tried on the remainder. Both must be positive integers, else `ERR_INVALID_OPTION`
- Inherits `JWTClaimValidationOptions`: `audience`, `issuer`, `subject`, `maxTokenAge`, `clockTolerance`, `typ`, `currentDate`, `requiredClaims`, `recognizedHeaders`
- `audience` — the `aud` claim is checked **only when this option is set**. A token carrying `aud` is accepted by a decryptor that configures none; configure `audience` to enforce RFC 7519 §4.1.3
- Options are checked before the token is read, as on `verify`: an empty `audience` / `issuer` / `subject` / `typ`, a non-string `typ`, `maxTokenAge: 0`, non-object `options` or `limits`, and an `algorithms` / `encryptionAlgorithms` / `requiredClaims` / `recognizedHeaders` that is not an array of strings throw `ERR_INVALID_OPTION`

**Returns:** `Promise<JWEDecryptResult<T>>`

**Return types follow the option.** The payload type is read off `JOSEPayloadTypeMap` by the `payload` literal (`PayloadOf<Mode, T>`, exported from `unjwt/jwe`):

- no `payload` or `payload: "json"` → `T`, the claims — `JWTClaims` unless given: `decrypt<MyClaims>(token, key)`
- `payload: "string"` → `string`; `payload: "bytes"` → `Uint8Array<ArrayBuffer>`
- a `payload` that is not a literal (a `JOSEPayloadMode` variable, a `JWEDecryptOptions` object) → the union of what its modes return
- the deprecated `forceUint8Array: true` → `Uint8Array<ArrayBuffer>`
- a claims type together with `payload: "string"` / `"bytes"` is a type error

**Header and segment validation.** Everything the protected header alone decides is settled before a key is resolved or imported, so a malformed token never reaches key management:

- `alg` — `"none"` and any algorithm outside the key-management table are rejected with `ERR_JWE_ALG_NOT_ALLOWED` before the `algorithms` allowlist is consulted.
- `enc` — an unsupported value is `ERR_JWE_INVALID` (`Invalid JWE: unsupported "enc" …`). The same table decides whether the unwrapped CEK is imported as a `CryptoKey` (AES-GCM) or kept as raw bytes (AES-CBC-HMAC).
- `zip` — compression is not implemented, and a token carrying `zip` is rejected with `ERR_JWE_INVALID` rather than decrypted without decompressing.
- `crit` — validated on the protected header before key management, so a `crit` violation surfaces as `ERR_JWE_INVALID` regardless of whether the key would have worked.
- `typ` — compared under RFC 7515 §4.1.9 media-type semantics: case-insensitive, `application/` optional. `typ: "at+jwt"` matches a header carrying `"application/AT+JWT"`. A protected header without `typ` fails it with `ERR_JWE_INVALID` (`'Invalid JWE: the protected header carries no "typ"; expected "at+jwt".'`).
- **Symmetric key roles** — an `oct` JWK's `alg` names the single role it holds, and roles do not alias: `A*KW` and `A*GCMKW` wrap only; a content encryption `alg` (`A*GCM`, `A*CBC-HS*`) is a CEK for `"dir"` only, and only when the token's `enc` equals that `alg`; `"dir"` serves any `enc` whose CEK length matches the key; a PBES2 `alg` serves only itself. A mismatch is `ERR_JWK_INVALID` — `JWK "alg" is "A256GCM" but "dir" requires a key declared as "dir" or as the token's "enc" (A128CBC-HS256).` for the CEK case, and the `importKey` authority message (`JWK "alg" is "A256GCM" but the operation requires "A256GCMKW".`) when a CEK is offered as a wrapping key.
- **Empty encrypted key for direct algorithms** — `dir` and bare `ECDH-ES` agree on the CEK directly (RFC 7516 §5.2 step 6), so a non-empty encrypted-key segment is `ERR_JWE_INVALID` instead of silently discarded bytes.
- **IV and tag lengths** — both are fixed by `enc` (12/16 bytes IV, 16/16/24/32 bytes tag) and checked before the AEAD primitive runs. Without it, `ciphertext ‖ tag` could be re-split by an attacker for AES-GCM, or the AES-CBC-HMAC tag compared truncated.
- **ECDH-ES `epk`** — the ephemeral public key is wire data: it must be an EC or OKP _public_ key (a `d` member is refused), on a curve the library supports (`P-256` / `P-384` / `P-521` / `X25519`; never `X448`) _and_ the same curve as the recipient key, and only `kty`/`crv`/coordinates are carried into the import — a forged `alg`, `key_ops`, `ext` or `use` is ignored. `apu` and `apv` are bounded at 1024 bytes each (`ERR_JWE_INVALID` beyond).

```ts
import { decrypt } from "unjwt/jwe";

// Password-based
const { payload } = await decrypt(token, "my-password");

// With algorithm restrictions
const result = await decrypt(token, privateKey, {
  algorithms: ["RSA-OAEP-256"],
  encryptionAlgorithms: ["A256GCM"],
});

// With CEK access
const { payload, cek, aad } = await decrypt(token, key, { returnCek: true });
```

## Multi-recipient (JSON Serialization)

`unjwt` exposes `encryptMulti` / `decryptMulti` for JWE General JSON Serialization (RFC 7516 §7.2.1). Use them whenever you need more than one recipient on a single ciphertext; for the single-recipient case compact `encrypt()`/`decrypt()` remains the right tool.

### `encryptMulti(payload, recipients, options?)`

Produces a `JWEGeneralSerialization` object — one shared CEK encrypts the payload once; the CEK is wrapped independently per recipient using each recipient's `alg`.

**Parameters:**

- `payload` — `string | Uint8Array | Record<string, any>`
- `recipients: JWEMultiRecipient[]` — non-empty. Each recipient is `{ key: JWEEncryptJWK, header?, ecdh?, p2s?, p2c?, keyManagementIV? }`. `key.alg` is required (inferred per-recipient; throws `ERR_JWE_RECIPIENT_ALG_INFERENCE` when absent). A `zip` in any header tier (protected, shared unprotected, per-recipient) throws `ERR_INVALID_OPTION`, and so does a `crit` in the shared unprotected or a per-recipient header — `crit` must be integrity protected, and `decryptMulti` rejects it anywhere else.
- `options?: JWEMultiEncryptOptions` — extends `JWEEncryptOptions` minus the per-recipient fields (`alg`, `ecdh`, `p2s`, `p2c`, `keyManagementIV`). Adds:
  - `sharedUnprotectedHeader?: Record<string, unknown>` — surfaces as top-level `unprotected`.
  - `aad?: Uint8Array | string` — external AAD (RFC 7516 §5.1); content cipher AAD becomes `BASE64URL(protected) || '.' || BASE64URL(aad)`. An empty `aad` is no AAD at all: the `aad` member is left out (RFC 7516 §7.2.1). On decrypt, a token whose `aad` member is present but empty is still opened, authenticating `BASE64URL(protected) || '.'` (RFC 7516 §5.2 step 15). Any other type throws `ERR_INVALID_OPTION` (`'"aad" must be a string or a Uint8Array.'`).

Throws `ERR_JWE_ALG_FORBIDDEN_IN_MULTI` when any recipient resolves to `dir` or bare `ECDH-ES` (these algorithms require exactly one recipient — use `encrypt()`). Throws `ERR_JWE_HEADER_PARAMS_NOT_DISJOINT` when a parameter name appears in more than one header tier.

The producer-side option gates of `encrypt` apply here too, each as `ERR_INVALID_OPTION`: `cek` and `contentEncryptionIV` must be the lengths `enc` fixes, `options.protectedHeader`'s `crit` must list extensions the header carries (and `crit` is refused in the unprotected tiers), a recipient's `ecdh.partyUInfo` / `partyVInfo` must be `Uint8Array`s of at most `1024` bytes, every recipient entry and every header option (`protectedHeader`, `sharedUnprotectedHeader`, a recipient's `header`) must be an object, and the protected header must serialize to JSON.

A PBES2 recipient that names no `p2c` is minted at `600_000` iterations, and the default `limits.pbes2Iterations` budget of `2_400_000` covers four such attempts — so an envelope written entirely at the defaults is openable by its fourth PBES2 recipient without the reader raising anything.

```ts
import { encryptMulti } from "unjwt/jwe";

const jwe = await encryptMulti(
  { sub: "u1", role: "admin" },
  [
    { key: aliceRsaPublicJwk }, // alg from JWK → RSA-OAEP-256
    { key: bobEcdhPublicJwk }, // alg from JWK → ECDH-ES+A256KW
    { key: sharedAesKwJwk, header: { "x-route": "eu" } },
  ],
  { enc: "A256GCM", expiresIn: "1h" },
);
```

### `decryptMulti(jwe, keyOrLookup, options?)`

Accepts a General or Flattened serialization object and returns the first recipient whose wrap can be unwrapped with the supplied key. Compact tokens go through `decrypt()`.

**Parameters:**

- `jwe` — `JWEGeneralSerialization | JWEFlattenedSerialization`. Flattened input is auto-normalized to General in memory. An object without `recipients` is Flattened — its `header` and `encrypted_key` are both optional (RFC 7516 §7.2.2), so a Flattened `dir` / `ECDH-ES` token carrying neither is accepted. `recipients` together with a top-level `header` or `encrypted_key` throws `ERR_JWE_INVALID_SERIALIZATION`.
- `keyOrLookup` — same shape as `decrypt()` (`JWK | JWKSet | CryptoKey | Uint8Array | string | JWKLookupFunction`). `JWKSet` / lookup functions are consulted per recipient until one succeeds.
- `options?: JWEMultiDecryptOptions` — extends `JWEDecryptOptions`. Adds:
  - `limits?: { recipients?: number; keyCandidates?: number; pbes2Iterations?: number }` — `recipients` defaults to `16`; a serialization carrying more throws `ERR_JWE_INVALID` (`"Invalid JWE: 17 recipients exceed the limit of 16."`) before any recipient is read. The `pbes2Iterations` budget is summed across every recipient, so injected PBES2 recipients cost one budget between them
  - `strictRecipientMatch?: boolean` — when `true`, a recipient is attempted only when the key material could plausibly open it; nothing matching means `ERR_JWE_NO_MATCHING_RECIPIENT` with no trial-decryption fallback. A recipient is skipped only on a _definite_ mismatch: a different `kid` on both sides, key material whose `kty` / curve / length cannot serve the recipient's `alg`, or an `epk` on a different curve than the key. Key material that carries no identity of its own (a `CryptoKey`, raw bytes, a password) is treated as unknown rather than mismatched — it falls through to the compatibility check instead of being filtered out.

**Header tiers (RFC 7516 §7.2.1).** `enc` is read from the protected header or, when absent there, from the shared unprotected header — never from a per-recipient header; absent from both is `ERR_JWE_INVALID`, and `encryptionAlgorithms` applies to it wherever it sits. `alg` may sit in any tier (usually the per-recipient header). `crit` must be protected, and every name it lists must be present in the protected header. `options.typ` is matched against the protected header only — a `typ` in an unprotected tier never satisfies it, since a type gate an attacker could move would gate nothing. `kid` is read from the merged header, so the key lookup may be steered by an unprotected tier; that is why the recipient must still unwrap, and the content still authenticate, under the key the lookup returns. A name may sit in only one tier (`ERR_JWE_HEADER_PARAMS_NOT_DISJOINT`; an overlap between the protected and the shared unprotected header is a token verdict).

**Recipient isolation.** `recipients[]` is not covered by the AAD, so anyone can append or rewrite an entry. Every failure scoped to a single recipient — an entry that is not a JSON object (or whose `header` is not one, or whose `encrypted_key` is not a string), a header tier overlap, a `crit` or `zip` in its header, missing PBES2 `p2s`/`p2c`, a missing `epk`, missing AES-GCMKW `iv`/`tag`, an unsupported `alg`, a failed unwrap — only means "try the next recipient" and is kept as the error to report if no recipient works. A verdict on the token as a whole — the protected header (`crit` included, validated before any key management), the shared unprotected header (including one that is not a JSON object), the content segments, and (after a successful decryption) JWT claim validation — is thrown immediately.

**Returns:** `JWEMultiDecryptResult<T>` — the payload type follows `options.payload` exactly as for `decrypt` (`PayloadOf<Mode>`; `decryptMulti<MyClaims>(jwe, key)` for the claims). Like `JWEDecryptResult`, except:

- `protectedHeader: JWEHeaderParameters` — exactly what was integrity protected (`{}` when there is no `protected` member). `alg` and `enc` appear here only when the producer protected them; `encryptMulti` writes `alg` per recipient, so read it from `recipientHeader`.
- `recipientIndex: number` — index into `jwe.recipients` that decrypted.
- `recipientHeader?: JWEHeaderParameters` — per-recipient unprotected header.
- `sharedUnprotectedHeader?: JWEHeaderParameters` — shared unprotected header, when present.

```ts
import { decryptMulti } from "unjwt/jwe";

// Receiver with their own private key
const { payload, recipientIndex, recipientHeader } = await decryptMulti(
  jweFromWire,
  bobEcdhPrivateJwk,
);

// Or via JWKSet / lookup function (same API as decrypt())
const jwe = JSON.parse(jweString);
const { payload } = await decryptMulti(jwe, myJwkSet);
const { payload } = await decryptMulti(jwe, (header) => fetchKeyByKid(header.kid));

// Strict — fail fast when no recipient matches
const { payload } = await decryptMulti(jwe, key, { strictRecipientMatch: true });
```

### `generalToFlattened(jwe)`

`encryptMulti` always emits General, even for a single recipient — which keeps the return shape stable if you later add recipients. For strict Flattened-only consumers, post-process with this helper:

```ts
import { encryptMulti, generalToFlattened } from "unjwt/jwe";

const general = await encryptMulti(payload, [recipient], opts);
const flattened = generalToFlattened(general); // JWEFlattenedSerialization
```

Throws `ERR_JWE_INVALID_SERIALIZATION` when the input has zero or multiple recipients — Flattened is strictly single-recipient. `decryptMulti` accepts both shapes as input.

### Differences from JWS's multi-signature model

JWE's multi-recipient model has one more moving part than JWS's multi-signature model:

- **Shared protected header, per-recipient key management.** Opposite of JWS — JWE has one shared `protected` header (contains `enc`, `typ`, etc., part of AAD) and per-recipient `header` fields (contains `alg`, `kid`, `epk`, etc.). JWS has no shared protected header: each signer has its own.
- **Three header tiers: protected / shared unprotected / per-recipient.** RFC 7516 §7.2.1 defines all three; `jwe.unprotected` (shared across all recipients, not part of AAD) is the middle tier that JWS lacks entirely. Every parameter name must appear in at most one tier per recipient (RFC-mandated disjointness).
- **Shared CEK tied to the content ciphertext.** One random CEK encrypts the payload once; each recipient wraps the same CEK with its own alg. This is why `dir` and bare `ECDH-ES` are forbidden in multi — those algs make the recipient's key _be_ the CEK, which can't be shared across recipients without collapsing security. `ERR_JWE_ALG_FORBIDDEN_IN_MULTI` surfaces that.
- **External AAD support (RFC 7516 §5.1).** The `aad` field binds the ciphertext to out-of-band context (document hash, request URL). JWS has no analog — signatures already cover the whole payload.
- **"First recipient that decrypts" semantics.** One recipient's key unlocks the ciphertext; the others are invisible to that recipient. By contrast, JWS signatures are independently verifiable — any verifier can check any subset (see `verifyMulti` in the JWS reference).

## Errors

Every JOSE operation in this module throws `JWTError` — a single `instanceof` is enough. When the root cause is one of the bundled [`unsecure`](https://github.com/sandros94/unsecure) primitives (base64url codec, JSON parse), it is preserved as `cause`:

```ts
import { decrypt, isJWTError, isUnsecureError } from "unjwt/jwe";

const error = await decrypt(jwe, key).catch((e) => e);
if (isJWTError(error, "ERR_JWE_INVALID") && isUnsecureError(error.cause, "MALFORMED")) {
  // a segment of the wire format is not canonical base64url
}
```

`unsecure` is inlined into unjwt's dist, so `instanceof` against a consumer-installed `unsecure` never matches. Use the `UnsecureError` / `isUnsecureError` that unjwt re-exports. The `unjwt/utils` primitives themselves still throw `UnsecureError` directly — only the JOSE operations wrap.

## Types

```ts
// Narrow key-type aliases enforced at the encrypt/decrypt boundary.
// `_JWEOctAlg` lists symmetric algs usable as a JWE key-management key — HMAC is intentionally
// excluded because it has no JWE use.
type _JWEOctAlg = JWK_AES_KW | JWK_AES_GCM | JWK_AES_GCM_KW | JWK_AES_CBC_HMAC | JWK_PBES2 | "dir";
type JWEAsymmetricPublicJWK =
  JWK_RSA_Public<JWK_RSA_ENC> | JWK_EC_Public<JWK_ECDH_ES> | JWK_OKP_Public<JWK_ECDH_ES>;
type JWEAsymmetricPrivateJWK =
  JWK_RSA_Private<JWK_RSA_ENC> | JWK_EC_Private<JWK_ECDH_ES> | JWK_OKP_Private<JWK_ECDH_ES>;
type JWEEncryptJWK = JWK_oct<_JWEOctAlg> | JWEAsymmetricPublicJWK;
type JWEDecryptJWK = JWK_oct<_JWEOctAlg> | JWEAsymmetricPrivateJWK;

type JOSEPayload = string | Uint8Array<ArrayBuffer> | Record<string, unknown>;

// Bounded work per call. Each operation exposes the subset that applies to it;
// `DEFAULT_JOSE_LIMITS` (exported from `unjwt`, `unjwt/jws` and `unjwt/jwe`)
// carries the defaults below. Every value must be a positive integer.
interface JOSELimits {
  signatures?: number; // JWS `signatures[]` entries — default 16
  recipients?: number; // JWE `recipients[]` entries — default 16
  keyCandidates?: number; // JWK Set candidates per token — default 8
  pbes2Iterations?: number; // PBKDF2 iterations per call — default 2_400_000 (4 × the default p2c)
}

type Duration =
  | number
  | `${number}`
  | `${number}${"s" | "second" | "seconds" | "m" | "minute" | "minutes" | "h" | "hour" | "hours" | "D" | "day" | "days" | "W" | "week" | "weeks" | "M" | "month" | "months" | "Y" | "year" | "years"}`;

type ExpiresIn = Duration;

interface JWEHeaderParameters {
  // JOSE header parameters (shared with JWS)
  kid?: string;
  x5t?: string;
  x5c?: string[];
  x5u?: string;
  jku?: string;
  jwk?: JWK_Public;
  typ?: string;
  cty?: string;
  crit?: string[];
  // JWE-specific header parameters
  alg?: KeyManagementAlgorithm | (string & {});
  enc?: ContentEncryptionAlgorithm | (string & {});
  p2c?: number;
  p2s?: string;
  iv?: string;
  tag?: string;
  epk?: JWK_EC_Public | JWK_OKP_Public;
  apu?: string;
  apv?: string;
  zip?: never; // compression is not supported
  [propName: string]: unknown;
}

interface JWEProtectedHeader {
  // JOSE header parameters (shared with JWS)
  kid?: string;
  x5t?: string;
  x5c?: string[];
  x5u?: string;
  jku?: string;
  jwk?: JWK_Public;
  typ?: string;
  cty?: string;
  crit?: string[];
  // JWE-specific — alg and enc are required in a protected header
  alg: KeyManagementAlgorithm;
  enc: ContentEncryptionAlgorithm;
  p2c?: number;
  p2s?: string;
  iv?: string;
  tag?: string;
  epk?: JWK_EC_Public | JWK_OKP_Public;
  apu?: string;
  apv?: string;
  zip?: never; // compression is not supported
  [propName: string]: unknown;
}

interface JWEEncryptOptions {
  alg?: KeyManagementAlgorithm;
  enc?: ContentEncryptionAlgorithm;
  currentDate?: Date;
  expiresIn?: ExpiresIn;
  expiresAt?: Date;
  notBeforeIn?: ExpiresIn;
  notBeforeAt?: Date;
  // Additional header params — alg/enc/iv/tag/p2s/p2c/epk/apu/apv are reserved
  // and typed as `never` to signal they cannot be set here.
  protectedHeader?: {
    alg?: never;
    enc?: never;
    iv?: never;
    tag?: never;
    p2s?: never;
    p2c?: never;
    epk?: never;
    apu?: never;
    apv?: never;
    kid?: string;
    x5t?: string;
    x5c?: string[];
    x5u?: string;
    jku?: string;
    jwk?: JWK_Public;
    typ?: string;
    cty?: string;
    crit?: string[];
    [propName: string]: unknown;
  };
  keyManagementIV?: Uint8Array<ArrayBuffer>;
  p2s?: Uint8Array<ArrayBuffer>;
  p2c?: number; // default: 600_000 for PBES2
  ecdh?: {
    ephemeralKey?:
      | CryptoKey
      | JWK_EC_Private
      | JWK_OKP_Private
      | CryptoKeyPair
      | {
          publicKey: CryptoKey | JWK_EC_Public | JWK_OKP_Public;
          privateKey: CryptoKey | JWK_EC_Private | JWK_OKP_Private;
        };
    partyUInfo?: Uint8Array<ArrayBuffer>;
    partyVInfo?: Uint8Array<ArrayBuffer>;
  };
  cek?: Uint8Array<ArrayBuffer>;
  contentEncryptionIV?: Uint8Array<ArrayBuffer>;
}

// `Mode` is the `payload` literal decrypt reads its return type from — see
// `JOSEPayloadTypeMap` / `PayloadOf` in the JWS reference.
interface JWEDecryptOptions<Mode extends JOSEPayloadMode = JOSEPayloadMode> {
  // JWT claim validation options (inlined from JWTClaimValidationOptions)
  audience?: string | string[];
  issuer?: string | string[];
  subject?: string;
  maxTokenAge?: Duration;
  clockTolerance?: number | Duration; // seconds, or a Duration shorthand
  typ?: string;
  currentDate?: Date;
  requiredClaims?: string[];
  recognizedHeaders?: string[];
  // JWE-specific decrypt options
  algorithms?: KeyManagementAlgorithm[];
  allowSymmetricJWKSet?: boolean;
  encryptionAlgorithms?: ContentEncryptionAlgorithm[];
  unwrappedKeyAlgorithm?: Parameters<typeof crypto.subtle.importKey>[2];
  keyUsage?: KeyUsage[];
  extractable?: boolean;
  payload?: Mode;
  /** @deprecated Use `payload: "bytes"`. Removed in v0.9.0 */
  forceUint8Array?: boolean;
  validateClaims?: boolean;
  returnCek?: boolean;
  minIterations?: number; // default: 1000
  maxIterations?: number; // default: 600_000 (the default p2c)
  limits?: Pick<JOSELimits, "keyCandidates" | "pbes2Iterations">;
}

interface JWEDecryptResult<T extends JOSEPayload = JOSEPayload> {
  payload: T;
  protectedHeader: JWEProtectedHeader; // alg and enc are required and strongly typed
  cek?: Uint8Array<ArrayBuffer>; // only when returnCek: true
  aad?: Uint8Array<ArrayBuffer>; // only when returnCek: true
}

// --- Multi-recipient (RFC 7516 §7.2) ---

interface JWEFlattenedSerialization {
  header?: JWEHeaderParameters;
  encrypted_key?: string;
  protected?: string;
  unprotected?: JWEHeaderParameters;
  aad?: string;
  iv: string;
  ciphertext: string;
  tag: string;
}

interface JWEGeneralSerialization {
  protected?: string;
  unprotected?: JWEHeaderParameters;
  recipients: JWEGeneralRecipient[];
  aad?: string;
  iv: string;
  ciphertext: string;
  tag: string;
}

interface JWEGeneralRecipient {
  header?: JWEHeaderParameters;
  encrypted_key?: string;
}

interface JWEMultiRecipient {
  key: JWEEncryptJWK;
  // Per-recipient header — alg/enc/iv/tag/p2s/p2c/epk/apu/apv are reserved.
  header?: {
    alg?: never;
    enc?: never;
    iv?: never;
    tag?: never;
    p2s?: never;
    p2c?: never;
    epk?: never;
    apu?: never;
    apv?: never;
    kid?: string;
    x5t?: string;
    x5c?: string[];
    x5u?: string;
    jku?: string;
    jwk?: JWK_Public;
    typ?: string;
    cty?: string;
    crit?: string[];
    [propName: string]: unknown;
  };
  ecdh?: {
    ephemeralKey?:
      | CryptoKey
      | JWK_EC_Private
      | JWK_OKP_Private
      | CryptoKeyPair
      | {
          publicKey: CryptoKey | JWK_EC_Public | JWK_OKP_Public;
          privateKey: CryptoKey | JWK_EC_Private | JWK_OKP_Private;
        };
    partyUInfo?: Uint8Array<ArrayBuffer>;
    partyVInfo?: Uint8Array<ArrayBuffer>;
  };
  p2s?: Uint8Array<ArrayBuffer>;
  p2c?: number;
  keyManagementIV?: Uint8Array<ArrayBuffer>;
}

interface JWEMultiEncryptOptions {
  // Inherited from JWEEncryptOptions (minus alg, ecdh, p2s, p2c, keyManagementIV)
  enc?: ContentEncryptionAlgorithm;
  currentDate?: Date;
  expiresIn?: ExpiresIn;
  expiresAt?: Date;
  notBeforeIn?: ExpiresIn;
  notBeforeAt?: Date;
  protectedHeader?: {
    alg?: never;
    enc?: never;
    iv?: never;
    tag?: never;
    p2s?: never;
    p2c?: never;
    epk?: never;
    apu?: never;
    apv?: never;
    kid?: string;
    x5t?: string;
    x5c?: string[];
    x5u?: string;
    jku?: string;
    jwk?: JWK_Public;
    typ?: string;
    cty?: string;
    crit?: string[];
    [propName: string]: unknown;
  };
  cek?: Uint8Array<ArrayBuffer>;
  contentEncryptionIV?: Uint8Array<ArrayBuffer>;
  // Multi-recipient additions
  sharedUnprotectedHeader?: Record<string, unknown>;
  aad?: Uint8Array<ArrayBuffer> | string;
}

interface JWEMultiDecryptOptions<Mode extends JOSEPayloadMode = JOSEPayloadMode> {
  // JWT claim validation options (inlined from JWTClaimValidationOptions)
  audience?: string | string[];
  issuer?: string | string[];
  subject?: string;
  maxTokenAge?: Duration;
  clockTolerance?: number | Duration; // seconds, or a Duration shorthand
  typ?: string;
  currentDate?: Date;
  requiredClaims?: string[];
  recognizedHeaders?: string[];
  // JWE decrypt options (inlined from JWEDecryptOptions)
  algorithms?: KeyManagementAlgorithm[];
  allowSymmetricJWKSet?: boolean;
  encryptionAlgorithms?: ContentEncryptionAlgorithm[];
  unwrappedKeyAlgorithm?: Parameters<typeof crypto.subtle.importKey>[2];
  keyUsage?: KeyUsage[];
  extractable?: boolean;
  payload?: Mode;
  /** @deprecated Use `payload: "bytes"`. Removed in v0.9.0 */
  forceUint8Array?: boolean;
  validateClaims?: boolean;
  returnCek?: boolean;
  minIterations?: number;
  maxIterations?: number;
  // Multi-recipient additions
  limits?: Pick<JOSELimits, "recipients" | "keyCandidates" | "pbes2Iterations">;
  strictRecipientMatch?: boolean;
}

interface JWEMultiDecryptResult<T extends JOSEPayload = JOSEPayload> {
  payload: T;
  protectedHeader: JWEHeaderParameters; // only what was protected — alg/enc may be in the other tiers
  cek?: Uint8Array<ArrayBuffer>;
  aad?: Uint8Array<ArrayBuffer>;
  sharedUnprotectedHeader?: JWEHeaderParameters;
  recipientHeader?: JWEHeaderParameters;
  recipientIndex: number;
}

// JWKLookupFunction is shared with JWS verify — imported from unjwt/jwk or unjwt
// Optional `TReturn` generic narrows the return type; defaults fully permissive.
type JWKLookupFunction<TReturn = CryptoKey | JWK | JWKSet | string | Uint8Array<ArrayBuffer>> = (
  header: {
    kid?: string;
    alg?: string;
    enc?: string;
    typ?: string;
    crit?: string[];
    [key: string]: unknown;
  },
  token: string,
) => TReturn | Promise<TReturn>;
```
