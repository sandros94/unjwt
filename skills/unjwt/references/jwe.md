# JWE Reference (unjwt/jwe)

JSON Web Encryption ([RFC 7516](https://www.rfc-editor.org/rfc/rfc7516.txt)) — encrypt and decrypt data.

Import: `import { encrypt, decrypt } from "unjwt/jwe"` — or `from "unjwt"`

## Algorithms

### Key Management (`alg`)

| Family           | Identifiers                                                      |
| ---------------- | ---------------------------------------------------------------- |
| Direct           | `dir`                                                            |
| RSA-OAEP         | `RSA-OAEP`, `RSA-OAEP-256`, `RSA-OAEP-384`, `RSA-OAEP-512`       |
| AES Key Wrap     | `A128KW`, `A192KW`, `A256KW`                                     |
| AES-GCM Key Wrap | `A128GCMKW`, `A192GCMKW`, `A256GCMKW`                            |
| PBES2            | `PBES2-HS256+A128KW`, `PBES2-HS384+A192KW`, `PBES2-HS512+A256KW` |
| ECDH-ES          | `ECDH-ES`, `ECDH-ES+A128KW`, `ECDH-ES+A192KW`, `ECDH-ES+A256KW`  |

Type: `KeyManagementAlgorithm`

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
  - `string` → password for PBES2 (infers `alg = "PBES2-HS256+A128KW"`)
  - `JWEEncryptJWK` → infers `alg`/`enc` from key properties. Narrows by family: `JWK_oct` with a JWE symmetric `alg` (AES-KW, AES-GCM, AES-GCM-KW, AES-CBC-HMAC, PBES2, `"dir"`) or an asymmetric _public_ JWK whose `alg` is RSA-OAEP or ECDH-ES. HMAC / signing-family JWKs are rejected at the type level.
  - `CryptoKey | Extract<JWEEncryptJWK, { kty: "oct" }> | Uint8Array` with `alg: "dir"` → used directly as the CEK (`enc` required)
  - `CryptoKey` with other algorithms → requires explicit `alg` and `enc`
- `options?: JWEEncryptOptions`
  - `alg?: KeyManagementAlgorithm`
  - `enc?: ContentEncryptionAlgorithm` — required when `alg` is `"dir"`
  - `protectedHeader?` — additional header params (excludes `alg`/`enc`/`iv`/`tag`/`p2s`/`p2c`/`epk`/`apu`/`apv`; `zip` is typed `never` and rejected at runtime with `ERR_INVALID_OPTION`)
  - `expiresIn?: ExpiresIn` — sets `exp` claim
  - `currentDate?: Date`
  - `cek?: Uint8Array` — custom Content Encryption Key
  - `contentEncryptionIV?: Uint8Array` — custom IV
  - `p2s?: Uint8Array`, `p2c?: number` — PBES2 salt and iteration count (default `p2c` is `600_000`)
  - `keyManagementIV?: Uint8Array` — IV for AES-GCM key wrapping
  - `ecdh?` — `{ ephemeralKey?, partyUInfo?, partyVInfo?, enc? }` for ECDH-ES; `enc` required only for bare `"ECDH-ES"`

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

// Direct encryption with a JWK_oct that carries an enc hint
const cekJwk = { ...(await generateJWK("A256GCM")), enc: "A256GCM" };
const token5 = await encrypt({ secret: "data" }, cekJwk, { alg: "dir" }); // enc inferred from jwk.enc

// ECDH-ES
const ecKeys = await generateJWK("ECDH-ES+A256KW");
const token6 = await encrypt({ secret: "data" }, ecKeys.publicKey);
```

## `decrypt(jwe, key, options?)`

Decrypts a JWE token.

**Parameters:**

- `jwe` — `string` — the JWE compact token
- `key` — `CryptoKey | JWEDecryptJWK | JWKSet | string | Uint8Array | JWKLookupFunction`
  - `JWEDecryptJWK` is the private-side counterpart of `JWEEncryptJWK`.
  - `JWKSet` stays fully permissive (`JWK[]`) — wire JWKS can carry any key shape; runtime filters per header.
  - For `alg: "dir"`, pass the raw CEK (`CryptoKey`, `JWK_oct`, or `Uint8Array`)
  - `JWKSet`: accepted directly or returned from a `JWKLookupFunction`; multi-key retry applies in both cases
    - Token has `kid` — only keys with that exact `kid` are tried (fast path, no retry)
    - Token has no `kid` — all keys whose `alg` field is compatible are tried in order; first to succeed wins
    - No matching candidates — throws `JWTError("ERR_JWK_KEY_NOT_FOUND")` before any crypto attempt
  - `JWKLookupFunction`: `(header, token) => key | JWKSet | Promise<key | JWKSet>` for dynamic key resolution
- `options?: JWEDecryptOptions`
  - `algorithms?: KeyManagementAlgorithm[]` — allowlist of key management algorithms. When omitted, the allowlist is inferred from the key shape via `inferJWEAllowedAlgorithms`; pass explicitly when the key carries no usable metadata
  - `encryptionAlgorithms?: ContentEncryptionAlgorithm[]` — allowlist of content encryption algorithms
  - `validateClaims?: boolean` — `false` explicitly skips JWT claim validation. Defaults to `undefined`, which validates whenever the decrypted payload is a JSON object — **independent of the `typ` header**, because `typ` is signer-controlled and cannot gate security-critical checks
  - `forceUint8Array?: boolean` — force payload as `Uint8Array`
  - `returnCek?: boolean` — include raw `cek` and `aad` in result
  - `minIterations?: number` — minimum accepted PBES2 `p2c` on unwrap. Defaults to `1000` (RFC 7518 §4.8.1.2)
  - `maxIterations?: number` — maximum accepted PBES2 `p2c` on unwrap. Defaults to `1_000_000` to cap PBKDF2 DoS potential
  - Inherits `JWTClaimValidationOptions`: `audience`, `issuer`, `subject`, `maxTokenAge`, `clockTolerance`, `typ`, `currentDate`, `requiredClaims`, `recognizedHeaders`

**Returns:** `Promise<JWEDecryptResult<T>>`

**Header and segment validation.** Everything the protected header alone decides is settled before a key is resolved or imported, so a malformed token never reaches key management:

- `alg` — `"none"` and any algorithm outside the key-management table are rejected with `ERR_JWE_ALG_NOT_ALLOWED` before the `algorithms` allowlist is consulted.
- `enc` — an unsupported value is `ERR_JWE_INVALID` (`Invalid JWE: unsupported "enc" …`). The same table decides whether the unwrapped CEK is imported as a `CryptoKey` (AES-GCM) or kept as raw bytes (AES-CBC-HMAC).
- `zip` — compression is not implemented, and a token carrying `zip` is rejected with `ERR_JWE_INVALID` rather than decrypted without decompressing.
- `crit` — validated on the protected header before key management, so a `crit` violation surfaces as `ERR_JWE_INVALID` regardless of whether the key would have worked.
- `typ` — compared under RFC 7515 §4.1.9 media-type semantics: case-insensitive, `application/` optional. `typ: "at+jwt"` matches a header carrying `"application/AT+JWT"`.
- **Empty encrypted key for direct algorithms** — `dir` and bare `ECDH-ES` agree on the CEK directly (RFC 7516 §5.2 step 6), so a non-empty encrypted-key segment is `ERR_JWE_INVALID` instead of silently discarded bytes.
- **IV and tag lengths** — both are fixed by `enc` (12/16 bytes IV, 16/16/24/32 bytes tag) and checked before the AEAD primitive runs. Without it, `ciphertext ‖ tag` could be re-split by an attacker for AES-GCM, or the AES-CBC-HMAC tag compared truncated.
- **ECDH-ES `epk`** — the ephemeral public key is wire data: it must be an EC or OKP _public_ key (a `d` member is refused), on a curve the library supports _and_ the same curve as the recipient key, and only `kty`/`crv`/coordinates are carried into the import — a forged `alg`, `key_ops`, `ext` or `use` is ignored. `apu` and `apv` are bounded at 1024 bytes each (`ERR_JWE_INVALID` beyond).

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
- `recipients: JWEMultiRecipient[]` — non-empty. Each recipient is `{ key: JWEEncryptJWK, header?, ecdh?, p2s?, p2c?, keyManagementIV? }`. `key.alg` is required (inferred per-recipient; throws `ERR_JWE_RECIPIENT_ALG_INFERENCE` when absent). A `zip` in any header tier (protected, shared unprotected, per-recipient) throws `ERR_INVALID_OPTION`.
- `options?: JWEMultiEncryptOptions` — extends `JWEEncryptOptions` minus the per-recipient fields (`alg`, `ecdh`, `p2s`, `p2c`, `keyManagementIV`). Adds:
  - `sharedUnprotectedHeader?: Record<string, unknown>` — surfaces as top-level `unprotected`.
  - `aad?: Uint8Array | string` — external AAD (RFC 7516 §5.1); content cipher AAD becomes `BASE64URL(protected) || '.' || BASE64URL(aad)`.

Throws `ERR_JWE_ALG_FORBIDDEN_IN_MULTI` when any recipient resolves to `dir` or bare `ECDH-ES` (these algorithms require exactly one recipient — use `encrypt()`). Throws `ERR_JWE_HEADER_PARAMS_NOT_DISJOINT` when a parameter name appears in more than one header tier.

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

- `jwe` — `JWEGeneralSerialization | JWEFlattenedSerialization`. Flattened input is auto-normalized to General in memory.
- `keyOrLookup` — same shape as `decrypt()` (`JWK | JWKSet | CryptoKey | Uint8Array | string | JWKLookupFunction`). `JWKSet` / lookup functions are consulted per recipient until one succeeds.
- `options?: JWEMultiDecryptOptions` — extends `JWEDecryptOptions`. Adds:
  - `strictRecipientMatch?: boolean` — when `true`, a recipient is attempted only when the key material could plausibly open it; nothing matching means `ERR_JWE_NO_MATCHING_RECIPIENT` with no trial-decryption fallback. A recipient is skipped only on a _definite_ mismatch: a different `kid` on both sides, key material whose `kty` / curve / length cannot serve the recipient's `alg`, or an `epk` on a different curve than the key. Key material that carries no identity of its own (a `CryptoKey`, raw bytes, a password) is treated as unknown rather than mismatched — it falls through to the compatibility check instead of being filtered out.

**Recipient isolation.** `recipients[]` is not covered by the AAD, so anyone can append or rewrite an entry. Every failure scoped to a single recipient — a header tier overlap, a `crit` or `zip` in its header, missing PBES2 `p2s`/`p2c`, a missing `epk`, missing AES-GCMKW `iv`/`tag`, an unsupported `alg`, a failed unwrap — only means "try the next recipient" and is kept as the error to report if no recipient works. A verdict on the token as a whole — the protected header, the shared unprotected header, the content segments, and (after a successful decryption) `crit` and JWT claim validation — is thrown immediately.

**Returns:** `JWEMultiDecryptResult<T>` — extends `JWEDecryptResult` with:

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
      | CryptoKeyPair
      | {
          publicKey: CryptoKey | JWK_EC_Public;
          privateKey: CryptoKey | JWK_EC_Private;
        };
    partyUInfo?: Uint8Array<ArrayBuffer>;
    partyVInfo?: Uint8Array<ArrayBuffer>;
  };
  cek?: Uint8Array<ArrayBuffer>;
  contentEncryptionIV?: Uint8Array<ArrayBuffer>;
}

interface JWEDecryptOptions {
  // JWT claim validation options (inlined from JWTClaimValidationOptions)
  audience?: string | string[];
  issuer?: string | string[];
  subject?: string;
  maxTokenAge?: Duration;
  clockTolerance?: number; // seconds
  typ?: string;
  currentDate?: Date;
  requiredClaims?: string[];
  recognizedHeaders?: string[];
  // JWE-specific decrypt options
  algorithms?: KeyManagementAlgorithm[];
  encryptionAlgorithms?: ContentEncryptionAlgorithm[];
  unwrappedKeyAlgorithm?: Parameters<typeof crypto.subtle.importKey>[2];
  keyUsage?: KeyUsage[];
  extractable?: boolean;
  forceUint8Array?: boolean;
  validateClaims?: boolean;
  returnCek?: boolean;
  minIterations?: number; // default: 1000
  maxIterations?: number; // default: 1_000_000
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
      | CryptoKeyPair
      | {
          publicKey: CryptoKey | JWK_EC_Public;
          privateKey: CryptoKey | JWK_EC_Private;
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

interface JWEMultiDecryptOptions {
  // JWT claim validation options (inlined from JWTClaimValidationOptions)
  audience?: string | string[];
  issuer?: string | string[];
  subject?: string;
  maxTokenAge?: Duration;
  clockTolerance?: number; // seconds
  typ?: string;
  currentDate?: Date;
  requiredClaims?: string[];
  recognizedHeaders?: string[];
  // JWE decrypt options (inlined from JWEDecryptOptions)
  algorithms?: KeyManagementAlgorithm[];
  encryptionAlgorithms?: ContentEncryptionAlgorithm[];
  unwrappedKeyAlgorithm?: Parameters<typeof crypto.subtle.importKey>[2];
  keyUsage?: KeyUsage[];
  extractable?: boolean;
  forceUint8Array?: boolean;
  validateClaims?: boolean;
  returnCek?: boolean;
  minIterations?: number;
  maxIterations?: number;
  // Multi-recipient addition
  strictRecipientMatch?: boolean;
}

interface JWEMultiDecryptResult<T extends JOSEPayload = JOSEPayload> {
  payload: T;
  protectedHeader: JWEProtectedHeader;
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
