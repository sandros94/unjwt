# JWS Reference (unjwt/jws)

JSON Web Signature ([RFC 7515](https://www.rfc-editor.org/rfc/rfc7515.txt)) — sign and verify tokens.

Import: `import { sign, verify } from "unjwt/jws"` — or `from "unjwt"`

## Algorithms

| Family          | Identifiers               |
| --------------- | ------------------------- |
| HMAC            | `HS256`, `HS384`, `HS512` |
| RSA PKCS#1 v1.5 | `RS256`, `RS384`, `RS512` |
| RSA-PSS         | `PS256`, `PS384`, `PS512` |
| ECDSA           | `ES256`, `ES384`, `ES512` |
| EdDSA           | `Ed25519`, `EdDSA`        |

Type: `JWSAlgorithm`

`EdDSA` is Ed25519 only: an `Ed448` key is refused at generation and import. `EdDSA` (RFC 8037) and `Ed25519` (fully-specified) name the same signature: a key whose `alg` is either verifies and signs tokens under either name, and `inferJWSAllowedAlgorithms` returns both.

## `sign(payload, key, options?)`

Creates a JWS Compact Serialization token.

**Parameters:**

- `payload` — `JOSEPayload` = `string | Uint8Array | object` (objects are JSON-serialized; interfaces welcome)
- `key` — `CryptoKey | JWSSignJWK | Uint8Array`
  - `JWSSignJWK` narrows by family: `JWK_oct<JWK_HMAC>` | asymmetric private JWK with a signing `alg`.
    A JWK whose `alg` points at a non-signing family (`"RSA-OAEP"`, `"A256KW"`, …) is rejected at the type level.
  - JWK keys infer `alg` automatically; CryptoKey/Uint8Array require `options.alg`
  - A `string` is never a key: every JWS entry point throws `ERR_JWK_INVALID`
    (`"Key must be a JWK, CryptoKey or Uint8Array, not a string."`).
    Without it, `sign(payload, pemText, { alg: "HS256" })` would HMAC over the PEM armour.
- `options?: JWSSignOptions`
  - `alg?: JWSAlgorithm` — required when key is CryptoKey or Uint8Array
  - `protectedHeader?: JWSHeaderParameters` — additional header params (`kid`, `typ`, `cty`, `crit`, `b64`, `jwk`). A `jwk` must be a public JWK (`isPublicJWK`): a private key or an `oct` secret there is `ERR_INVALID_OPTION`, in every tier of `signMulti` too. A JSON payload whose `cnf.jwk` is not a public JWK is `ERR_JWT_CLAIM_INVALID` (RFC 7800 §3.2), in every producer
  - `expiresIn?: ExpiresIn` — sets `exp` claim relative to `currentDate`, the clock (number in seconds, or string like `"1h"`, `"7D"`). A malformed duration throws `ERR_INVALID_OPTION`
  - `issuedAt?: boolean | Date` — writes `iat` alone: `true` as `currentDate`, a `Date` as that instant; `false` is unset. Anything else is `ERR_INVALID_OPTION`. `iat` and the clock are distinct: a backdated `iat` does not move `exp`/`nbf`
  - `currentDate?: Date` — the clock: `iat` when written, and the base of `expiresIn`/`notBeforeIn`

**Returns:** `Promise<string>` — JWS compact token

**Behavior:**

- The `alg` is settled before any key work: `"none"` and anything outside `JWSAlgorithm` are refused with `ERR_JWS_ALG_NOT_ALLOWED`, carrying the same message `verify` reports for the same string
- A payload that is neither text, bytes nor an object, and one `JSON.stringify` refuses (a `BigInt`, a circular reference), throw `ERR_INVALID_OPTION` — as does a `protectedHeader` that will not serialize
- A caller `crit` is held to the rules `verify` applies, as `ERR_INVALID_OPTION`: a non-empty array of strings, no parameter registered by RFC 7515/7516/7518, and every entry present in the protected header being built — `"b64"` included, so `crit: ["b64"]` needs a `b64` member (`b64: true` is kept in the header when `crit` lists it, dropped otherwise). The same gate runs per signer in `signMulti`, which also refuses `crit` and `b64` in a signer's `unprotectedHeader` (`ERR_INVALID_OPTION`)
- `b64` must be a boolean (RFC 7797 §3) — any other value is `ERR_INVALID_OPTION`. A `protectedHeader` that is not an object (a string, an array, `null`) is `ERR_INVALID_OPTION` too, as is a `signMulti` signer entry, or its `protectedHeader`/`unprotectedHeader`, that is not one
- A key that cannot serve the declared `alg` throws `ERR_JWK_INVALID` with the WebCrypto failure as its `cause`
- If payload is an object and `typ` is not set, defaults to `"JWT"`. No `cty` is added (RFC 7519 §5.2 keeps it for nested JWTs, as `"JWT"`); a `cty` set in `protectedHeader` is kept as given
- If `expiresIn`/`notBefore*` or `issuedAt` is set and `iat` is missing, `iat` is set to `currentDate` (`issuedAt: Date`: that instant); `exp`/`nbf` from a duration are `currentDate` plus the duration, never `iat` plus
- `b64: false` in header enables unencoded payload ([RFC 7797](https://www.rfc-editor.org/rfc/rfc7797.txt)). `"b64"` is added to `crit` automatically (created when absent, never duplicated) — RFC 7797 §6 requires the flag to be integrity protected, and jose/other verifiers reject the token otherwise
- With `b64: false`, a compact payload containing `"."` throws `ERR_JWS_INVALID` (RFC 7797 §5.2 — it would split the compact serialization). Use the JSON serialization (`signMulti`) for such payloads
- With `b64: false`, payload bytes that are not valid UTF-8 throw `ERR_JWS_INVALID` (`"Invalid JWS: Payload is not valid UTF-8."`) in `sign` and `signMulti` — the unencoded payload travels as text
- A `protectedHeader.typ` that is not a string throws `ERR_INVALID_OPTION` (`'"typ" must be a string.'`)
- When a JWK with a `kid` is used, the `kid` is added to the header as a fallback — an explicit `protectedHeader.kid` always takes precedence

```ts
import { sign, verify } from "unjwt/jws";
import { generateJWK } from "unjwt/jwk";

// Symmetric (HMAC): one key signs and verifies
const hmacKey = await generateJWK("HS256");
const token = await sign({ sub: "user123" }, hmacKey);

// Asymmetric (RSA): a pair is two keys — the private half signs, the public half verifies
const { privateKey, publicKey } = await generateJWK("RS256");
const token2 = await sign({ sub: "user123" }, privateKey);
const { payload } = await verify(token2, publicKey);

// With expiration
const token3 = await sign({ sub: "user123" }, hmacKey, { expiresIn: "1h" });
```

## `verify(jws, key, options?)`

Verifies a JWS token and returns its payload.

**Parameters:**

- `jws` — `string` — the JWS compact token
- `key` — `CryptoKey | JWSVerifyJWK | JWKSet | Uint8Array | JWSKeyLookup`
  - `JWSVerifyJWK` is the public counterpart of `JWSSignJWK` — `JWK_oct<JWK_HMAC>` or a public asymmetric JWK with a signing `alg`. The key is imported with `expect: "public"`, so an asymmetric JWK still carrying `d` throws `ERR_JWK_INVALID` instead of being imported; `sign` mirrors this with `expect: "private"`.
  - `JWKSet` stays fully permissive (`JWK[]`) because JWKS from the wire are heterogeneous; runtime filters candidates per header.
  - `JWSKeyLookup`: `(header: JWSHeaderParameters, token) => key | JWKSet | Promise<key | JWKSet>` for dynamic key resolution; the header's `alg` is already validated
  - `JWKSet`: multi-key selection with automatic retry. A set is public-key material, so an entry is a candidate only when it is a JWK, is not `oct` (unless `allowSymmetricJWKSet`), its `kid` matches the header (or the header carries none), its `alg` matches (or it declares none), its `use` is absent or `"sig"`, and its `key_ops` is absent or contains `verify`
    - Token has `kid` — only keys with that exact `kid` are tried (fast path, typically one key, no retry)
    - Token has no `kid` — every candidate is tried in order; the first to verify successfully wins
    - A candidate that cannot verify — unusable key material as much as a signature mismatch — only means "try the next one"; when none verifies, `ERR_JWS_SIGNATURE_INVALID` carries the per-candidate `JWTError`s (one per tried key, in order) as its `cause`
    - No matching candidates — throws `JWTError("ERR_JWK_KEY_NOT_FOUND")` before any crypto attempt
  - A `JWKLookupFunction` that throws is a key that could not be resolved: the failure surfaces as `ERR_JWK_KEY_NOT_FOUND` with the thrown value as its `cause`. One that returns `undefined` or `null` is `ERR_JWK_KEY_NOT_FOUND` too (`"Key lookup returned no key for the JWS."`)
  - The `kid` named in a key-not-found message is JSON-quoted and cut at 64 characters — it is token input
  - A token that is not a string throws `ERR_JWS_INVALID` (`"Invalid JWS: token must be a string."`)
    - Same retry applies when a `JWKLookupFunction` returns a `JWKSet`

- `options?: JWSVerifyOptions`
  - `algorithms?: JWSAlgorithm[]` — allowlist of accepted algorithms. When omitted, the allowlist is inferred from the key shape via `inferJWSAllowedAlgorithms`; pass explicitly when the key carries no usable metadata (raw `Uint8Array`, alg-less JWKs, lookup functions returning ambiguous shapes). For a JWK Set the allowlist is the union over its entries, skipping the ones it cannot infer
  - `allowSymmetricJWKSet?: boolean` — default `false`. A JWK Set is treated as public-key material: its `oct` entries are ignored, both as candidates and for inference. `true` admits them, and is only appropriate for a set the application itself controls (an HMAC key-rotation set), never for one fetched from a `jwks_uri`
  - `payload?: "json" | "string" | "bytes"` — what the payload is, declared by the caller. Defaults to `"json"`: the payload must be UTF-8 JSON naming a non-null, non-array object, or `ERR_JWS_INVALID` (`"Invalid JWS: Payload is not a JSON object."`). `"string"` returns UTF-8 text (invalid UTF-8 → `ERR_JWS_INVALID`), `"bytes"` returns `Uint8Array<ArrayBuffer>`. The signed content never decides its own shape, and `typ`/`cty` never pick it — both are signer-controlled. Under RFC 7797 `b64: false` the unencoded segment is the content and the same modes apply
  - `validateClaims?: boolean` — `false` skips JWT claim validation. `undefined` (default) and `true` both validate under `payload: "json"`; `true` together with `payload: "string"` / `"bytes"` throws `ERR_INVALID_OPTION` (`'"validateClaims" requires payload: "json".'`) rather than silently not running
  - `limits?: { keyCandidates?: number }` — how many JWK Set candidates one token may be tried against after `kid`/`alg`/`use` filtering. Default `8` (`DEFAULT_JOSE_LIMITS.keyCandidates`); a wider set throws `ERR_JWK_KEY_NOT_FOUND` (`'12 candidate keys exceed the limit of 8, narrow them with a "kid".'`) before the first import. Must be a positive integer, else `ERR_INVALID_OPTION`
  - `allowSymmetricJWKSet`, `payload` and `validateClaims` come from `JOSEConsumerOptions`, the base `JWEDecryptOptions` shares
  - Inherits `JWTClaimValidationOptions`: `audience`, `issuer`, `subject`, `maxTokenAge`, `clockTolerance`, `typ`, `currentDate`, `requiredClaims`, `recognizedHeaders`
  - `audience` — the `aud` claim is checked **only when this option is set**. A token carrying `aud` is accepted by a verifier that configures none; configure `audience` to enforce RFC 7519 §4.1.3
  - Every option is checked before the token is read, and a configured check is never skipped for being empty: `audience: ""` (or a list with an empty entry), `issuer: ""`, `subject: ""`, `typ: ""` or a non-string `typ`, `maxTokenAge: 0`, an `options` that is not an object, `limits` that is not an object, and an `algorithms` / `requiredClaims` / `recognizedHeaders` that is not an array of strings each throw `ERR_INVALID_OPTION` (`'"algorithms" must be an array of strings.'`). An empty list (`audience: []`, `algorithms: []`) is a check no token passes
  - `clockTolerance?: number | Duration` — seconds, or a `Duration` shorthand (`"5m"`, `"1h"`). Negative, non-finite or unparseable values throw `ERR_INVALID_OPTION` instead of silently disabling the `exp`/`nbf`/`iat` checks
  - `exp`/`nbf`/`iat` must be non-negative NumericDates (fractions allowed, RFC 7519 §2); a negative value throws `ERR_JWT_CLAIM_INVALID`

**Returns:** `Promise<JWSVerifyResult<T>>` — `{ payload: T, protectedHeader: JWSProtectedHeader }`

**Return types follow the option.** The payload type is read off `JOSEPayloadTypeMap` by the `payload` literal (`PayloadOf<Mode, T>`):

- no `payload` or `payload: "json"` → `T`, the claims — `JWTClaims` unless given: `verify<MyClaims>(token, key)`
- `payload: "string"` → `string`; `payload: "bytes"` → `Uint8Array<ArrayBuffer>`
- a `payload` that is not a literal (a `JOSEPayloadMode` variable, a `JWSVerifyOptions` object) → the union of what its modes return
- a claims type together with `payload: "string"` / `"bytes"` is a type error

**Header validation (before any key work):**

- The protected header must decode to a JSON **object** — `null`, an array or a JSON scalar throws `ERR_JWS_INVALID` (`"Invalid JWS: Protected header must be a JSON object."`)
- `alg: "none"` is rejected with `ERR_JWS_ALG_NOT_ALLOWED` (`'"none" is not a valid signing algorithm'`), as is any `alg` outside `JWSAlgorithm` (`"Algorithm not supported: <alg>"`) — neither ever reaches WebCrypto. The `options.algorithms` allowlist is checked after that and still reports `"Algorithm not allowed: <alg>"`
- `b64` must be a boolean (`"false"`, `0`, `null` → `ERR_JWS_INVALID`, RFC 7797 §3); `b64: false` is only honoured when `"b64"` is listed in `crit`; otherwise `ERR_JWS_INVALID` (RFC 7797 §6)
- `crit` must be a non-empty array of strings and must not list a parameter registered by RFC 7515/7516/7518 (`alg`, `enc`, `zip`, `jku`, `jwk`, `kid`, `x5u`, `x5c`, `x5t`, `x5t#S256`, `typ`, `cty`, `crit`, `epk`, `apu`, `apv`, `iv`, `tag`, `p2s`, `p2c`); `b64` is an extension and is allowed. `recognizedHeaders` cannot opt back into a registered name. Every entry must name a member the protected header carries — `"b64"` included — else `ERR_JWS_INVALID` (`'Critical header parameter "b64" is missing from the protected header.'`), and one the recipient understands (`b64`, or a name in `recognizedHeaders`), else `ERR_JWS_INVALID` (`"Unprocessed critical header parameters: <name>"`) — the same rule and messages as JWE (RFC 7515 §4.1.11)
- `options.typ` is compared under RFC 7515 §4.1.9 media-type semantics — case-insensitive, with an optional `application/` prefix on either side, so `typ: "at+jwt"` matches a header carrying `"application/AT+JWT"`. A protected header without `typ` fails it with `ERR_JWS_INVALID` (`'Invalid JWS: the protected header carries no "typ", expected "at+jwt".'`)
- Any non-`JWTError` raised while importing or using the key (WebCrypto `TypeError`/`DOMException`, codec `SyntaxError`, …) surfaces as `JWTError('Key is not usable for "<alg>".', "ERR_JWK_INVALID")` with the original as `cause`

```ts
import { verify } from "unjwt/jws";

// With JWK
const { payload, protectedHeader } = await verify(token, hmacKey);

// With key lookup
const result = await verify(token, async (header) => fetchKeyByKid(header.kid), {
  algorithms: ["RS256"],
});

// With claim validation
const result2 = await verify(token, key, {
  issuer: "https://auth.example.com",
  audience: "my-app",
  maxTokenAge: "24h",
});
```

## Multi-signature (JSON Serialization)

`unjwt` exposes `signMulti` / `verifyMulti` for JWS General JSON Serialization (RFC 7515 §7.2.1). Use them whenever you need more than one signer on a single payload — multi-party attestation, quorum approvals, key-rotation overlap, algorithm agility, hybrid signing. For single-signer tokens, compact `sign()`/`verify()` remains the right tool.

### `signMulti(payload, signers, options?)`

Produces a `JWSGeneralSerialization` object. The payload is shared; each signer independently signs `BASE64URL(its own protected header) . BASE64URL(payload)` using its own `alg`.

**Parameters:**

- `payload` — `string | Uint8Array | Record<string, any>`
- `signers: JWSMultiSigner[]` — non-empty. Each signer is `{ key: JWSSignJWK | CryptoKey, alg?, protectedHeader?, unprotectedHeader? }`. The signer's `alg` wins; otherwise it comes from `key.alg` (JWK) or the CryptoKey's own WebCrypto algorithm. An alg-less JWK throws `ERR_JWS_SIGNER_ALG_INFERENCE`. `kid` is copied from a JWK key only — a CryptoKey signer must put `kid` in its `protectedHeader`.
- `options?: JWSMultiSignOptions` — mirrors `JWSSignOptions` minus the per-signer fields (`alg`, `protectedHeader`). Keeps: `currentDate`, `issuedAt`, `expiresIn`, `expiresAt`, `notBeforeIn`, `notBeforeAt`.

Throws `ERR_JWS_B64_INCONSISTENT` when signers disagree on `b64` (RFC 7797 §3 mandates consistency). Throws `ERR_JWS_HEADER_PARAMS_NOT_DISJOINT` when a parameter name appears in both the protected and unprotected header of the same signer. When `b64: false`, each signer's protected header gets `"b64"` appended to its `crit` automatically (RFC 7797 §6).

```ts
import { signMulti } from "unjwt/jws";

const jws = await signMulti(
  { sub: "u1", role: "admin" },
  [
    { key: aliceRsaPrivateJwk }, // alg=RS256 from JWK
    { key: bobEdPrivateJwk, protectedHeader: { typ: "vc+jwt" } }, // alg=Ed25519, custom typ
    { key: witnessHmacJwk, unprotectedHeader: { "x-role": "witness" } },
  ],
  { expiresIn: "1h" },
);
```

### `verifyMulti(jws, keyOrLookup, options?)`

Accepts an already-parsed General or Flattened JWS and returns the first signature that verifies. Parse the JSON yourself before calling — `verifyMulti` does not accept strings. Compact tokens go through `verify()`.

**Parameters:**

- `jws` — `JWSGeneralSerialization | JWSFlattenedSerialization`. Flattened input is auto-normalized to General in memory.
- `keyOrLookup` — same shape as `verify()` (`JWK | JWKSet | CryptoKey | Uint8Array | JWKLookupFunction`). `JWKSet` / lookup functions are consulted per signature until one verifies.
- `options?: JWSMultiVerifyOptions` — extends `JWSVerifyOptions`. Adds:
  - `limits?: { signatures?: number; keyCandidates?: number }` — `signatures` defaults to `16`; a serialization carrying more throws `ERR_JWS_INVALID` (`"Invalid JWS: 17 signatures exceed the limit of 16."`) before any signature is read
  - `strictSignerMatch?: boolean` — when `true`, a signature is attempted only when the key material could have produced it; nothing matching means `ERR_JWS_NO_MATCHING_SIGNER` with no trial verification fallback. A signature is skipped only on a _definite_ mismatch: a different `kid` on both sides, or key material whose `kty` / curve / length cannot serve the signature's `alg`. Key material that carries no identity of its own (a `CryptoKey`, raw bytes) is treated as unknown rather than mismatched — it falls through to the compatibility check instead of being filtered out. For a single JWK or `CryptoKey`, `kid` never rules the key out; for a JWK Set the header `kid` selects the candidates (an entry with another `kid`, or none, is not one): no candidate is `ERR_JWK_KEY_NOT_FOUND`, candidates that all fail the compatibility check skip the signature.

**Returns:** `JWSMultiVerifyResult<T>` — `{ payload, protectedHeader, signerIndex, signerHeader? }`. The payload type follows `options.payload` exactly as for `verify` (`PayloadOf<Mode>`; `verifyMulti<MyClaims>(jws, key)` for the claims):

- `protectedHeader: JWSHeaderParameters` — exactly what was signed. `alg` appears here only when protected; a Flattened JWS with no `protected` member yields `{}`.
- `signerIndex: number` — index into `jws.signatures` that verified.
- `signerHeader?: JWSHeaderParameters` — per-signer unprotected header (holds `alg` when the signer did not protect it).

**Header tiers (RFC 7515 §7.2.1):** `alg` may sit in the protected header or in the signature's unprotected `header` — and a Flattened JWS may omit `protected` entirely. The `algorithms` allowlist, key-based inference and every key/`alg` check apply to an unprotected `alg` exactly as to a protected one. `crit` and `b64` must be protected (either one in a signature's unprotected `header` fails that signature with `ERR_JWS_INVALID`), and a name may sit in only one tier (`ERR_JWS_HEADER_PARAMS_NOT_DISJOINT`). `options.typ` is matched against the protected header only — a `typ` carried unprotected never satisfies it, since a type gate an attacker could move would gate nothing. `kid` is read from the merged header, so the key lookup may be steered by the unprotected tier; that is why the signature must still verify under the key the lookup returns.

**Per-signature isolation:** every signature-scoped failure — a `signatures[]` entry that is not a JSON object (or whose `header` is not one, or whose `protected` is not a string), malformed protected header, `alg: "none"` / unsupported `alg`, `b64` without `crit`, protected/unprotected overlap, a signature segment that is not canonical base64url, an unusable key — is recorded and the next signature is still tried; the collected error is thrown only when no signature verifies. A malformed signer prepended to a token therefore cannot suppress a valid one. `crit` or `b64` in an **unprotected** header fails that signature with `ERR_JWS_INVALID` (RFC 7515 §4.1.11, RFC 7797 §3 — both must be integrity protected). A document carrying `signatures[]` together with a top-level `signature`/`protected` is ambiguous and throws `ERR_JWS_INVALID_SERIALIZATION`.

```ts
import { verifyMulti } from "unjwt/jws";

const { payload, signerIndex, signerHeader } = await verifyMulti(jws, alicePublicJwk);

// Or via JWKSet / lookup function
const { payload: p } = await verifyMulti(jws, myJwkSet);
const { payload: q } = await verifyMulti(jws, (header) => fetchKeyByKid(header.kid));

// Strict — fail fast when no signature matches
const { payload: r } = await verifyMulti(jws, key, { strictSignerMatch: true });
```

### `verifyMultiAll(jws, keyResolver, options?)`

Verify every signature in a JWS **independently** and return a per-signature outcome array — the caller applies their own policy (all-must-verify, M-of-N quorum, specific-signer checks, audit logs).

Unlike `verifyMulti`, this function **never throws** on an individual signature's failure. A `signatures[]` entry that is not a JSON object, malformed protected headers (including non-object headers), `alg: "none"` / unsupported or disallowed `alg`s, a non-boolean `b64`, `b64` without `crit`, `crit` or `b64` in an unprotected header, protected/unprotected overlap, malformed signature segments, `typ` mismatches, key-resolver errors, unusable keys, bad signatures, critical-header violations, and JWT-claim failures are all collected into `JWSMultiVerifyOutcome` entries with `verified: false`.

Structural errors in the envelope itself (non-object input, missing `payload` / `signatures[]`) still throw `ERR_JWS_INVALID_SERIALIZATION` — there's no per-signature outcome to return in that case.

**Parameters:**

- `jws` — `JWSGeneralSerialization | JWSFlattenedSerialization` (Flattened is auto-normalised).
- `keyResolver` — **required** `JWKLookupFunction`. Per-signature keys are typically different, so the function form is mandatory. Wrap a static `JWKSet` as `(header) => mySet` if that's all you have.
- `options?: JWSMultiVerifyAllOptions` — inherits `JWSMultiVerifyOptions` minus `strictSignerMatch` (not meaningful when every signature is independently reported). Keeps `algorithms`, `limits`, `typ`, `payload`, `validateClaims`, `recognizedHeaders`, and all `JWTClaimValidationOptions`. A `string` key from the resolver is reported as that signature's `ERR_JWK_INVALID` outcome rather than thrown. The `signatures` limit is the exception to the never-throws rule: a token carrying more signatures than the cap throws `ERR_JWS_INVALID`, since there is no per-signature outcome to report for signatures that are never looked at.

**Returns:** `Promise<JWSMultiVerifyOutcome<T>[]>` — one entry per signature; a verified outcome's `payload` follows `options.payload` exactly as for `verify` (`PayloadOf<Mode>`). Each is a discriminated union:

- `{ signerIndex, verified: true, payload, protectedHeader, signerHeader? }` — verified cryptographically, `typ` matched (if required), JWT claims passed (if enabled).
- `{ signerIndex, verified: false, error, protectedHeader?, signerHeader? }` — failure at some step. `protectedHeader` / `signerHeader` are populated when they were successfully parsed before failure; they're missing when the signature was structurally malformed.

```ts
import { verifyMultiAll } from "unjwt/jws";

// All signatures must verify
const outcomes = await verifyMultiAll(jws, myKeyResolver);
if (!outcomes.every((o) => o.verified)) {
  throw new Error("not all signatures verified");
}

// M-of-N quorum by distinct kid
const validKids = outcomes.filter((o) => o.verified).map((o) => o.protectedHeader.kid);
if (new Set(validKids).size < 2) {
  throw new Error("quorum of 2 not met");
}

// Specific required signers
const signedBy = new Set(outcomes.filter((o) => o.verified).map((o) => o.protectedHeader.kid));
if (!signedBy.has("alice") || !signedBy.has("notary")) {
  throw new Error("missing required signers");
}

// Audit log — record every outcome regardless of overall policy
for (const o of outcomes) {
  log(o.signerIndex, o.verified ? "ok" : o.error.code);
}
```

### `generalToFlattenedJWS(jws)`

`signMulti` always emits General, even for a single signer — keeps the return shape stable if you later add signers. For strict Flattened-only consumers, post-process:

```ts
import { signMulti, generalToFlattenedJWS } from "unjwt/jws";

const general = await signMulti(payload, [signer], opts);
const flattened = generalToFlattenedJWS(general); // JWSFlattenedSerialization
```

Throws `ERR_JWS_INVALID_SERIALIZATION` when the input has zero or multiple signatures.

### Differences from JWE's multi-recipient model

JWS JSON Serialization is structurally simpler than JWE's:

- **Payload is shared, protected header is per-signer.** Opposite of JWE, where the protected header is shared and the per-recipient state is in `recipients[]`.
- **No shared unprotected header at the top level** — only per-signature `header` fields (RFC 7515 §7.2.1).
- **RFC 7797 `b64: false` constraint** — all signers must agree on `b64`; inconsistency throws `ERR_JWS_B64_INCONSISTENT`.

## Errors

Every JOSE operation in this module throws `JWTError` — a single `instanceof` is enough. When the root cause is one of the bundled [`unsecure`](https://github.com/sandros94/unsecure) primitives (base64url codec, JSON parse), it is preserved as `cause`:

```ts
import { verify, isJWTError, isUnsecureError } from "unjwt/jws";

const error = await verify(token, key).catch((e) => e);
if (isJWTError(error, "ERR_JWS_INVALID") && isUnsecureError(error.cause, "MALFORMED")) {
  // a segment of the wire format is not canonical base64url
}
```

`unsecure` is inlined into unjwt's dist, so `instanceof` against a consumer-installed `unsecure` never matches. Use the `UnsecureError` / `isUnsecureError` that unjwt re-exports. The `unjwt/utils` primitives themselves still throw `UnsecureError` directly — only the JOSE operations wrap.

Error codes come in two types: `KnownJWTErrorCode` (the closed literal union of every code the library throws) and `JWTErrorCode = KnownJWTErrorCode | (string & {})` (forward-compatible, what `JWTError["code"]` is typed as). `isJWTError`'s `code` parameter takes `KnownJWTErrorCode`, so a typo such as `isJWTError(e, "ERR_JWS_INVALD")` is a compile error rather than a check that never matches.

## Types

```ts
// Narrow key-type aliases enforced at the sign/verify boundary. Each one combines:
// - the symmetric branch with the signing alg family, and
// - asymmetric branches whose `_Public` / `_Private` interfaces restrict `alg` to
//   their respective signing family (RSA sign, ECDSA, Ed*).
type JWSAsymmetricPrivateJWK =
  | JWK_RSA_Private<JWK_RSA_SIGN | JWK_RSA_PSS>
  | JWK_EC_Private<JWK_ECDSA>
  | JWK_OKP_Private<JWK_OKP_SIGN>;
type JWSAsymmetricPublicJWK =
  | JWK_RSA_Public<JWK_RSA_SIGN | JWK_RSA_PSS>
  | JWK_EC_Public<JWK_ECDSA>
  | JWK_OKP_Public<JWK_OKP_SIGN>;
type JWSSignJWK = JWK_oct<JWK_HMAC> | JWSAsymmetricPrivateJWK;
type JWSVerifyJWK = JWK_oct<JWK_HMAC> | JWSAsymmetricPublicJWK;

type JOSEPayload = string | Uint8Array<ArrayBuffer> | object;

// Bounded work per call. Each operation exposes the subset that applies to it;
// `DEFAULT_JOSE_LIMITS` (exported from `unjwt`, `unjwt/jws` and `unjwt/jwe`)
// carries the defaults below. Every value must be a positive integer.
interface JOSELimits {
  signatures?: number; // JWS `signatures[]` entries — default 16
  recipients?: number; // JWE `recipients[]` entries — default 16
  keyCandidates?: number; // JWK Set candidates per token — default 8
  pbes2Iterations?: number; // PBKDF2 iterations per call — default 2_400_000
}

type ExpiresIn = Duration;

type Duration =
  | number
  | `${number}`
  | `${number}${"s" | "second" | "seconds" | "m" | "minute" | "minutes" | "h" | "hour" | "hours" | "D" | "day" | "days" | "W" | "week" | "weeks" | "M" | "month" | "months" | "Y" | "year" | "years"}`;

interface JWSHeaderParameters {
  alg?: JWSAlgorithm;
  b64?: boolean; // RFC 7797 unencoded payload
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
}

interface JWSProtectedHeader {
  alg: JWSAlgorithm;
  b64?: boolean;
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
}

interface JWSSignOptions {
  alg?: JWSAlgorithm;
  protectedHeader?: {
    alg?: never;
    b64?: boolean;
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
  currentDate?: Date;
  issuedAt?: boolean | Date;
  expiresIn?: ExpiresIn;
  expiresAt?: Date;
  notBeforeIn?: ExpiresIn;
  notBeforeAt?: Date;
}

// The payload each mode returns; `PayloadOf<Mode, T>` reads one entry (a union of
// modes yields the union of payloads). Also exported from unjwt/jwe and the root.
interface JOSEPayloadTypeMap<T = JWTClaims> {
  json: T;
  string: string;
  bytes: Uint8Array<ArrayBuffer>;
}
type JOSEPayloadMode = keyof JOSEPayloadTypeMap; // "json" | "string" | "bytes"
type PayloadOf<Mode extends JOSEPayloadMode, T = JWTClaims> = JOSEPayloadTypeMap<T>[Mode];

// `Mode` is the `payload` literal verify reads its return type from.
interface JWSVerifyOptions<Mode extends JOSEPayloadMode = JOSEPayloadMode> {
  algorithms?: JWSAlgorithm[];
  allowSymmetricJWKSet?: boolean;
  limits?: Pick<JOSELimits, "keyCandidates">;
  payload?: Mode;
  validateClaims?: boolean;
  audience?: string | string[];
  issuer?: string | string[];
  subject?: string;
  maxTokenAge?: Duration;
  clockTolerance?: number | Duration;
  typ?: string;
  currentDate?: Date;
  requiredClaims?: string[];
  recognizedHeaders?: string[];
}

interface JWSVerifyResult<T extends JOSEPayload = JOSEPayload> {
  payload: T;
  protectedHeader: JWSProtectedHeader;
}

// --- Multi-signature (RFC 7515 §7.2) ---

interface JWSFlattenedSerialization {
  payload: string;
  protected?: string;
  header?: JWSHeaderParameters;
  signature: string;
}

interface JWSGeneralSignature {
  protected?: string;
  header?: JWSHeaderParameters;
  signature: string;
}

interface JWSGeneralSerialization {
  payload: string;
  signatures: JWSGeneralSignature[];
}

interface JWSMultiSigner {
  key: JWSSignJWK | CryptoKey;
  alg?: JWSAlgorithm; // optional; inferred from key.alg (JWK) or the CryptoKey itself
  protectedHeader?: {
    alg?: never;
    b64?: boolean;
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
  unprotectedHeader?: JWSHeaderParameters;
}

interface JWSMultiSignOptions {
  currentDate?: Date;
  issuedAt?: boolean | Date;
  expiresIn?: ExpiresIn;
  expiresAt?: Date;
  notBeforeIn?: ExpiresIn;
  notBeforeAt?: Date;
}

interface JWSMultiVerifyOptions<Mode extends JOSEPayloadMode = JOSEPayloadMode> {
  algorithms?: JWSAlgorithm[];
  allowSymmetricJWKSet?: boolean;
  limits?: Pick<JOSELimits, "signatures" | "keyCandidates">;
  payload?: Mode;
  validateClaims?: boolean;
  audience?: string | string[];
  issuer?: string | string[];
  subject?: string;
  maxTokenAge?: Duration;
  clockTolerance?: number | Duration;
  typ?: string;
  currentDate?: Date;
  requiredClaims?: string[];
  recognizedHeaders?: string[];
  strictSignerMatch?: boolean;
}

interface JWSMultiVerifyAllOptions<Mode extends JOSEPayloadMode = JOSEPayloadMode> {
  algorithms?: JWSAlgorithm[];
  allowSymmetricJWKSet?: boolean;
  limits?: Pick<JOSELimits, "signatures" | "keyCandidates">;
  payload?: Mode;
  validateClaims?: boolean;
  audience?: string | string[];
  issuer?: string | string[];
  subject?: string;
  maxTokenAge?: Duration;
  clockTolerance?: number | Duration;
  typ?: string;
  currentDate?: Date;
  requiredClaims?: string[];
  recognizedHeaders?: string[];
}

interface JWSMultiVerifyResult<T extends JOSEPayload = JOSEPayload> {
  payload: T;
  protectedHeader: JWSHeaderParameters; // only what was signed — alg may be in signerHeader
  signerIndex: number;
  signerHeader?: JWSHeaderParameters;
}

type JWSMultiVerifyOutcome<T extends JOSEPayload = JOSEPayload> =
  | {
      signerIndex: number;
      verified: true;
      payload: T;
      protectedHeader: JWSHeaderParameters;
      signerHeader?: JWSHeaderParameters;
    }
  | {
      signerIndex: number;
      verified: false;
      error: JWTError;
      protectedHeader?: JWSHeaderParameters;
      signerHeader?: JWSHeaderParameters;
    };

// JWSKeyLookup = JWKLookupFunction<TReturn, JWSHeaderParameters> — from unjwt/jws or unjwt.
// The header is the decoded protected header after the alg check, so `alg` is a `JWSAlgorithm`.
type JWSKeyLookup<TReturn = CryptoKey | JWK | JWKSet | string | Uint8Array<ArrayBuffer>> = (
  header: JWSHeaderParameters,
  token: string,
) => TReturn | undefined | null | Promise<TReturn | undefined | null>;
```
