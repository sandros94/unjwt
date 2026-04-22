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

## `sign(payload, key, options?)`

Creates a JWS Compact Serialization token.

**Parameters:**

- `payload` — `JOSEPayload` = `string | Uint8Array | Record<string, unknown>` (objects are JSON-serialized)
- `key` — `CryptoKey | JWSSignJWK | Uint8Array`
  - `JWSSignJWK` narrows by family: `JWK_oct<JWK_HMAC>` | asymmetric private JWK with a signing `alg`.
    A JWK whose `alg` points at a non-signing family (`"RSA-OAEP"`, `"A256KW"`, …) is rejected at the type level.
  - JWK keys infer `alg` automatically; CryptoKey/Uint8Array require `options.alg`
- `options?: JWSSignOptions`
  - `alg?: JWSAlgorithm` — required when key is CryptoKey or Uint8Array
  - `protectedHeader?: JWSHeaderParameters` — additional header params (`kid`, `typ`, `cty`, `crit`, `b64`)
  - `expiresIn?: ExpiresIn` — sets `exp` claim relative to `iat` (number in seconds, or string like `"1h"`, `"7D"`)
  - `currentDate?: Date` — override current time for `iat`/`exp` computation

**Returns:** `Promise<string>` — JWS compact token

**Behavior:**

- If payload is an object and `typ` is not set, defaults to `"JWT"`
- If `expiresIn` is set and `iat` is missing, `iat` is set to current time
- `b64: false` in header enables unencoded payload ([RFC 7797](https://www.rfc-editor.org/rfc/rfc7797.txt))
- When a JWK with a `kid` is used, the `kid` is added to the header as a fallback — an explicit `protectedHeader.kid` always takes precedence

```ts
import { sign } from "unjwt/jws";
import { generateJWK } from "unjwt/jwk";

// Symmetric (HMAC)
const hmacKey = await generateJWK("HS256");
const token = await sign({ sub: "user123" }, hmacKey);

// Asymmetric (RSA)
const rsaKeys = await generateJWK("RS256");
const token2 = await sign({ sub: "user123" }, rsaKeys.privateKey);

// With expiration
const token3 = await sign({ sub: "user123" }, hmacKey, { expiresIn: "1h" });
```

## `verify(jws, key, options?)`

Verifies a JWS token and returns its payload.

**Parameters:**

- `jws` — `string` — the JWS compact token
- `key` — `CryptoKey | JWSVerifyJWK | JWKSet | Uint8Array | JWKLookupFunction`
  - `JWSVerifyJWK` is the public counterpart of `JWSSignJWK` — `JWK_oct<JWK_HMAC>` or a public asymmetric JWK with a signing `alg`.
  - `JWKSet` stays fully permissive (`JWK[]`) because JWKS from the wire are heterogeneous; runtime filters candidates per header.
  - `JWKLookupFunction`: `(header, token) => key | JWKSet | Promise<key | JWKSet>` for dynamic key resolution
  - `JWKSet`: multi-key selection with automatic retry
    - Token has `kid` — only keys with that exact `kid` are tried (fast path, typically one key, no retry)
    - Token has no `kid` — all keys whose `alg` field is compatible are tried in order; the first to verify successfully wins
    - No matching candidates — throws `JWTError("ERR_JWK_KEY_NOT_FOUND")` before any crypto attempt
    - Same retry applies when a `JWKLookupFunction` returns a `JWKSet`

- `options?: JWSVerifyOptions`
  - `algorithms?: JWSAlgorithm[]` — allowlist of accepted algorithms. When omitted, the allowlist is inferred from the key shape via `inferJWSAllowedAlgorithms`; pass explicitly when the key carries no usable metadata (raw `Uint8Array`, alg-less JWKs, lookup functions returning ambiguous shapes)
  - `validateClaims?: boolean` — `false` explicitly skips JWT claim validation. Defaults to `undefined`, which validates whenever the decoded payload is a JSON object — **independent of the `typ` header**, because `typ` is signer-controlled and cannot gate security-critical checks
  - `forceUint8Array?: boolean` — force payload returned as `Uint8Array`
  - Inherits `JWTClaimValidationOptions`: `audience`, `issuer`, `subject`, `maxTokenAge`, `clockTolerance`, `typ`, `currentDate`, `requiredClaims`, `recognizedHeaders`

**Returns:** `Promise<JWSVerifyResult<T>>` — `{ payload: T, protectedHeader: JWSProtectedHeader }`

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
- `signers: JWSMultiSigner[]` — non-empty. Each signer is `{ key: JWSSignJWK, protectedHeader?, unprotectedHeader? }`. `key.alg` is required (throws `ERR_JWS_SIGNER_ALG_INFERENCE` when absent).
- `options?: JWSMultiSignOptions` — mirrors `JWSSignOptions` minus the per-signer fields (`alg`, `protectedHeader`). Keeps: `currentDate`, `expiresIn`, `expiresAt`, `notBeforeIn`, `notBeforeAt`.

Throws `ERR_JWS_B64_INCONSISTENT` when signers disagree on `b64` (RFC 7797 §3 mandates consistency). Throws `ERR_JWS_HEADER_PARAMS_NOT_DISJOINT` when a parameter name appears in both the protected and unprotected header of the same signer.

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
  - `strictSignerMatch?: boolean` — when `true`, skip any signature whose header does not unambiguously match the provided key (by `kid`, then by `kty`/`crv`/length). Throws `ERR_JWS_NO_MATCHING_SIGNER` if nothing matches; no trial verification fallback.

**Returns:** `JWSMultiVerifyResult<T>` — extends `JWSVerifyResult` with:

- `signerIndex: number` — index into `jws.signatures` that verified.
- `signerHeader?: JWSHeaderParameters` — per-signer unprotected header.

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

Unlike `verifyMulti`, this function **never throws** on an individual signature's failure. Malformed protected headers, disallowed `alg`s, `typ` mismatches, key-resolver errors, bad signatures, critical-header violations, and JWT-claim failures are all collected into `JWSMultiVerifyOutcome` entries with `verified: false`.

Structural errors in the envelope itself (non-object input, missing `payload` / `signatures[]`) still throw `ERR_JWS_INVALID_SERIALIZATION` — there's no per-signature outcome to return in that case.

**Parameters:**

- `jws` — `JWSGeneralSerialization | JWSFlattenedSerialization` (Flattened is auto-normalised).
- `keyResolver` — **required** `JWKLookupFunction`. Per-signature keys are typically different, so the function form is mandatory. Wrap a static `JWKSet` as `(header) => mySet` if that's all you have.
- `options?: JWSMultiVerifyAllOptions` — inherits `JWSMultiVerifyOptions` minus `strictSignerMatch` (not meaningful when every signature is independently reported). Keeps `algorithms`, `typ`, `forceUint8Array`, `validateClaims`, `recognizedHeaders`, and all `JWTClaimValidationOptions`.

**Returns:** `Promise<JWSMultiVerifyOutcome<T>[]>` — one entry per signature. Each is a discriminated union:

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

type JOSEPayload = string | Uint8Array<ArrayBuffer> | Record<string, unknown>;

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
  expiresIn?: ExpiresIn;
  expiresAt?: Date;
  notBeforeIn?: ExpiresIn;
  notBeforeAt?: Date;
}

interface JWSVerifyOptions {
  algorithms?: JWSAlgorithm[];
  forceUint8Array?: boolean;
  validateClaims?: boolean;
  audience?: string | string[];
  issuer?: string | string[];
  subject?: string;
  maxTokenAge?: Duration;
  clockTolerance?: number;
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
  key: JWSSignJWK;
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
  expiresIn?: ExpiresIn;
  expiresAt?: Date;
  notBeforeIn?: ExpiresIn;
  notBeforeAt?: Date;
}

interface JWSMultiVerifyOptions {
  algorithms?: JWSAlgorithm[];
  forceUint8Array?: boolean;
  validateClaims?: boolean;
  audience?: string | string[];
  issuer?: string | string[];
  subject?: string;
  maxTokenAge?: Duration;
  clockTolerance?: number;
  typ?: string;
  currentDate?: Date;
  requiredClaims?: string[];
  recognizedHeaders?: string[];
  strictSignerMatch?: boolean;
}

interface JWSMultiVerifyAllOptions {
  algorithms?: JWSAlgorithm[];
  forceUint8Array?: boolean;
  validateClaims?: boolean;
  audience?: string | string[];
  issuer?: string | string[];
  subject?: string;
  maxTokenAge?: Duration;
  clockTolerance?: number;
  typ?: string;
  currentDate?: Date;
  requiredClaims?: string[];
  recognizedHeaders?: string[];
}

interface JWSMultiVerifyResult<T extends JOSEPayload = JOSEPayload> {
  payload: T;
  protectedHeader: JWSProtectedHeader;
  signerIndex: number;
  signerHeader?: JWSHeaderParameters;
}

type JWSMultiVerifyOutcome<T extends JOSEPayload = JOSEPayload> =
  | {
      signerIndex: number;
      verified: true;
      payload: T;
      protectedHeader: JWSProtectedHeader;
      signerHeader?: JWSHeaderParameters;
    }
  | {
      signerIndex: number;
      verified: false;
      error: JWTError;
      protectedHeader?: JWSProtectedHeader;
      signerHeader?: JWSHeaderParameters;
    };

// JWKLookupFunction is shared with JWE decrypt — imported from unjwt/jwk or unjwt
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
