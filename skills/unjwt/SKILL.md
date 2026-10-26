---
name: unjwt
description: "Expert knowledge for working with unjwt — a low-level, zero-dep, JWT library using the Web Crypto API. Use this skill whenever the user is working with JWS, JWE, JWK, or JWT utilities, including signing, verifying, encrypting, decrypting, key management, and session handling. Trigger on any mention of unjwt or related JWT operations."
metadata:
  version: 0.1.0
  library: unjwt
  library-version: 0.8.0
  org: sandros94
  documentation: https://github.com/sandros94/unjwt
---

# unjwt Skill

Low-level JWT library using the Web Crypto API. Zero runtime dependencies for core; optional peer deps for framework adapters.

Implements JWS (RFC 7515), JWE (RFC 7516), and JWK (RFC 7517).

## Quick orientation

> **Skill written against `unjwt@0.8.0`.** APIs are stable within v0.8 but check the [changelog](https://github.com/sandros94/unjwt/releases) if behaviour seems off on a newer version.

The following is a list of reference files:

- `references/jws.md`: `sign()`, `verify()`, `signMulti()`, `verifyMulti()`, `verifyMultiAll()`, `generalToFlattenedJWS()`, `JWSSignOptions`, `JWSVerifyOptions`, `JWSMultiSignOptions`, `JWSMultiVerifyOptions`, `JWSMultiVerifyAllOptions`, `JWSMultiVerifyOutcome`, `JWSGeneralSerialization`, `JWSFlattenedSerialization`, `JWSMultiSigner`
- `references/dpop.md`: `unjwt/dpop`, `createDPoPProof()`, `verifyDPoPProof()`, explicit key pairs and proof fields, token binding, nonce expectations and optional replay callback
- `references/jwe.md`: `encrypt()`, `decrypt()`, `encryptMulti()`, `decryptMulti()`, `generalToFlattened()`, `JWEEncryptOptions`, `JWEDecryptOptions`, `JWEMultiEncryptOptions`, `JWEMultiDecryptOptions`, `JWEGeneralSerialization`, `JWEFlattenedSerialization`, `JWEMultiRecipient`
- `references/jwk.md`: `generateKey()`, `generateJWK()`, `toPublicJWK()`, `thumbprint()`, `importKey()`, `exportJWK()`, `wrapKey()`, `unwrapKey()`, `deriveSharedSecret()`, PEM import/export (`importPEM`, `exportPEM`), PBES2 key derivation (`deriveKeyFromPassword`, `deriveJWKFromPassword`), JWK set utilities (`getJWKsFromSet`), JWK cache (`configureJWKCache`, `clearJWKCache`, `WeakMapJWKCache`), key lookup types (`JWKLookupFunction`, `JWKLookupFunctionHeader`), all JWK type definitions
- `references/utils.md`: `base64UrlStringify`/`base64UrlParse`, `base64Stringify`/`base64Parse`, `secureRandomBytes`, `digestUrl`, `concatUint8Arrays`, `textEncoder`/`textDecoder`, type guards (`isJWK`, `isJWKSet`, `isSymmetricJWK`, `isAsymmetricJWK`, `isPrivateJWK`, `isPublicJWK`, `isCryptoKey`, `isCryptoKeyPair`, `assertCryptoKey`), `validateJwtClaims`, `inferJWSAllowedAlgorithms`, `inferJWEAllowedAlgorithms`, `computeDurationInSeconds`, `Duration` format (aliased by `ExpiresIn` / `NotBeforeIn` / `MaxTokenAge`), `JWTClaimValidationOptions`
- `references/session.md`: `unjwt/session` Web standard sessions, `defineJWSSession`/`defineJWESession` over a `WebSessionEvent`: a request event `SessionRequestEvent` (`{ req, res, context }` for h3 / `nuxt/server`, `{ headers, res, context }` for a `Request` or a crossws upgrade request; read-only without `res`) or a handed token `SessionHandedToken` (`{ token }`, re-mint onto `manager.token`); hooks receive `{ event }`, `Set-Cookie` replace on `Headers`, rules for `use()`, the driver contract (`SessionDriver`, `CookieJar`, `defineSessionDriver`, `{ driver }` option, `handed`), a SvelteKit driver, frameworks (h3 `errHeaders` hook, Nitro 3 imports, Nuxt `nuxt/server` handlers, WebSocket upgrade)
- `references/adapters-elysia.md`: Elysia session adapter, `jwsSession`/`jweSession` plugins, ambient `ctx[contextKey]`, `requireSession` guard macro (derived per `contextKey`), multiple sessions (access JWS + refresh JWE), `defineJWSSession`/`defineJWESession` (`use`, `token`, `issue`, `open`, `plugin()`), `SessionDefinition`/`SessionPluginDefinition`, `SessionConfigJWS`/`SessionConfigJWE`, lifecycle hooks (`context` not `event`), cookie chunking, header tokens, `isolatedDeclarations` plugin typing

## Export Paths

| Path | Purpose |
| --- | --- |
| `unjwt` | Flat barrel: all public functions and types from `jws`, `jwe`, `jwk`, `utils` |
| `unjwt/jws` | `sign()`, `verify()` (Compact) — `signMulti()`, `verifyMulti()` (General JSON Serialization) |
| `unjwt/jwe` | `encrypt()`, `decrypt()` (Compact) — `encryptMulti()`, `decryptMulti()` (General JSON Serialization) |
| `unjwt/jwk` | Key generation, import/export, wrap/unwrap, PEM conversion, PBES2, cache utils |
| `unjwt/utils` | Base64URL encode/decode, type guards, JWT claim validation, `secureRandomBytes`, `digestUrl` |
| `unjwt/dpop` | Optional DPoP proof creation and verification; no HTTP or storage |
| `unjwt/error` | `JWTError`/`isJWTError`, `UnsecureError`/`isUnsecureError` and the error code types |
| `unjwt/internal` | JOSE plumbing for tests and tooling — internal, no semver guarantee, not for production use |
| `unjwt/adapters/elysia` | Elysia session adapter — `jwsSession`/`jweSession` plugins, `defineJWSSession`/`defineJWESession` (`^1.4.29`) |
| `unjwt/session` | Web standard sessions (`{ req, res, context }` event as h3 / `nuxt/server` hand it, a `Request`, or a token in hand) and the driver API — no peer dependency |

Session entry exports (as each `index.ts` exports them):

- `unjwt/adapters/elysia`: `jwsSession`, `jweSession`, `defineJWSSession`, `defineJWESession`; types `SessionDefinition`, `SessionManager`, `SessionClaims`, `SessionData`, `SessionUpdate`, `SessionUpdateTrigger`, `SessionIssueOptions`, `SessionConfigJWS`, `SessionConfigJWE`, `SessionHooksJWS`, `SessionHooksJWE`, `SessionJWS`, `SessionJWE`, `SessionSignOptions`, `SessionVerifyOptions`, `SessionEncryptOptions`, `SessionDecryptOptions`, plus `SessionContext`, `SessionPlugin`, `SessionPluginDefinition`, `CookieAttributes`, `ChunkableCookie`, `ChunkableCookieJar`, `WriteChunkedCookieOptions`
- `unjwt/session`: `defineJWSSession`, `defineJWESession`, `defineSessionDriver`; the same session types plus `WebSessionEvent`, `SessionRequestEvent`, `SessionHandedToken`, `SessionDriver`, `CookieJar`, `CookieAttributes`
- Every session entry also re-exports `generateJWK`, `toPublicJWK`, `thumbprint`, `importPEM`, `exportPEM`, `deriveJWKFromPassword` and every core type

## Quick Start

```ts
// Sign and verify (JWS)
import { sign, verify } from "unjwt/jws";
import { generateJWK } from "unjwt/jwk";

const key = await generateJWK("HS256");
const token = await sign({ sub: "user123" }, key, { expiresIn: "1h" });
const { payload } = await verify(token, key);

// Asymmetric: a pair is two keys — the private half signs, the public half verifies
const { privateKey, publicKey } = await generateJWK("ES256");
const signed = await sign({ sub: "user123" }, privateKey, { expiresIn: "1h" });
const verified = await verify(signed, publicKey);

// Encrypt and decrypt (JWE)
import { encrypt, decrypt } from "unjwt/jwe";

const jwe = await encrypt({ secret: "data" }, "password");
const { payload } = await decrypt(jwe, "password");

// Session (h3, Nitro 3, Nuxt `nuxt/server`, or a Web `Request`)
import { defineJWESession, generateJWK } from "unjwt/session";

const sessionKey = await generateJWK("A256GCM");
const useSession = defineJWESession({ key: sessionKey, maxAge: "7D" }); // once, at module scope
const session = await useSession.use(event); // per request
await session.update({ userId: "123" });
const link = await useSession.issue({ email: "a@example.com" }, { maxAge: "15m" }); // no request
```

## Key Concepts

- **`JOSEPayload`**: the payload type accepted by `sign`/`encrypt` — `string | Uint8Array | object`; covers both JWT and generic serializable objects. `JWTClaims` remains the spec-compliant sub-type for typed claim access
- **JWK-first key model**: functions accept JWK objects directly; `importKey()` normalizes CryptoKey/JWK/Uint8Array
- **A pair is two keys**: `generateJWK()`/`generateKey()` return `{ privateKey, publicKey }` for every asymmetric algorithm (Web Crypto only generates pairs). Sign and decrypt with `privateKey`; verify, encrypt and publish `publicKey` — `verify`/`encrypt` refuse a JWK carrying `d`. Keep and store both halves; prefer not to derive one from the other. `toPublicJWK(privateJWK)` is the advanced path. A JWE session key is symmetric (an `oct` JWK, a secret `CryptoKey`, or a `{ current, keys }` rotation set): an asymmetric key throws `ERR_SESSION_KEY_INVALID`, since a pair seals with its public half and anyone holding it could mint a session the server accepts — use `defineJWSSession` for a key pair
- **Strings are not keys**: `importKey` and every JWS entry point reject a `string` with `ERR_JWK_INVALID` (`"Key must be a JWK, CryptoKey or Uint8Array, not a string."`). JWE is the sole exception, and only as a PBES2 password — under any other `alg` it is rejected too
- **Payload typing is declared, not sniffed**: `verify`/`verifyMulti`/`verifyMultiAll`/`decrypt`/`decryptMulti` take `payload: "json" | "string" | "bytes"` (default `"json"` — must parse to a non-null, non-array object, and claims are validated). `typ`/`cty` never pick the shape. `validateClaims: true` outside `"json"` is `ERR_INVALID_OPTION`
- **Algorithm inference**: `sign`/`encrypt` infer `alg`/`enc` from JWK properties when not explicitly provided; password strings default to PBES2
- **`dir` (direct encryption)**: pass a `CryptoKey | JWK_oct | Uint8Array` directly as the CEK; `enc` must always be specified
- **Multi-recipient JWE**: `encryptMulti()` emits General JSON Serialization (RFC 7516 §7.2.1). One shared CEK, one ciphertext, per-recipient wraps. `dir` and bare `ECDH-ES` are rejected in multi (throw `ERR_JWE_ALG_FORBIDDEN_IN_MULTI`). `decryptMulti()` accepts General + Flattened (auto-normalized); compact tokens stay with `decrypt()`
- **Multi-signature JWS**: `signMulti()` emits General JSON Serialization (RFC 7515 §7.2.1). Shared payload, per-signer protected header. `b64: false` (RFC 7797) must be consistent across all signers. `verifyMulti()` returns the first valid signature; `verifyMultiAll()` returns per-signer outcomes for policy-driven verification (all-must-verify, M-of-N quorum, named signers). Both accept General + Flattened (auto-normalized); compact tokens stay with `verify()`
- **ExpiresIn**: time durations accept numbers (seconds) or strings: `"30s"`, `"10m"`, `"2h"`, `"7D"`, `"1W"`, `"3M"`, `"1Y"` (also long forms: `"minutes"`, `"hours"`, `"days"`, `"weeks"`, `"months"`, `"years"`)
- **Session Adapters**: `defineJWSSession(config)` / `defineJWESession(config)` define a session once and throw there for a config they cannot use (key shape, name, cookie prefix, `sessionHeader`, `rolling`; key import waits for the first `use()`/`issue()`/`open()`); `.use(event | context)` returns the per-request manager, `.token()` the raw token, `.issue(data)` / `.open(token)` mint and read tokens without a request (token-only configs with `cookie: false, sessionHeader: false` allow only these two). JWTs live in chunked cookies; sessions are lazy (`id` is `undefined` until `update()` is called). Elysia's `jwsSession`/`jweSession` plugins are `defineXSession(config).plugin()`. `unjwt/session` takes `{ req, res?, context? }` (an h3 or `nuxt/server` event as is), a `Request` or `{ headers, context? }` read-only, or `{ token }`, and `defineXSession(config, { driver })` runs on any framework through a `SessionDriver`
- **PBES2 security**: default `p2c` (iteration count) is `600_000` per OWASP cookbook; only lower it for legacy interoperability. It is also the default unwrap ceiling (`maxIterations`), so producers refuse a higher `p2c`
- **Bounded work per call**: `verify`/`verifyMulti`/`verifyMultiAll`/`decrypt`/`decryptMulti` take a grouped `limits` option — `signatures` (16), `recipients` (16), `keyCandidates` (8), `keyAttempts` (16 — key trials summed across every signature or recipient of a `verifyMulti`/`verifyMultiAll`/`decryptMulti` call) and `pbes2Iterations` (2 400 000 — four attempts at the default `p2c` of 600 000 — a budget summed across every PBES2 attempt of the call; a single unwrap is separately capped by `maxIterations`, default 600 000). Each operation exposes the subset that applies to it, every value must be a positive integer (`ERR_INVALID_OPTION` otherwise), and `DEFAULT_JOSE_LIMITS` (from `unjwt`, `unjwt/jws`, `unjwt/jwe`) carries the numbers
- **`kid` defaults to the thumbprint**: `generateJWK()` and `deriveJWKFromPassword()` name a key by its RFC 7638 `thumbprint()` when the caller passes no `kid`. A thumbprint is derived from the key material, so it is also the safe key for a replacement JWK cache — combined with the key half (`"d" in jwk`) and the `alg`, since both halves of a pair share one thumbprint — while a `kid` is a chosen label and two keys may share one
- **`aud` is opt-in**: the `aud` claim is checked only when `audience` is configured; a token carrying `aud` passes a verifier that sets none
