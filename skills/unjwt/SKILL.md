---
name: unjwt
description: "Expert knowledge for working with unjwt — a low-level, zero-dep, JWT library using the Web Crypto API. Use this skill whenever the user is working with JWS, JWE, JWK, or JWT utilities, including signing, verifying, encrypting, decrypting, key management, and session handling. Trigger on any mention of unjwt or related JWT operations."
metadata:
  version: 0.1.0
  library: unjwt
  library-version: 0.6.0
  org: sandros94
  documentation: https://github.com/sandros94/unjwt
---

# unjwt Skill

Low-level JWT library using the Web Crypto API. Zero runtime dependencies for core; optional peer deps for framework adapters.

Implements JWS (RFC 7515), JWE (RFC 7516), and JWK (RFC 7517).

## Quick orientation

> **Skill written against `unjwt@0.6.0`.** APIs are stable within v0.6 but check the [changelog](https://github.com/sandros94/unjwt/releases) if behaviour seems off on a newer version.

The following is a list of reference files:

- `references/jws.md`: `sign()`, `verify()`, `JWSSignOptions`, `JWSVerifyOptions`
- `references/jwe.md`: `encrypt()`, `decrypt()`, `JWEEncryptOptions`, `JWEDecryptOptions`
- `references/jwk.md`: `generateKey()`, `generateJWK()`, `importKey()`, `exportKey()`, `wrapKey()`, `unwrapKey()`, PEM import/export (`importJWKFromPEM`, `exportJWKToPEM`), PBES2 key derivation (`deriveKeyFromPassword`, `deriveJWKFromPassword`), `getJWKFromSet()`, all JWK type definitions (`JWK`, `JWK_oct`, `JWK_Public`, `JWK_Private`, `JWKSet`, algorithm unions)
- `references/utils.md`: `base64UrlEncode`/`base64UrlDecode`, `base64Encode`/`base64Decode`, `randomBytes`, `concatUint8Arrays`, `textEncoder`/`textDecoder`, type guards (`isJWK`, `isJWKSet`, `isSymmetricJWK`, `isPrivateJWK`, `isPublicJWK`, `isCryptoKey`, `isCryptoKeyPair`), `validateJwtClaims`, `computeExpiresInSeconds`, `ExpiresIn` format, `JWTClaimValidationOptions`, `sanitizeObject`, `StrictOmit`
- `references/adapters-h3.md`: H3 session adapters (v1 and v2), `useJWESession`, `useJWSSession`, `SessionManager` interface, `SessionConfigJWE`, `SessionConfigJWS`, lifecycle hooks (`onRead`, `onUpdate`, `onClear`, `onExpire`, `onError`), key lookup hooks (`onUnsealKeyLookup`, `onVerifyKeyLookup`), lower-level functions (`getJWESession`, `sealJWESession`, `unsealJWESession`, `signJWSSession`, `verifyJWSSession`, etc.), cookie chunking (v2), header-based tokens, refresh token pattern

## Export Paths

| Path                  | Purpose                                                                       |
| --------------------- | ----------------------------------------------------------------------------- |
| `unjwt`               | Flat barrel: all public functions and types from `jws`, `jwe`, `jwk`, `utils` |
| `unjwt/jws`           | `sign()`, `verify()` — JWS Compact Serialization                              |
| `unjwt/jwe`           | `encrypt()`, `decrypt()` — JWE Compact Serialization                          |
| `unjwt/jwk`           | Key generation, import/export, wrap/unwrap, PEM conversion, PBES2 derivation  |
| `unjwt/utils`         | Base64URL encode/decode, type guards, JWT claim validation, `randomBytes`     |
| `unjwt/adapters/h3`   | H3 session adapter (aliases h3v1)                                             |
| `unjwt/adapters/h3v1` | H3 v1 session adapter (Nuxt v4, Nitro v2)                                     |
| `unjwt/adapters/h3v2` | H3 v2 session adapter (Nuxt v5, Nitro v3)                                     |

## Quick Start

```ts
// Sign and verify (JWS) — use subpath or root barrel
import { sign, verify } from "unjwt/jws";
import { generateJWK } from "unjwt/jwk";
// or: import { sign, verify, generateJWK } from "unjwt";

const key = await generateJWK("HS256");
const token = await sign({ sub: "user123" }, key, { expiresIn: "1h" });
const { payload } = await verify(token, key);

// Encrypt and decrypt (JWE)
import { encrypt, decrypt } from "unjwt/jwe";

const jwe = await encrypt({ secret: "data" }, "password");
const { payload } = await decrypt(jwe, "password");

// H3 session
import { useJWESession } from "unjwt/adapters/h3v2";

const session = await useJWESession(event, { key: "secret", maxAge: "7D" });
await session.update({ userId: "123" });
```

## Key Concepts

- **JWK-first key model**: functions accept JWK objects directly; `importKey()` normalizes CryptoKey/JWK/Uint8Array/string
- **Algorithm inference**: `sign`/`encrypt` infer `alg`/`enc` from JWK properties when not explicitly provided; password strings default to PBES2
- **ExpiresIn**: time durations accept numbers (seconds) or strings: `"30s"`, `"10m"`, `"2h"`, `"7D"`, `"1W"`, `"3M"`, `"1Y"`
- **H3 Session Adapters**: store JWTs in chunked cookies; sessions are lazy (`id` is `undefined` until `update()` is called)
