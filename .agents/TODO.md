# Deprecations

Ledger of deprecated public API. One row per symbol: where it lives, what replaces it, the release that marked it `@deprecated`, the release that removes it.

| Symbol | Replacement | Deprecated in | Remove in |
| --- | --- | --- | --- |
| `base64UrlEncode` (`unjwt/utils`) | `base64UrlStringify` | v0.8.0 | v0.9.0 |
| `base64UrlDecode` (`unjwt/utils`) | `base64UrlParse` | v0.8.0 | v0.9.0 |
| `base64Encode` (`unjwt/utils`) | `base64Stringify` | v0.8.0 | v0.9.0 |
| `base64Decode` (`unjwt/utils`) | `base64Parse` | v0.8.0 | v0.9.0 |
| `forceUint8Array` (`unjwt/jws`, `unjwt/jwe`) | `payload: "bytes"` | v0.8.0 | v0.9.0 |
| `applyTypCtyDefaults` (`unjwt/utils`) | `applyTypDefault` (`unjwt/internal`) | v0.8.0 | v0.9.0 |
| `decodePayloadFromBytes` (`unjwt/utils`) | `parsePayloadBytes` (`unjwt/internal`) | v0.8.0 | v0.9.0 |
| `decodePayloadFromB64UrlSegment` (`unjwt/utils`) | `parsePayloadSegment` (`unjwt/internal`) | v0.8.0 | v0.9.0 |
| `getPlaintextBytes` (`unjwt/utils`) | `getPlaintextBytes` (`unjwt/internal`) | v0.8.0 | v0.9.0 |
| `computeJwtTimeClaims` (`unjwt/utils`) | `computeJwtTimeClaims` (`unjwt/internal`) | v0.8.0 | v0.9.0 |
| `validateCriticalHeadersJWS` (`unjwt/utils`) | `validateCriticalHeadersJWS` (`unjwt/internal`) | v0.8.0 | v0.9.0 |
| `validateCriticalHeadersJWE` (`unjwt/utils`) | `validateCriticalHeadersJWE` (`unjwt/internal`) | v0.8.0 | v0.9.0 |
| `assertCritShape` (`unjwt/utils`) | `assertCritShape` (`unjwt/internal`) | v0.8.0 | v0.9.0 |
| `DecodePayloadOptions` (`unjwt/utils`) | `ParsePayloadOptions` (`unjwt/internal`) | v0.8.0 | v0.9.0 |
| `ComputeJwtTimeClaimsOptions` (`unjwt/utils`) | `ComputeJwtTimeClaimsOptions` (`unjwt/internal`) | v0.8.0 | v0.9.0 |
| implicit `sessionHeader` default with cookies on (`unjwt/adapters/*`) | `sessionHeader: true` | v0.8.2 | v0.9.0 |
| `useJWSSession` (`unjwt/adapters/h3v1`, `h3v2`) | `defineJWSSession(config).use(event)` | v0.8.2 | v0.9.0 |
| `getJWSSession` (`unjwt/adapters/h3v1`, `h3v2`) | `defineJWSSession(config).use(event)` | v0.8.2 | v0.9.0 |
| `getJWSSessionToken` (`unjwt/adapters/h3v1`, `h3v2`) | `defineJWSSession(config).token(event)` | v0.8.2 | v0.9.0 |
| `updateJWSSession` (`unjwt/adapters/h3v1`, `h3v2`) | `(await defineJWSSession(config).use(event)).update()` | v0.8.2 | v0.9.0 |
| `clearJWSSession` (`unjwt/adapters/h3v1`, `h3v2`) | `(await defineJWSSession(config).use(event)).clear()` | v0.8.2 | v0.9.0 |
| `signJWSSession` (`unjwt/adapters/h3v1`, `h3v2`) | `defineJWSSession(config).issue(data)` | v0.8.2 | v0.9.0 |
| `verifyJWSSession` (`unjwt/adapters/h3v1`, `h3v2`) | `defineJWSSession(config).open(token, event)` | v0.8.2 | v0.9.0 |
| `useJWESession` (`unjwt/adapters/h3v1`, `h3v2`) | `defineJWESession(config).use(event)` | v0.8.2 | v0.9.0 |
| `getJWESession` (`unjwt/adapters/h3v1`, `h3v2`) | `defineJWESession(config).use(event)` | v0.8.2 | v0.9.0 |
| `getJWESessionToken` (`unjwt/adapters/h3v1`, `h3v2`) | `defineJWESession(config).token(event)` | v0.8.2 | v0.9.0 |
| `updateJWESession` (`unjwt/adapters/h3v1`, `h3v2`) | `(await defineJWESession(config).use(event)).update()` | v0.8.2 | v0.9.0 |
| `clearJWESession` (`unjwt/adapters/h3v1`, `h3v2`) | `(await defineJWESession(config).use(event)).clear()` | v0.8.2 | v0.9.0 |
| `sealJWESession` (`unjwt/adapters/h3v1`, `h3v2`) | `defineJWESession(config).issue(data)` | v0.8.2 | v0.9.0 |
| `unsealJWESession` (`unjwt/adapters/h3v1`, `h3v2`) | `defineJWESession(config).open(token, event)` | v0.8.2 | v0.9.0 |
| `defineJWSSession` (`unjwt/adapters/h3v1`) | `defineJWSSession` (`unjwt/session`) | v0.8.2 | v0.9.0 |
| `defineJWESession` (`unjwt/adapters/h3v1`) | `defineJWESession` (`unjwt/session`) | v0.8.2 | v0.9.0 |
| `CompatEvent` (`unjwt/adapters/h3v1`) | `SessionRequestEvent` (`unjwt/session`) | v0.8.2 | v0.9.0 |
| `defineJWSSession` (`unjwt/adapters/h3`, `h3v2`) | `defineJWSSession` (`unjwt/session`) | v0.8.2 | v0.9.0 |
| `defineJWESession` (`unjwt/adapters/h3`, `h3v2`) | `defineJWESession` (`unjwt/session`) | v0.8.2 | v0.9.0 |
| `SessionJWS`, `SessionJWE` (`unjwt/adapters/h3*`) | `SessionJWS`, `SessionJWE` (`unjwt/session`) | v0.8.2 | v0.9.0 |
| `SessionHooksJWS`, `SessionHooksJWE` (`unjwt/adapters/h3*`) | the same names on `unjwt/session` | v0.8.2 | v0.9.0 |
| `SessionConfigJWS`, `SessionConfigJWE` (`unjwt/adapters/h3*`) | the same names on `unjwt/session` | v0.8.2 | v0.9.0 |
| `createJWSSession` (`unjwt/adapters/elysia`) | `defineJWSSession(config).use(context)` | v0.8.2 | v0.9.0 |
| `createJWESession` (`unjwt/adapters/elysia`) | `defineJWESession(config).use(context)` | v0.8.2 | v0.9.0 |
| `exportKey` (`unjwt/jwk`) | `exportJWK` | v0.8.2 | v0.9.0 |
| `{ privateKey, publicKey? }` pair as a JWE session `key` (`JWESessionKey`, `unjwt/session`, `unjwt/adapters/*`) | an `oct` JWK, or `defineJWSSession` for a key pair | v0.8.5 | v0.9.0 |
| `DecodeOptions` (`unjwt/utils`) | `Base64ParseOptions` | v0.8.5 | v0.9.0 |
