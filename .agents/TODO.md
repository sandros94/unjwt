# Deprecations

Ledger of deprecated public API. One row per symbol: where it lives, what replaces it, the release that marked it `@deprecated`, the release that removes it.

| Symbol                                           | Replacement                                      | Deprecated in | Remove in |
| ------------------------------------------------ | ------------------------------------------------ | ------------- | --------- |
| `base64UrlEncode` (`unjwt/utils`)                | `base64UrlStringify`                             | v0.8.0        | v0.9.0    |
| `base64UrlDecode` (`unjwt/utils`)                | `base64UrlParse`                                 | v0.8.0        | v0.9.0    |
| `base64Encode` (`unjwt/utils`)                   | `base64Stringify`                                | v0.8.0        | v0.9.0    |
| `base64Decode` (`unjwt/utils`)                   | `base64Parse`                                    | v0.8.0        | v0.9.0    |
| `forceUint8Array` (`unjwt/jws`, `unjwt/jwe`)     | `payload: "bytes"`                               | v0.8.0        | v0.9.0    |
| `applyTypCtyDefaults` (`unjwt/utils`)            | `applyTypDefault` (`unjwt/internal`)             | v0.8.0        | v0.9.0    |
| `decodePayloadFromBytes` (`unjwt/utils`)         | `parsePayloadBytes` (`unjwt/internal`)           | v0.8.0        | v0.9.0    |
| `decodePayloadFromB64UrlSegment` (`unjwt/utils`) | `parsePayloadSegment` (`unjwt/internal`)         | v0.8.0        | v0.9.0    |
| `getPlaintextBytes` (`unjwt/utils`)              | `getPlaintextBytes` (`unjwt/internal`)           | v0.8.0        | v0.9.0    |
| `computeJwtTimeClaims` (`unjwt/utils`)           | `computeJwtTimeClaims` (`unjwt/internal`)        | v0.8.0        | v0.9.0    |
| `validateCriticalHeadersJWS` (`unjwt/utils`)     | `validateCriticalHeadersJWS` (`unjwt/internal`)  | v0.8.0        | v0.9.0    |
| `validateCriticalHeadersJWE` (`unjwt/utils`)     | `validateCriticalHeadersJWE` (`unjwt/internal`)  | v0.8.0        | v0.9.0    |
| `assertCritShape` (`unjwt/utils`)                | `assertCritShape` (`unjwt/internal`)             | v0.8.0        | v0.9.0    |
| `DecodePayloadOptions` (`unjwt/utils`)           | `ParsePayloadOptions` (`unjwt/internal`)         | v0.8.0        | v0.9.0    |
| `ComputeJwtTimeClaimsOptions` (`unjwt/utils`)    | `ComputeJwtTimeClaimsOptions` (`unjwt/internal`) | v0.8.0        | v0.9.0    |
