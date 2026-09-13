# Deprecations

Ledger of deprecated public API. One row per symbol: where it lives, what replaces it, the release that marked it `@deprecated`, the release that removes it.

| Symbol                                      | Replacement                          | Deprecated in    | Remove in |
| ------------------------------------------- | ------------------------------------ | ---------------- | --------- |
| `getJWKFromSet` (`unjwt/jwk`)               | `getJWKsFromSet`                     | v0.6.0           | TBD       |
| `importFromPEM` (`unjwt/jwk`)               | `importPEM`                          | v0.7.0           | TBD       |
| `exportToPEM` (`unjwt/jwk`)                 | `exportPEM`                          | v0.7.0           | TBD       |
| `computeExpiresInSeconds` (`unjwt/utils`)   | `computeDurationInSeconds`           | v0.7.0           | TBD       |
| `computeMaxTokenAgeSeconds` (`unjwt/utils`) | `computeDurationInSeconds`           | v0.7.0           | TBD       |
| `base64UrlEncode` (`unjwt/utils`)           | unjwt base64url tooling (0.8 naming) | v0.8.0 (planned) | v0.9.0    |
| `base64UrlDecode` (`unjwt/utils`)           | unjwt base64url tooling (0.8 naming) | v0.8.0 (planned) | v0.9.0    |
| `base64Encode` (`unjwt/utils`)              | TBD (0.8 decision)                   | v0.8.0 (planned) | v0.9.0    |
| `base64Decode` (`unjwt/utils`)              | TBD (0.8 decision)                   | v0.8.0 (planned) | v0.9.0    |
