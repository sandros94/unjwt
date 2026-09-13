# Deprecations

Ledger of deprecated public API. One row per symbol: where it lives, what replaces it, the release that marked it `@deprecated`, the release that removes it.

| Symbol                                      | Replacement                | Deprecated in    | Remove in |
| ------------------------------------------- | -------------------------- | ---------------- | --------- |
| `getJWKFromSet` (`unjwt/jwk`)               | `getJWKsFromSet`           | v0.6.0           | v0.8.0    |
| `importFromPEM` (`unjwt/jwk`)               | `importPEM`                | v0.7.0           | v0.8.0    |
| `exportToPEM` (`unjwt/jwk`)                 | `exportPEM`                | v0.7.0           | v0.8.0    |
| `computeExpiresInSeconds` (`unjwt/utils`)   | `computeDurationInSeconds` | v0.7.0           | v0.8.0    |
| `computeMaxTokenAgeSeconds` (`unjwt/utils`) | `computeDurationInSeconds` | v0.7.0           | v0.8.0    |
| `base64UrlEncode` (`unjwt/utils`)           | `base64UrlStringify`       | v0.8.0 (planned) | v0.9.0    |
| `base64UrlDecode` (`unjwt/utils`)           | `base64UrlParse`           | v0.8.0 (planned) | v0.9.0    |
| `base64Encode` (`unjwt/utils`)              | `base64Stringify`          | v0.8.0 (planned) | v0.9.0    |
| `base64Decode` (`unjwt/utils`)              | `base64Parse`              | v0.8.0 (planned) | v0.9.0    |
