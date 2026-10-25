# Deprecations

Ledger of deprecated public API. One row per symbol: where it lives, what replaces it, the release that marked it `@deprecated`, the release that removes it.

| Symbol | Replacement | Deprecated in | Remove in |
| --- | --- | --- | --- |
| `createJWSSession` (`unjwt/adapters/elysia`) | `defineJWSSession(config).use(context)` | v0.8.2 | v0.9.0 |
| `createJWESession` (`unjwt/adapters/elysia`) | `defineJWESession(config).use(context)` | v0.8.2 | v0.9.0 |
