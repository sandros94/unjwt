# Changelog

## v0.5.9

[compare changes](https://github.com/sandros94/unjwt/compare/v0.5.8...v0.5.9)

### 🩹 Fixes

- **JWS:** Automatically include `kid` if available in the signing JWK ([889cacb](https://github.com/sandros94/unjwt/commit/889cacb))

### 🏡 Chore

- Remove `.d.ts` files from final build ([9e0ca26](https://github.com/sandros94/unjwt/commit/9e0ca26))

### ❤️ Contributors

- Sandro Circi ([@sandros94](https://github.com/sandros94))

## v0.5.8

[compare changes](https://github.com/sandros94/unjwt/compare/v0.5.7...v0.5.8)

### 🩹 Fixes

- **JWS:** Simplify iat assignment and ensure exp calculation uses current time ([7abdf5f](https://github.com/sandros94/unjwt/commit/7abdf5f))

### ✅ Tests

- **JWS:** Update tests to handle undefined iat and exp values ([d763152](https://github.com/sandros94/unjwt/commit/d763152))
- **JWS:** Improve expiration validation tests ([b58cd80](https://github.com/sandros94/unjwt/commit/b58cd80))

### ❤️ Contributors

- Sandro Circi ([@sandros94](https://github.com/sandros94))

## v0.5.7

[compare changes](https://github.com/sandros94/unjwt/compare/v0.5.6...v0.5.7)

### 🩹 Fixes

- **JWS:** Conditional issued at ([e3231fd](https://github.com/sandros94/unjwt/commit/e3231fd))
- **JWS:** Validate claims only for valid JWTs ([375a498](https://github.com/sandros94/unjwt/commit/375a498))

### ❤️ Contributors

- Sandro Circi ([@sandros94](https://github.com/sandros94))

## v0.5.6

[compare changes](https://github.com/sandros94/unjwt/compare/v0.5.5...v0.5.6)

### 🚀 Enhancements

- **JWS:** `expiresIn` sign option ([481edc6](https://github.com/sandros94/unjwt/commit/481edc6))

### 🩹 Fixes

- **JWS:** Missing key length validation ([1501793](https://github.com/sandros94/unjwt/commit/1501793))

### ❤️ Contributors

- Sandro Circi ([@sandros94](https://github.com/sandros94))

## v0.5.5

[compare changes](https://github.com/sandros94/unjwt/compare/v0.5.4...v0.5.5)

### 🩹 Fixes

- **utils:** Native `fromBase64` decode ([85950df](https://github.com/sandros94/unjwt/commit/85950df))

### ❤️ Contributors

- Sandro Circi ([@sandros94](https://github.com/sandros94))

## v0.5.4

[compare changes](https://github.com/sandros94/unjwt/compare/v0.5.3...v0.5.4)

### 🩹 Fixes

- **jwk:** Allow importKey to infer alg from provided JWK ([7ad1140](https://github.com/sandros94/unjwt/commit/7ad1140))

### ✅ Tests

- Parallelize key generation and skip coverage for now ([08928f5](https://github.com/sandros94/unjwt/commit/08928f5))

### ❤️ Contributors

- Sandro Circi ([@sandros94](https://github.com/sandros94))

## v0.5.3

[compare changes](https://github.com/sandros94/unjwt/compare/v0.5.2...v0.5.3)

### 🚀 Enhancements

- **jws:** Automatically retrieve correct JWK from JWK Set ([d1274c6](https://github.com/sandros94/unjwt/commit/d1274c6))

### 🩹 Fixes

- `KeyLookupFunction` ([c707ae4](https://github.com/sandros94/unjwt/commit/c707ae4))

### 🏡 Chore

- Apply automated updates ([0130d7e](https://github.com/sandros94/unjwt/commit/0130d7e))

### ❤️ Contributors

- Sandro Circi ([@sandros94](https://github.com/sandros94))

## v0.5.2

[compare changes](https://github.com/sandros94/unjwt/compare/v0.5.1...v0.5.2)

### 🚀 Enhancements

- **jws:** Enhance verification options with required claims and validations ([bc5dad4](https://github.com/sandros94/unjwt/commit/bc5dad4))

### 🩹 Fixes

- **jws:** `crit` header param check ([34c536f](https://github.com/sandros94/unjwt/commit/34c536f))
- **jws:** B64 payload decoding ([8a034d9](https://github.com/sandros94/unjwt/commit/8a034d9))

### ❤️ Contributors

- Sandro Circi ([@sandros94](https://github.com/sandros94))

## v0.5.1

[compare changes](https://github.com/sandros94/unjwt/compare/v0.5.0...v0.5.1)

### 🚀 Enhancements

- **utils:** Add simple base64 utils and improve performance ([42d506e](https://github.com/sandros94/unjwt/commit/42d506e))
- **jwk:** PEM to and from JWK ([6cde7b4](https://github.com/sandros94/unjwt/commit/6cde7b4))

### 🩹 Fixes

- **jws:** Variable naming ([bd12420](https://github.com/sandros94/unjwt/commit/bd12420))
- **jwk:** Pem import extractable by default ([32a8b25](https://github.com/sandros94/unjwt/commit/32a8b25))

### 📖 Documentation

- Update readme ([4c7160e](https://github.com/sandros94/unjwt/commit/4c7160e))
- Update readme ([2a76e50](https://github.com/sandros94/unjwt/commit/2a76e50))
- **README:** Add note for partially compatible algorithms and encodings ([c49fc97](https://github.com/sandros94/unjwt/commit/c49fc97))

### 🏡 Chore

- Apply automated updates ([3234986](https://github.com/sandros94/unjwt/commit/3234986))
- Apply automated updates ([a23bf60](https://github.com/sandros94/unjwt/commit/a23bf60))

### ❤️ Contributors

- Sandro Circi ([@sandros94](https://github.com/sandros94))

## v0.5.0

[compare changes](https://github.com/sandros94/unjwt/compare/v0.4.0...v0.5.0)

### 🚀 Enhancements

- ⚠️ Asymmetric keys and standardize library ([#3](https://github.com/sandros94/unjwt/pull/3))

### 📖 Documentation

- Add rfc links to readme ([4fd846f](https://github.com/sandros94/unjwt/commit/4fd846f))

### 🏡 Chore

- Apply automated updates ([e4b61c3](https://github.com/sandros94/unjwt/commit/e4b61c3))

#### ⚠️ Breaking Changes

- ⚠️ Asymmetric keys and standardize library ([#3](https://github.com/sandros94/unjwt/pull/3))

### ❤️ Contributors

- Sandro Circi ([@sandros94](https://github.com/sandros94))

## v0.4.0

### 🚀 Enhancements

- Init JWK and JWS utils ([4b12012](https://github.com/sandros94/unjwt/commit/4b12012))
- **jwk:** Unify import key ([1975918](https://github.com/sandros94/unjwt/commit/1975918))

### 🩹 Fixes

- Sub-module ([7f730f5](https://github.com/sandros94/unjwt/commit/7f730f5))

### 💅 Refactors

- Streamline algorithm validation functions and introduce lookup utility ([1ef081a](https://github.com/sandros94/unjwt/commit/1ef081a))
- **jwk:** `generateKey` ([360696d](https://github.com/sandros94/unjwt/commit/360696d))
- **jwk:** `exportKey` ([2cdb1e7](https://github.com/sandros94/unjwt/commit/2cdb1e7))

### 📖 Documentation

- Init ([2436ca4](https://github.com/sandros94/unjwt/commit/2436ca4))
- Add JWK and JWS ([21136f8](https://github.com/sandros94/unjwt/commit/21136f8))
- Add credits ([5bbc65c](https://github.com/sandros94/unjwt/commit/5bbc65c))
- Update readme ([22e1a59](https://github.com/sandros94/unjwt/commit/22e1a59))

### 🏡 Chore

- Init ([956100f](https://github.com/sandros94/unjwt/commit/956100f))
- Fork `uncrypto` ([2cf8314](https://github.com/sandros94/unjwt/commit/2cf8314))
- ⚠️ Set correct version ([1bb6131](https://github.com/sandros94/unjwt/commit/1bb6131))
- Drop `Buffer` support ([748d505](https://github.com/sandros94/unjwt/commit/748d505))

### ✅ Tests

- **jwe:** Missing tamper test ([c81bb85](https://github.com/sandros94/unjwt/commit/c81bb85))
- Add basic tests for utils ([bd644d9](https://github.com/sandros94/unjwt/commit/bd644d9))
- Improve characters out of range test ([bc61099](https://github.com/sandros94/unjwt/commit/bc61099))

#### ⚠️ Breaking Changes

- ⚠️ Set correct version ([1bb6131](https://github.com/sandros94/unjwt/commit/1bb6131))

### ❤️ Contributors

- Sandro Circi ([@sandros94](https://github.com/sandros94))
- Sandros94 ([@sandros94](https://github.com/sandros94))
