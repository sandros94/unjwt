# Changelog

## v0.5.41

[compare changes](https://github.com/sandros94/unjwt/compare/v0.5.40...v0.5.41)

### 🚀 Enhancements

- `JWTError` and `isJWTError` utilities ([4722732](https://github.com/sandros94/unjwt/commit/4722732))
- **adapters:** Improve hook consistency and JWTError integration into `onExpire` ([5ccba0b](https://github.com/sandros94/unjwt/commit/5ccba0b))
- **jwk:** Configurable JWK import cache via JWKCacheAdapter ([6278677](https://github.com/sandros94/unjwt/commit/6278677))
- ⚠️ Type system overhaul ([a5e4c3e](https://github.com/sandros94/unjwt/commit/a5e4c3e))
- **jwk:** Full ECDH-ES support in wrapKey/unwrapKey + deriveSharedSecret export ([a39b3b8](https://github.com/sandros94/unjwt/commit/a39b3b8))
- **jwe:** Wire dir (direct key agreement) algorithm ([4d0b4bc](https://github.com/sandros94/unjwt/commit/4d0b4bc))
- **jwk:** ImportKey — opt-in CryptoKey output for oct JWKs ([17dd93b](https://github.com/sandros94/unjwt/commit/17dd93b))
- **jwk:** GetJWKFromSet single-key auto-resolve + getAllJWKsFromSet ([008c200](https://github.com/sandros94/unjwt/commit/008c200))
- Unify JWKSet filtering under new `getJWKsFromSet` function ([4887881](https://github.com/sandros94/unjwt/commit/4887881))
- Add JWK retry functionality for JWKSet ([ef3eefd](https://github.com/sandros94/unjwt/commit/ef3eefd))

### 🩹 Fixes

- Allow updating a token regardless of being able to store it in cookie (for direct body responses, OAuth) ([a1eb5d0](https://github.com/sandros94/unjwt/commit/a1eb5d0))
- **adapters:** Ensure session.token is always current and hooks fire reliably ([8fbfa00](https://github.com/sandros94/unjwt/commit/8fbfa00))
- **adapters:** Simplify token exposure via session ([de1efb4](https://github.com/sandros94/unjwt/commit/de1efb4))
- **adapters:** Make `onError` hook more consistent ([a974ca1](https://github.com/sandros94/unjwt/commit/a974ca1))
- **adapters:** Token initialization in sessions ([71abe44](https://github.com/sandros94/unjwt/commit/71abe44))
- `utils` module exports ([3a015b1](https://github.com/sandros94/unjwt/commit/3a015b1))
- **security:** Make sanitizeObject non-mutating ([75478c2](https://github.com/sandros94/unjwt/commit/75478c2))
- ⚠️ Unify JWK lookup type for both jws and jwe ([b17ab10](https://github.com/sandros94/unjwt/commit/b17ab10))

### 💅 Refactors

- **adapters:** Hook handling + typing and fix `onClear` exposing session before clearance ([3cc4667](https://github.com/sandros94/unjwt/commit/3cc4667))
- Module exports ([917b9d4](https://github.com/sandros94/unjwt/commit/917b9d4))
- ⚠️ Remove namespace exports ([7e3535b](https://github.com/sandros94/unjwt/commit/7e3535b))
- Promote jose fork to internal \_crypto/ implementation ([5683425](https://github.com/sandros94/unjwt/commit/5683425))
- Extract \_buildJWSHeader/\_buildJWEHeader internal utilities ([a19ee4a](https://github.com/sandros94/unjwt/commit/a19ee4a))
- ⚠️ Rename to `validateClaims` for better understanding ([33a7f49](https://github.com/sandros94/unjwt/commit/33a7f49))
- Simplify internal code ([162f5ac](https://github.com/sandros94/unjwt/commit/162f5ac))
- ⚠️ Simplify sign/encrypt overloads and use generic `JOSEPayload` type ([cca3950](https://github.com/sandros94/unjwt/commit/cca3950))

### 📖 Documentation

- Update based on recent changes ([7fa9d65](https://github.com/sandros94/unjwt/commit/7fa9d65))
- Update for v0.6 release ([f0ac225](https://github.com/sandros94/unjwt/commit/f0ac225))

### 🏡 Chore

- Update h3 dep ([0c15bdb](https://github.com/sandros94/unjwt/commit/0c15bdb))
- Apply automated updates ([72c5bb5](https://github.com/sandros94/unjwt/commit/72c5bb5))
- Update AGENTS.md ([f2f552a](https://github.com/sandros94/unjwt/commit/f2f552a))
- **agent:** Add adapter hooks planned changes ([e83cd79](https://github.com/sandros94/unjwt/commit/e83cd79))
- Apply automated updates ([be57acc](https://github.com/sandros94/unjwt/commit/be57acc))
- Apply automated updates ([8ef6218](https://github.com/sandros94/unjwt/commit/8ef6218))
- **agent:** Update plan state ([78358dd](https://github.com/sandros94/unjwt/commit/78358dd))
- Update rolldown dep and remove engine ([102da68](https://github.com/sandros94/unjwt/commit/102da68))
- Update AGENTS.md ([1593e18](https://github.com/sandros94/unjwt/commit/1593e18))
- Cleanup deprecated code ([5cd67bb](https://github.com/sandros94/unjwt/commit/5cd67bb))

#### ⚠️ Breaking Changes

- ⚠️ Type system overhaul ([a5e4c3e](https://github.com/sandros94/unjwt/commit/a5e4c3e))
- ⚠️ Unify JWK lookup type for both jws and jwe ([b17ab10](https://github.com/sandros94/unjwt/commit/b17ab10))
- ⚠️ Remove namespace exports ([7e3535b](https://github.com/sandros94/unjwt/commit/7e3535b))
- ⚠️ Rename to `validateClaims` for better understanding ([33a7f49](https://github.com/sandros94/unjwt/commit/33a7f49))
- ⚠️ Simplify sign/encrypt overloads and use generic `JOSEPayload` type ([cca3950](https://github.com/sandros94/unjwt/commit/cca3950))

### ❤️ Contributors

- Sandro Circi ([@sandros94](https://github.com/sandros94))

## v0.5.40

[compare changes](https://github.com/sandros94/unjwt/compare/v0.5.39...v0.5.40)

### 🚀 Enhancements

- Add JWK_Pair type for public and private JSON Web Keys combinations ([2bb33fa](https://github.com/sandros94/unjwt/commit/2bb33fa))

### 🩹 Fixes

- **core:** Remove redundant key deletion strategies during sanitization ([f33e8cd](https://github.com/sandros94/unjwt/commit/f33e8cd))
- Adapters exports ([f69bbf6](https://github.com/sandros94/unjwt/commit/f69bbf6))
- **h3v2:** Correct event type and move `onUpdate` hook ([99f53da](https://github.com/sandros94/unjwt/commit/99f53da))
- GenerateKey return type ([b9689f4](https://github.com/sandros94/unjwt/commit/b9689f4))
- **h3:** Make `update` parameter optional in `use*Session` functions ([86bcb50](https://github.com/sandros94/unjwt/commit/86bcb50))
- Respect async `clear` method in `use*Session` functions ([8c58661](https://github.com/sandros94/unjwt/commit/8c58661))
- **h3:** Make `update` parameter optional in `use*Session` functions ([a6f8c8d](https://github.com/sandros94/unjwt/commit/a6f8c8d))

### 📖 Documentation

- Add agent skill install snippet ([3f1af9e](https://github.com/sandros94/unjwt/commit/3f1af9e))

### 🏡 Chore

- Update readme badges ([46fb20b](https://github.com/sandros94/unjwt/commit/46fb20b))
- Update deps ([6b0359f](https://github.com/sandros94/unjwt/commit/6b0359f))
- Apply automated updates ([6e2738b](https://github.com/sandros94/unjwt/commit/6e2738b))

### 🤖 CI

- Add pkg.pr.new ([0ce74ee](https://github.com/sandros94/unjwt/commit/0ce74ee))

### ❤️ Contributors

- Sandro Circi ([@sandros94](https://github.com/sandros94))

## v0.5.39

[compare changes](https://github.com/sandros94/unjwt/compare/v0.5.38...v0.5.39)

### 🔥 Performance

- Optimize JWE/JWS to match or beat jose ([67c2f7d](https://github.com/sandros94/unjwt/commit/67c2f7d))

### 🩹 Fixes

- **h3v2:** Do not rely on upstream `event.res` ([8afdb1b](https://github.com/sandros94/unjwt/commit/8afdb1b))

### 💅 Refactors

- Improve performance, security, and bundle size across core modules ([9dbcb91](https://github.com/sandros94/unjwt/commit/9dbcb91))

### 📦 Build

- **h3v2:** Set `rou3` as external ([8f14b19](https://github.com/sandros94/unjwt/commit/8f14b19))

### 🏡 Chore

- Update deps ([eb292f1](https://github.com/sandros94/unjwt/commit/eb292f1))
- Apply automated updates ([7879fa6](https://github.com/sandros94/unjwt/commit/7879fa6))
- Add `AGENTS.md` ([1075536](https://github.com/sandros94/unjwt/commit/1075536))
- Switch to obuild, oxc and tsgo ([3c57f53](https://github.com/sandros94/unjwt/commit/3c57f53))
- Apply automated updates ([811bb19](https://github.com/sandros94/unjwt/commit/811bb19))
- Add `dev:prepare` script ([1602746](https://github.com/sandros94/unjwt/commit/1602746))
- Update scripts ([82e5d2b](https://github.com/sandros94/unjwt/commit/82e5d2b))
- Update AGENTS.md ([cdf76fe](https://github.com/sandros94/unjwt/commit/cdf76fe))
- Create agent skills ([635d738](https://github.com/sandros94/unjwt/commit/635d738))
- Update `AGENTS.md` ([c48c71a](https://github.com/sandros94/unjwt/commit/c48c71a))

### ✅ Tests

- Improve coverage ([16d2891](https://github.com/sandros94/unjwt/commit/16d2891))

### 🤖 CI

- Skip autofix on releases ([75e2266](https://github.com/sandros94/unjwt/commit/75e2266))
- Update actions ([7380ba8](https://github.com/sandros94/unjwt/commit/7380ba8))
- Use node present in `package.json` ([a726359](https://github.com/sandros94/unjwt/commit/a726359))
- Unify jobs and run autofix only when required ([466813e](https://github.com/sandros94/unjwt/commit/466813e))

### ❤️ Contributors

- Sandro Circi ([@sandros94](https://github.com/sandros94))

## v0.5.38

[compare changes](https://github.com/sandros94/unjwt/compare/v0.5.37...v0.5.38)

### 💅 Refactors

- **adapters:** Session init and id tracking ([#9](https://github.com/sandros94/unjwt/pull/9))

### ❤️ Contributors

- Sandro Circi ([@sandros94](https://github.com/sandros94))

## v0.5.37

[compare changes](https://github.com/sandros94/unjwt/compare/v0.5.36...v0.5.37)

### 🩹 Fixes

- **adapters:** Do not allow nullish ids ([f49df49](https://github.com/sandros94/unjwt/commit/f49df49))
- **adapters:** Properly use `jti`, `iat` and `exp` as per JWT spec ([ad159cd](https://github.com/sandros94/unjwt/commit/ad159cd))

### ❤️ Contributors

- Sandro Circi ([@sandros94](https://github.com/sandros94))

## v0.5.36

[compare changes](https://github.com/sandros94/unjwt/compare/v0.5.35...v0.5.36)

### 🩹 Fixes

- **adapters:** Compute `iat` as per JWT spec ([bab18c1](https://github.com/sandros94/unjwt/commit/bab18c1))

### ❤️ Contributors

- Sandro Circi ([@sandros94](https://github.com/sandros94))

## v0.5.35

[compare changes](https://github.com/sandros94/unjwt/compare/v0.5.34...v0.5.35)

### 🚀 Enhancements

- **adapters:** Expose `oldSession` `onUpdate` hooks ([699140b](https://github.com/sandros94/unjwt/commit/699140b))

### ❤️ Contributors

- Sandro Circi ([@sandros94](https://github.com/sandros94))

## v0.5.34

[compare changes](https://github.com/sandros94/unjwt/compare/v0.5.33...v0.5.34)

### 🩹 Fixes

- **adapters:** Add `session` to `onClear` hook ([afff527](https://github.com/sandros94/unjwt/commit/afff527))

### ❤️ Contributors

- Sandro Circi ([@sandros94](https://github.com/sandros94))

## v0.5.33

[compare changes](https://github.com/sandros94/unjwt/compare/v0.5.32...v0.5.33)

### 🚀 Enhancements

- **adapters:** Key lookup hook during verify/unseal ([741b194](https://github.com/sandros94/unjwt/commit/741b194))

### 🩹 Fixes

- **adapters:** Improve token retriveal for updated sessions ([623ebd5](https://github.com/sandros94/unjwt/commit/623ebd5))
- **JWS/JWE:** Automatically populate correct `kid` if available ([e987cf1](https://github.com/sandros94/unjwt/commit/e987cf1))
- **jwe/jwk:** Update key management algorithms to support AES-GCM key wrapping ([899642e](https://github.com/sandros94/unjwt/commit/899642e))

### 🏡 Chore

- Update deps ([2c9a8a6](https://github.com/sandros94/unjwt/commit/2c9a8a6))

### ❤️ Contributors

- Sandro Circi ([@sandros94](https://github.com/sandros94))

## v0.5.32

[compare changes](https://github.com/sandros94/unjwt/compare/v0.5.31...v0.5.32)

### 🤖 CI

- Remove duplicate build step ([2e36b20](https://github.com/sandros94/unjwt/commit/2e36b20))

### ❤️ Contributors

- Sandro Circi ([@sandros94](https://github.com/sandros94))

## v0.5.31

[compare changes](https://github.com/sandros94/unjwt/compare/v0.5.30...v0.5.31)

### 🩹 Fixes

- **h3v2:** Type generics not being optional ([6cab06c](https://github.com/sandros94/unjwt/commit/6cab06c))
- **adapters:** Token read on session initialization for supported responses ([9a98be1](https://github.com/sandros94/unjwt/commit/9a98be1))

### 💅 Refactors

- **adapters:** Replace JWTClaims with SessionClaims and fix exp typing ([9bf9b3c](https://github.com/sandros94/unjwt/commit/9bf9b3c))

### 🤖 CI

- Adjust CI conditions and update test command ([8180a23](https://github.com/sandros94/unjwt/commit/8180a23))
- Add publish.yml ([de054bd](https://github.com/sandros94/unjwt/commit/de054bd))

### ❤️ Contributors

- Sandro Circi ([@sandros94](https://github.com/sandros94))

## v0.5.30

[compare changes](https://github.com/sandros94/unjwt/compare/v0.5.29...v0.5.30)

### 🚀 Enhancements

- **h3:** Add token retrieval to JWE and JWS session management ([e49e093](https://github.com/sandros94/unjwt/commit/e49e093))

### ❤️ Contributors

- Sandro Circi ([@sandros94](https://github.com/sandros94))

## v0.5.29

[compare changes](https://github.com/sandros94/unjwt/compare/v0.5.28...v0.5.29)

### 🩹 Fixes

- **h3:** Type `SessionManager` prefer `ConfigMaxAge` for `expiresAt` typing ([d78ef92](https://github.com/sandros94/unjwt/commit/d78ef92))
- **h3:** Update session management types to use `ExpiresIn` for maxAge and expiresAt ([9f2850e](https://github.com/sandros94/unjwt/commit/9f2850e))

### 📖 Documentation

- Add comprehensive guide for H3 session adapters and JWT management ([06ca61b](https://github.com/sandros94/unjwt/commit/06ca61b))

### ❤️ Contributors

- Sandro Circi ([@sandros94](https://github.com/sandros94))

## v0.5.28

[compare changes](https://github.com/sandros94/unjwt/compare/v0.5.27...v0.5.28)

### 🏡 Chore

- Apply automated updates ([12118fa](https://github.com/sandros94/unjwt/commit/12118fa))

## v0.5.27

[compare changes](https://github.com/sandros94/unjwt/compare/v0.5.26...v0.5.27)

## v0.5.26

[compare changes](https://github.com/sandros94/unjwt/compare/v0.5.25...v0.5.26)

### 🚀 Enhancements

- **h3:** Automatically support `Bearer` style tokens in headers ([434c6db](https://github.com/sandros94/unjwt/commit/434c6db))

### 🩹 Fixes

- Use Set while constructing `requiredClaims` in h3 adapters ([b1dc462](https://github.com/sandros94/unjwt/commit/b1dc462))
- Set rou3 as optional peerDep ([de777bf](https://github.com/sandros94/unjwt/commit/de777bf))
- **h3:** Use object-style arguments for hooks ([6a5472e](https://github.com/sandros94/unjwt/commit/6a5472e))
- **h3:** Change error type to Error in `onExpire` hook and always provide detailed expiration error message ([1338d05](https://github.com/sandros94/unjwt/commit/1338d05))

### 📖 Documentation

- Fix H3 adapter documentation links ([ceb7817](https://github.com/sandros94/unjwt/commit/ceb7817))
- Add adapters dedicated readmes ([a3a8b6d](https://github.com/sandros94/unjwt/commit/a3a8b6d))

### 🏡 Chore

- Update `@eslint/plugin-kit` ([1663c91](https://github.com/sandros94/unjwt/commit/1663c91))
- Update h3 v2 to rc.5 ([5af244f](https://github.com/sandros94/unjwt/commit/5af244f))
- Update rou3 ([596bd9f](https://github.com/sandros94/unjwt/commit/596bd9f))

### ❤️ Contributors

- Sandro Circi ([@sandros94](https://github.com/sandros94))

## v0.5.25

[compare changes](https://github.com/sandros94/unjwt/compare/v0.5.24...v0.5.25)

### 🩹 Fixes

- Use h3's v2 chuncked cookie utils ([885f1ab](https://github.com/sandros94/unjwt/commit/885f1ab))

### 🏡 Chore

- Update h3 v2 ([8d3db63](https://github.com/sandros94/unjwt/commit/8d3db63))

### ❤️ Contributors

- Sandro Circi ([@sandros94](https://github.com/sandros94))

## v0.5.24

[compare changes](https://github.com/sandros94/unjwt/compare/v0.5.23...v0.5.24)

### 🚀 Enhancements

- **adapters:** New H3 v2 adapter ([#5](https://github.com/sandros94/unjwt/pull/5))

### 🩹 Fixes

- **h3:** Prevent `exp` spill ([01d8d14](https://github.com/sandros94/unjwt/commit/01d8d14))

### 📖 Documentation

- Describe h3v2 example with hooks ([cc4c9a7](https://github.com/sandros94/unjwt/commit/cc4c9a7))

### 📦 Build

- Fix exports ([f2f698d](https://github.com/sandros94/unjwt/commit/f2f698d))

### ❤️ Contributors

- Sandro Circi ([@sandros94](https://github.com/sandros94))

## v0.5.23

[compare changes](https://github.com/sandros94/unjwt/compare/v0.5.22...v0.5.23)

### 🚀 Enhancements

- **h3:** Propagate session configs via hook's last argument ([e9524c2](https://github.com/sandros94/unjwt/commit/e9524c2))

### 🩹 Fixes

- **h3:** Fork permalink ([6399c01](https://github.com/sandros94/unjwt/commit/6399c01))
- **h3:** Session validation when available in-context ([a5ecb4d](https://github.com/sandros94/unjwt/commit/a5ecb4d))
- **h3:** Remove `crypto` leftoff ([01ce93e](https://github.com/sandros94/unjwt/commit/01ce93e))
- **h3:** Conditional initialization ([3269537](https://github.com/sandros94/unjwt/commit/3269537))
- **h3:** Allow custom `typ` ([4e739fd](https://github.com/sandros94/unjwt/commit/4e739fd))
- **h3:** Simplify error checking ([794b936](https://github.com/sandros94/unjwt/commit/794b936))
- **h3:** Standardize `key` param in JWE sessions ([2e9306a](https://github.com/sandros94/unjwt/commit/2e9306a))
- **jwk:** Automatically create `kid` for `generateJWK` ([3ffcba3](https://github.com/sandros94/unjwt/commit/3ffcba3))
- **h3:** Improve JWK constrains ([fb8f90c](https://github.com/sandros94/unjwt/commit/fb8f90c))
- **h3:** Explicit `expiresIn: undefined` ([99efc2b](https://github.com/sandros94/unjwt/commit/99efc2b))

### ✅ Tests

- **h3:** Custom `typ` header ([efa3d77](https://github.com/sandros94/unjwt/commit/efa3d77))

### ❤️ Contributors

- Sandro Circi ([@sandros94](https://github.com/sandros94))

## v0.5.22

[compare changes](https://github.com/sandros94/unjwt/compare/v0.5.21...v0.5.22)

### 🚀 Enhancements

- **h3:** Session hooks ([346d88c](https://github.com/sandros94/unjwt/commit/346d88c))

### ❤️ Contributors

- Sandro Circi ([@sandros94](https://github.com/sandros94))

## v0.5.21

[compare changes](https://github.com/sandros94/unjwt/compare/v0.5.20...v0.5.21)

### 🚀 Enhancements

- H3 adapter ([7cb4584](https://github.com/sandros94/unjwt/commit/7cb4584))
- **h3:** Expose `expiresAt` if available ([57373f5](https://github.com/sandros94/unjwt/commit/57373f5))

### 🩹 Fixes

- **jwk:** Double sanitization ([a6be563](https://github.com/sandros94/unjwt/commit/a6be563))
- **h3:** Support asym keys with strictier types and re-export JWK utils ([d2c5669](https://github.com/sandros94/unjwt/commit/d2c5669))
- **h3:** Improve session exp validation ([462bcad](https://github.com/sandros94/unjwt/commit/462bcad))
- **h3:** Use payload's root as data storage ([1db6d7e](https://github.com/sandros94/unjwt/commit/1db6d7e))

### 📖 Documentation

- **adapters:** Show h3 example ([72d882c](https://github.com/sandros94/unjwt/commit/72d882c))

### 🏡 Chore

- Refactor project structure for future adapters ([9fede28](https://github.com/sandros94/unjwt/commit/9fede28))

### ❤️ Contributors

- Sandro Circi ([@sandros94](https://github.com/sandros94))

## v0.5.20

[compare changes](https://github.com/sandros94/unjwt/compare/v0.5.19...v0.5.20)

### 🩹 Fixes

- **jwt:** Update `maxTokenAge` type to match `ExpiresIn` and add `computeMaxTokenAgeSeconds` utility re-export ([480137e](https://github.com/sandros94/unjwt/commit/480137e))

### ❤️ Contributors

- Sandro Circi ([@sandros94](https://github.com/sandros94))

## v0.5.19

[compare changes](https://github.com/sandros94/unjwt/compare/v0.5.18...v0.5.19)

### 🚀 Enhancements

- Introduce ExpiresIn string compute ('1minute', '10d', ...) ([bfe554c](https://github.com/sandros94/unjwt/commit/bfe554c))

### ❤️ Contributors

- Sandro Circi ([@sandros94](https://github.com/sandros94))

## v0.5.18

[compare changes](https://github.com/sandros94/unjwt/compare/v0.5.17...v0.5.18)

### 🚀 Enhancements

- **jwk:** Add `deriveJWKFromPassword` utility variant ([459f0c9](https://github.com/sandros94/unjwt/commit/459f0c9))

### 🩹 Fixes

- **jwk:** Missing `deriveKeyFromPassword` custom JWK properties ([56d190c](https://github.com/sandros94/unjwt/commit/56d190c))

### ❤️ Contributors

- Sandro Circi ([@sandros94](https://github.com/sandros94))

## v0.5.17

[compare changes](https://github.com/sandros94/unjwt/compare/v0.5.16...v0.5.17)

### 🚀 Enhancements

- **jwk:** Add generateJWK function for JWK generation and narrow JWK type returns ([cd2e9ed](https://github.com/sandros94/unjwt/commit/cd2e9ed))

### 🩹 Fixes

- **jwk:** Preserve full `key_ops` for private or sym JWKs ([e2ab00f](https://github.com/sandros94/unjwt/commit/e2ab00f))
- **jwe:** `ECDH-ES` support ([90a3641](https://github.com/sandros94/unjwt/commit/90a3641))
- **jwe:** `RSA-OAEP` 256,384,512 with CBC enc ([a289258](https://github.com/sandros94/unjwt/commit/a289258))

### 📖 Documentation

- Specify solved warnings ([74b836f](https://github.com/sandros94/unjwt/commit/74b836f))

### 🏡 Chore

- Apply automated updates ([e694619](https://github.com/sandros94/unjwt/commit/e694619))
- Apply automated updates ([b7dc282](https://github.com/sandros94/unjwt/commit/b7dc282))

### ✅ Tests

- Reduce modulus (faster tests) and add more RSA-OAEP variants tests for `unwrapKey` ([8930faa](https://github.com/sandros94/unjwt/commit/8930faa))

### ❤️ Contributors

- Sandro Circi ([@sandros94](https://github.com/sandros94))

## v0.5.16

[compare changes](https://github.com/sandros94/unjwt/compare/v0.5.15...v0.5.16)

### 🩹 Fixes

- **utils:** `isAsymmetricJWK` return type ([167cc05](https://github.com/sandros94/unjwt/commit/167cc05))

### 📖 Documentation

- **JWS:** Improve example ([b943bdd](https://github.com/sandros94/unjwt/commit/b943bdd))

### ❤️ Contributors

- Sandro Circi ([@sandros94](https://github.com/sandros94))

## v0.5.15

[compare changes](https://github.com/sandros94/unjwt/compare/v0.5.14...v0.5.15)

### 🩹 Fixes

- Don't force `at+jwt`, optionally skip JWT verification and verify JWE ones by default ([8fe739d](https://github.com/sandros94/unjwt/commit/8fe739d))
- **JWT:** `exp` computing for custom `iat` ([f078fca](https://github.com/sandros94/unjwt/commit/f078fca))

### 📖 Documentation

- Add `validateJWT` description ([98db1a4](https://github.com/sandros94/unjwt/commit/98db1a4))

### 🏡 Chore

- Setup basic benchmarks ([e94ee4e](https://github.com/sandros94/unjwt/commit/e94ee4e))
- Update tasks ([82d9882](https://github.com/sandros94/unjwt/commit/82d9882))
- Update deps ([6c0a209](https://github.com/sandros94/unjwt/commit/6c0a209))

### ✅ Tests

- **JWS:** Skip validating JWT ([3d58540](https://github.com/sandros94/unjwt/commit/3d58540))
- **JWS:** Fix computed `exp` date calculation ([fa72522](https://github.com/sandros94/unjwt/commit/fa72522))

### ❤️ Contributors

- Sandro Circi ([@sandros94](https://github.com/sandros94))

## v0.5.14

[compare changes](https://github.com/sandros94/unjwt/compare/v0.5.13...v0.5.14)

### 🚀 Enhancements

- Add type guards for JWK types (sym/asym/ public/private) ([9912f8d](https://github.com/sandros94/unjwt/commit/9912f8d))
- **JWK:** Allow custom JWK params while generating keys ([2336e21](https://github.com/sandros94/unjwt/commit/2336e21))

### ✅ Tests

- Fix typing ([64456ef](https://github.com/sandros94/unjwt/commit/64456ef))

### ❤️ Contributors

- Sandro Circi ([@sandros94](https://github.com/sandros94))

## v0.5.13

[compare changes](https://github.com/sandros94/unjwt/compare/v0.5.12...v0.5.13)

### 🚀 Enhancements

- Sanitize from potential prototype pollution ([456dd07](https://github.com/sandros94/unjwt/commit/456dd07))

### 🏡 Chore

- Add vscode tasks ([1143c45](https://github.com/sandros94/unjwt/commit/1143c45))

### ❤️ Contributors

- Sandro Circi ([@sandros94](https://github.com/sandros94))

## v0.5.12

[compare changes](https://github.com/sandros94/unjwt/compare/v0.5.11...v0.5.12)

## v0.5.11

[compare changes](https://github.com/sandros94/unjwt/compare/v0.5.10...v0.5.11)

### 🩹 Fixes

- Default to `at+jwt` typ as per `RFC9068` ([60a4fe6](https://github.com/sandros94/unjwt/commit/60a4fe6))

### ❤️ Contributors

- Sandro Circi ([@sandros94](https://github.com/sandros94))

## v0.5.10

[compare changes](https://github.com/sandros94/unjwt/compare/v0.5.9...v0.5.10)

### 🚀 Enhancements

- JWE automatic claim validation and extracted utilities for advanced use ([119398e](https://github.com/sandros94/unjwt/commit/119398e))

### 🩹 Fixes

- Internal variable naming ([efb7682](https://github.com/sandros94/unjwt/commit/efb7682))
- Missing support for `Ed25519` keys ([6725437](https://github.com/sandros94/unjwt/commit/6725437))

### 🏡 Chore

- Update deps ([49b284a](https://github.com/sandros94/unjwt/commit/49b284a))

### ✅ Tests

- Add `jose` dependency for cross tests ([1fba782](https://github.com/sandros94/unjwt/commit/1fba782))
- Exclude jose fork from coverage ([a84f3df](https://github.com/sandros94/unjwt/commit/a84f3df))

### ❤️ Contributors

- Sandro Circi ([@sandros94](https://github.com/sandros94))

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
