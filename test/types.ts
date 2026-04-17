// Compile-time assertions for public generic return types. Picked up by tsgo via the
// `test/**/*.ts` include pattern but not executed by vitest. Failures surface as
// typecheck errors rather than runtime test failures.
import { generateKey, generateJWK } from "../src/core/jwk";
import type {
  JWK_oct,
  JWK_RSA_Private,
  JWK_RSA_Public,
  JWK_EC_Private,
  JWK_EC_Public,
  JWK_OKP_Private,
  JWK_OKP_Public,
} from "../src/core/types";

type Equal<X, Y> =
  (<T>() => T extends X ? 1 : 2) extends <T>() => T extends Y ? 1 : 2 ? true : false;

// `_expect` consumes the `Equal<A, B>` result — passes only when the two resolve to an
// identical type. Compile errors here mean `generateKey`'s return type drifted.
const _expect = <T extends true>(_: T): void => {};

// --- generateKey without toJWK ---

_expect<Equal<Awaited<ReturnType<typeof generateKey<"HS256", {}>>>, CryptoKey>>(true);
_expect<Equal<Awaited<ReturnType<typeof generateKey<"A128KW", {}>>>, CryptoKey>>(true);
_expect<Equal<Awaited<ReturnType<typeof generateKey<"A256GCM", {}>>>, CryptoKey>>(true);
_expect<Equal<Awaited<ReturnType<typeof generateKey<"A128GCMKW", {}>>>, CryptoKey>>(true);

_expect<
  Equal<Awaited<ReturnType<typeof generateKey<"A128CBC-HS256", {}>>>, Uint8Array<ArrayBuffer>>
>(true);
_expect<
  Equal<Awaited<ReturnType<typeof generateKey<"A256CBC-HS512", {}>>>, Uint8Array<ArrayBuffer>>
>(true);

_expect<Equal<Awaited<ReturnType<typeof generateKey<"RS256", {}>>>, CryptoKeyPair>>(true);
_expect<Equal<Awaited<ReturnType<typeof generateKey<"PS384", {}>>>, CryptoKeyPair>>(true);
_expect<Equal<Awaited<ReturnType<typeof generateKey<"ES256", {}>>>, CryptoKeyPair>>(true);
_expect<Equal<Awaited<ReturnType<typeof generateKey<"Ed25519", {}>>>, CryptoKeyPair>>(true);
_expect<Equal<Awaited<ReturnType<typeof generateKey<"RSA-OAEP-256", {}>>>, CryptoKeyPair>>(true);
_expect<Equal<Awaited<ReturnType<typeof generateKey<"ECDH-ES+A128KW", {}>>>, CryptoKeyPair>>(true);

// --- generateKey with toJWK: true ---

_expect<Equal<Awaited<ReturnType<typeof generateKey<"HS256", { toJWK: true }>>>, JWK_oct>>(true);
_expect<Equal<Awaited<ReturnType<typeof generateKey<"A128KW", { toJWK: true }>>>, JWK_oct>>(true);
_expect<Equal<Awaited<ReturnType<typeof generateKey<"A256GCM", { toJWK: true }>>>, JWK_oct>>(true);
_expect<Equal<Awaited<ReturnType<typeof generateKey<"A128CBC-HS256", { toJWK: true }>>>, JWK_oct>>(
  true,
);

_expect<
  Equal<
    Awaited<ReturnType<typeof generateKey<"RS256", { toJWK: true }>>>,
    { privateKey: JWK_RSA_Private; publicKey: JWK_RSA_Public }
  >
>(true);
_expect<
  Equal<
    Awaited<ReturnType<typeof generateKey<"ES256", { toJWK: true }>>>,
    { privateKey: JWK_EC_Private; publicKey: JWK_EC_Public }
  >
>(true);
_expect<
  Equal<
    Awaited<ReturnType<typeof generateKey<"Ed25519", { toJWK: true }>>>,
    { privateKey: JWK_OKP_Private; publicKey: JWK_OKP_Public }
  >
>(true);

// ECDH-ES spans EC + OKP curves — runtime result depends on `namedCurve`, so the type is a union.
_expect<
  Equal<
    Awaited<ReturnType<typeof generateKey<"ECDH-ES+A128KW", { toJWK: true }>>>,
    | { privateKey: JWK_EC_Private; publicKey: JWK_EC_Public }
    | { privateKey: JWK_OKP_Private; publicKey: JWK_OKP_Public }
  >
>(true);

// --- generateJWK mirrors generateKey's toJWK:true return ---

_expect<Equal<Awaited<ReturnType<typeof generateJWK<"HS256">>>, JWK_oct>>(true);
_expect<
  Equal<
    Awaited<ReturnType<typeof generateJWK<"RS256">>>,
    { privateKey: JWK_RSA_Private; publicKey: JWK_RSA_Public }
  >
>(true);
_expect<
  Equal<
    Awaited<ReturnType<typeof generateJWK<"ES384">>>,
    { privateKey: JWK_EC_Private; publicKey: JWK_EC_Public }
  >
>(true);
