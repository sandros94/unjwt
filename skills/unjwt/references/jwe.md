# JWE Reference (unjwt/jwe)

JSON Web Encryption ([RFC 7516](https://www.rfc-editor.org/rfc/rfc7516.txt)) — encrypt and decrypt data.

Import: `import { encrypt, decrypt } from "unjwt/jwe"` — or `from "unjwt"`

## Algorithms

### Key Management (`alg`)

| Family           | Identifiers                                                      |
| ---------------- | ---------------------------------------------------------------- |
| Direct           | `dir`                                                            |
| RSA-OAEP         | `RSA-OAEP`, `RSA-OAEP-256`, `RSA-OAEP-384`, `RSA-OAEP-512`       |
| AES Key Wrap     | `A128KW`, `A192KW`, `A256KW`                                     |
| AES-GCM Key Wrap | `A128GCMKW`, `A192GCMKW`, `A256GCMKW`                            |
| PBES2            | `PBES2-HS256+A128KW`, `PBES2-HS384+A192KW`, `PBES2-HS512+A256KW` |
| ECDH-ES          | `ECDH-ES`, `ECDH-ES+A128KW`, `ECDH-ES+A192KW`, `ECDH-ES+A256KW`  |

Type: `KeyManagementAlgorithm`

### Content Encryption (`enc`)

| Family              | Identifiers                                       |
| ------------------- | ------------------------------------------------- |
| AES-GCM             | `A128GCM`, `A192GCM`, `A256GCM`                   |
| AES-CBC + HMAC-SHA2 | `A128CBC-HS256`, `A192CBC-HS384`, `A256CBC-HS512` |

Type: `ContentEncryptionAlgorithm`

## `encrypt(payload, key, options?)`

Produces a JWE Compact Serialization token.

**Parameters:**

- `payload` — `string | Uint8Array | Record<string, any>`
- `key`
  - `string` → password for PBES2 (infers `alg = "PBES2-HS256+A128KW"`)
  - `JWK` → infers `alg`/`enc` from key properties
  - `CryptoKey | JWK_oct | Uint8Array` with `alg: "dir"` → used directly as the CEK (`enc` required)
  - `CryptoKey` with other algorithms → requires explicit `alg` and `enc`
- `options?: JWEEncryptOptions`
  - `alg?: KeyManagementAlgorithm`
  - `enc?: ContentEncryptionAlgorithm` — required when `alg` is `"dir"`
  - `protectedHeader?` — additional header params (excludes `alg`/`enc`/`iv`/`tag`/`p2s`/`p2c`/`epk`/`apu`/`apv`)
  - `expiresIn?: ExpiresIn` — sets `exp` claim
  - `currentDate?: Date`
  - `cek?: Uint8Array` — custom Content Encryption Key
  - `contentEncryptionIV?: Uint8Array` — custom IV
  - `p2s?: Uint8Array`, `p2c?: number` — PBES2 salt and iteration count (default `p2c` is `600_000`)
  - `keyManagementIV?: Uint8Array` — IV for AES-GCM key wrapping
  - `ecdh?` — `{ ephemeralKey?, partyUInfo?, partyVInfo?, enc? }` for ECDH-ES; `enc` required only for bare `"ECDH-ES"`

**Returns:** `Promise<string>` — JWE compact token

```ts
import { encrypt } from "unjwt/jwe";
import { generateJWK, generateKey } from "unjwt/jwk";

// Password-based (PBES2, simplest)
const token = await encrypt({ secret: "data" }, "my-password");

// Symmetric key (AES Key Wrap)
const aesKey = await generateJWK("A128KW");
const token2 = await encrypt({ secret: "data" }, aesKey);

// Asymmetric (RSA-OAEP)
const rsaKeys = await generateJWK("RSA-OAEP-256");
const token3 = await encrypt({ secret: "data" }, rsaKeys.publicKey);

// Direct encryption (dir) — key IS the CEK
const cek = await generateKey("A256GCM");
const token4 = await encrypt({ secret: "data" }, cek, { alg: "dir", enc: "A256GCM" });

// Direct encryption with a JWK_oct that carries an enc hint
const cekJwk = { ...(await generateJWK("A256GCM")), enc: "A256GCM" };
const token5 = await encrypt({ secret: "data" }, cekJwk, { alg: "dir" }); // enc inferred from jwk.enc

// ECDH-ES
const ecKeys = await generateJWK("ECDH-ES+A256KW");
const token6 = await encrypt({ secret: "data" }, ecKeys.publicKey);
```

## `decrypt(jwe, key, options?)`

Decrypts a JWE token.

**Parameters:**

- `jwe` — `string` — the JWE compact token
- `key` — `CryptoKey | JWK_Symmetric | JWK_Private | string | Uint8Array | JWEKeyLookupFunction`
  - For `alg: "dir"`, pass the raw CEK (`CryptoKey`, `JWK_oct`, or `Uint8Array`)
  - `JWEKeyLookupFunction`: `(header, token) => key | JWKSet | Promise<key | JWKSet>` for dynamic key resolution
  - `JWKSet`: multi-key selection with automatic retry
    - Token has `kid` — only keys with that exact `kid` are tried (fast path, typically one key, no retry)
    - Token has no `kid` — all keys whose `alg` field is compatible are tried in order; the first to verify successfully wins
    - No matching candidates — throws `JWTError("ERR_JWK_KEY_NOT_FOUND")` before any crypto attempt
    - Same retry applies when a `JWEKeyLookupFunction` returns a `JWKSet`
- `options?: JWEDecryptOptions`
  - `algorithms?: KeyManagementAlgorithm[]` — allowlist of key management algorithms
  - `encryptionAlgorithms?: ContentEncryptionAlgorithm[]` — allowlist of content encryption algorithms
  - `validateJWT?: boolean` — parse as JWT and validate claims
  - `forceUint8Array?: boolean` — force payload as `Uint8Array`
  - `returnCek?: boolean` — include raw `cek` and `aad` in result
  - Inherits `JWTClaimValidationOptions`: `audience`, `issuer`, `subject`, `maxTokenAge`, `clockTolerance`, `typ`, `currentDate`, `requiredClaims`, `recognizedHeaders`

**Returns:** `Promise<JWEDecryptResult<T>>`

```ts
import { decrypt } from "unjwt/jwe";

// Password-based
const { payload } = await decrypt(token, "my-password");

// With algorithm restrictions
const result = await decrypt(token, privateKey, {
  algorithms: ["RSA-OAEP-256"],
  encryptionAlgorithms: ["A256GCM"],
});

// With CEK access
const { payload, cek, aad } = await decrypt(token, key, { returnCek: true });
```

## Types

```ts
interface JWEEncryptOptions {
  alg?: KeyManagementAlgorithm;
  enc?: ContentEncryptionAlgorithm;
  currentDate?: Date;
  expiresIn?: ExpiresIn;
  protectedHeader?: StrictOmit<
    JWEHeaderParameters,
    "alg" | "enc" | "iv" | "tag" | "p2s" | "p2c" | "epk" | "apu" | "apv"
  >;
  cek?: Uint8Array;
  contentEncryptionIV?: Uint8Array;
  keyManagementIV?: Uint8Array;
  p2s?: Uint8Array;
  p2c?: number; // default: 600_000 for PBES2
  ecdh?: {
    ephemeralKey?: CryptoKey | JWK_EC_Private | CryptoKeyPair | { publicKey; privateKey };
    partyUInfo?: Uint8Array;
    partyVInfo?: Uint8Array;
    enc?: ContentEncryptionAlgorithm; // required for bare "ECDH-ES"
  };
}

interface JWEDecryptOptions extends JWTClaimValidationOptions {
  algorithms?: KeyManagementAlgorithm[];
  encryptionAlgorithms?: ContentEncryptionAlgorithm[];
  forceUint8Array?: boolean;
  validateJWT?: boolean;
  returnCek?: boolean;
}

interface JWEDecryptResult<T> {
  payload: T;
  protectedHeader: JWEProtectedHeader; // alg and enc are required and strongly typed
  cek?: Uint8Array; // only when returnCek: true
  aad?: Uint8Array; // only when returnCek: true
}

// JWEProtectedHeader extends JWEHeaderParameters with alg and enc required
interface JWEProtectedHeader extends JWEHeaderParameters {
  alg: KeyManagementAlgorithm;
  enc: ContentEncryptionAlgorithm;
}

type JWEKeyLookupFunction = (
  header: JWEHeaderParameters,
  token: string,
) => MaybePromise<CryptoKey | JWK | JWKSet | string | Uint8Array>;
```
