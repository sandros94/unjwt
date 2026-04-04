# JWE Reference (unjwt/jwe)

JSON Web Encryption ([RFC 7516](https://www.rfc-editor.org/rfc/rfc7516.txt)) — encrypt and decrypt data.

Import: `import { encrypt, decrypt } from "unjwt/jwe"` — or `from "unjwt"`

## Algorithms

### Key Management (`alg`)

| Family           | Identifiers                                                      |
| ---------------- | ---------------------------------------------------------------- |
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
- `key` — `CryptoKey | JWK | string | Uint8Array`
  - `string` / `Uint8Array` → password for PBES2 (defaults to `PBES2-HS256+A128KW` + `A128GCM`)
  - JWK → infers `alg`/`enc` from key properties
  - CryptoKey → requires explicit `alg` and `enc`
- `options?: JWEEncryptOptions`
  - `alg?: KeyManagementAlgorithm` — required when key is CryptoKey
  - `enc?: ContentEncryptionAlgorithm` — required when key is CryptoKey
  - `protectedHeader?: JWEHeaderParameters` — additional header params (`kid`, `typ`, `cty`, `crit`)
  - `expiresIn?: ExpiresIn` — sets `exp` claim
  - `currentDate?: Date`
  - `cek?: Uint8Array` — provide custom Content Encryption Key
  - `contentEncryptionIV?: Uint8Array` — provide custom IV
  - `p2s?: Uint8Array`, `p2c?: number` — PBES2 salt and iteration count
  - `keyManagementIV?: Uint8Array` — IV for AES-GCM key wrapping
  - `ecdh?` — `{ ephemeralKey?, partyUInfo?, partyVInfo? }` for ECDH-ES

**Returns:** `Promise<string>` — JWE compact token

```ts
import { encrypt } from "unjwt/jwe";
import { generateJWK } from "unjwt/jwk";

// Password-based (PBES2, simplest)
const token = await encrypt({ secret: "data" }, "my-password");

// Symmetric key (AES Key Wrap)
const aesKey = await generateJWK("A128KW");
const token2 = await encrypt({ secret: "data" }, aesKey);

// Asymmetric (RSA-OAEP)
const rsaKeys = await generateJWK("RSA-OAEP-256");
const token3 = await encrypt({ secret: "data" }, rsaKeys.publicKey);
```

## `decrypt(jwe, key, options?)`

Decrypts a JWE token.

**Parameters:**

- `jwe` — `string` — the JWE compact token
- `key` — `CryptoKey | JWK_Symmetric | JWK_Private | string | Uint8Array | JWEKeyLookupFunction`
  - `JWEKeyLookupFunction`: `(header, token) => key | Promise<key>`
- `options?: JWEDecryptOptions`
  - `algorithms?: KeyManagementAlgorithm[]` — allowlist of key management algorithms
  - `encryptionAlgorithms?: ContentEncryptionAlgorithm[]` — allowlist of content encryption algorithms
  - `validateJWT?: boolean` — parse as JWT and validate claims
  - `forceUint8Array?: boolean` — force payload as `Uint8Array`
  - `returnCek?: boolean` — if true, include `cek` and `aad` in result
  - Inherits `JWTClaimValidationOptions`: `audience`, `issuer`, `subject`, `maxTokenAge`, `clockTolerance`, `typ`, `currentDate`, `requiredClaims`

**Returns:** `Promise<JWEDecryptResult<T>>` — `{ payload, protectedHeader, cek?, aad? }`

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
  protectedHeader?: JWEHeaderParameters; // excludes alg/enc/iv/tag/p2s/p2c/epk/apu/apv
  cek?: Uint8Array;
  contentEncryptionIV?: Uint8Array;
  keyManagementIV?: Uint8Array;
  p2s?: Uint8Array;
  p2c?: number;
  ecdh?: {
    ephemeralKey?: CryptoKey | JWK_EC_Private | CryptoKeyPair | { publicKey; privateKey };
    partyUInfo?: Uint8Array;
    partyVInfo?: Uint8Array;
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
  protectedHeader: JWEHeaderParameters;
  cek?: Uint8Array; // only when returnCek: true
  aad?: Uint8Array; // only when returnCek: true
}

type JWEKeyLookupFunction = (
  header: JWEHeaderParameters,
  token: string,
) => MaybePromise<CryptoKey | JWK | string | Uint8Array>;
```
