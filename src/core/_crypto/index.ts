/** Internal crypto primitives, originally derived from panva/jose (MIT License, https://github.com/panva/jose). */

export { sign, verify } from "./_sign-verify.ts";
export {
  encrypt,
  decrypt,
  generateIV,
  generateCEK,
  bitLengthCEK,
  bitLengthIV,
  bitLengthTag,
  gcmkwEncrypt,
  gcmkwDecrypt,
  aesKwWrap,
  aesKwUnwrap,
  assertOctKeyLength,
} from "./_aes.ts";
export { encryptKey, normalizeEpk } from "./_key-encryption.ts";
export { jwkTokey, keyToJWK } from "./_key-codec.ts";
export {
  DEFAULT_PBES2_ITERATIONS,
  assertPBES2Params,
  assertPBES2Salt,
  assertPBES2Count,
  assertPBES2Iterations,
  deriveKey as deriveKeyPBES2,
  pbes2Wrap,
  pbes2Unwrap,
} from "./_pbes2.ts";
export { deriveECDHESKey, assertECDHKeyAllowed } from "./_ecdh.ts";
export { encryptRSAES, decryptRSAES } from "./_rsa.ts";
export { fromPKCS8, fromSPKI, fromX509, toPKCS8, toSPKI } from "./_pem.ts";
export type { KeyImportOptions } from "./_pem.ts";
export { thumbprint } from "./_thumbprint.ts";
export type { ThumbprintHash } from "./_thumbprint.ts";
