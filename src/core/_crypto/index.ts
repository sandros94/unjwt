/** Internal crypto primitives, originally derived from panva/jose (MIT License, https://github.com/panva/jose). */

export { sign, verify } from "./_sign-verify";
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
} from "./_aes";
export { encryptKey, normalizeEpk } from "./_key-encryption";
export { jwkTokey, keyToJWK } from "./_key-codec";
export {
  DEFAULT_PBES2_ITERATIONS,
  assertPBES2Params,
  assertPBES2Salt,
  assertPBES2Count,
  assertPBES2Iterations,
  deriveKey as deriveKeyPBES2,
  pbes2Wrap,
  pbes2Unwrap,
} from "./_pbes2";
export { deriveECDHESKey, assertECDHKeyAllowed } from "./_ecdh";
export { encryptRSAES, decryptRSAES } from "./_rsa";
export { fromPKCS8, fromSPKI, fromX509, toPKCS8, toSPKI } from "./_pem";
export type { KeyImportOptions } from "./_pem";
export { thumbprint } from "./_thumbprint";
export type { ThumbprintHash } from "./_thumbprint";
