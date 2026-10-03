/**
 * Internal cryptographic primitives for unjwt.
 *
 * Originally derived from panva/jose (MIT License,
 * https://github.com/panva/jose). Now independently maintained as part
 * of this library. All files in this directory are internal (_-prefixed)
 * and not part of any public export path.
 */

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
export { encryptKey, normalizeKey, normalizeEpk } from "./_key-encryption";
export { jwkTokey, keyToJWK } from "./_key-codec";
export {
  DEFAULT_PBES2_ITERATIONS,
  assertPBES2Params,
  assertPBES2Iterations,
  deriveKey as deriveKeyPBES2,
  pbes2Wrap,
  pbes2Unwrap,
} from "./_pbes2";
export { deriveECDHESKey, isECDHKeyAllowed } from "./_ecdh";
export { encryptRSAES, decryptRSAES } from "./_rsa";
export { fromPKCS8, fromSPKI, fromX509, toPKCS8, toSPKI } from "./_pem";
export type { KeyImportOptions } from "./_pem";
export { thumbprint } from "./_thumbprint";
export type { ThumbprintHash } from "./_thumbprint";
