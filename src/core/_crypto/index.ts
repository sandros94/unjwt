/**
 * Internal cryptographic primitives for unjwt.
 *
 * Originally derived from panva/jose (MIT License,
 * https://github.com/panva/jose). Now independently maintained as part
 * of this library. All files in this directory are internal (_-prefixed)
 * and not part of any public export path.
 */

export { sign, verify, checkSigningKeyLength } from "./_sign-verify";
export {
  encrypt,
  decrypt,
  generateIV,
  generateCEK,
  bitLengthCEK,
  gcmkwEncrypt,
  gcmkwDecrypt,
  aesKwWrap,
  aesKwUnwrap,
} from "./_aes";
export { encryptKey, normalizeKey } from "./_key-encryption";
export { jwkTokey, keyToJWK } from "./_key-codec";
export { deriveKey as deriveKeyPBES2, pbes2Wrap, pbes2Unwrap } from "./_pbes2";
export { deriveECDHESKey, isECDHKeyAllowed } from "./_ecdh";
export { encryptRSAES, decryptRSAES } from "./_rsa";
export { fromPKCS8, fromSPKI, fromX509, toPKCS8, toSPKI } from "./_pem";
export type { KeyImportOptions } from "./_pem";
