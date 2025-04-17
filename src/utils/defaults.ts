/**
 * Supported key wrapping algorithms
 */
export const KEY_WRAPPING_ALGORITHMS = /* @__PURE__ */ Object.freeze({
  "PBES2-HS256+A128KW": {
    hash: "SHA-256",
    keyLength: 128,
  },
  "PBES2-HS384+A192KW": {
    hash: "SHA-384",
    keyLength: 192,
  },
  "PBES2-HS512+A256KW": {
    hash: "SHA-512",
    keyLength: 256,
  },
});

/**
 * Supported JWS symmetric algorithms
 */
export const JWS_SYMMETRIC_ALGORITHMS = /* @__PURE__ */ Object.freeze({
  HS256: { hash: "SHA-256" },
  HS384: { hash: "SHA-384" },
  HS512: { hash: "SHA-512" },
});

/**
 * Supported content encryption algorithms
 */
export const CONTENT_ENCRYPTION_ALGORITHMS = /* @__PURE__ */ Object.freeze({
  // GCM algorithms
  A128GCM: {
    type: "gcm",
    keyLength: 128,
    tagLength: 16,
    ivLength: 12,
  },
  A192GCM: {
    type: "gcm",
    keyLength: 192,
    tagLength: 16,
    ivLength: 12,
  },
  A256GCM: {
    type: "gcm",
    keyLength: 256,
    tagLength: 16,
    ivLength: 12,
  },
  // TODO: implement future CBC algorithms
  "A128CBC-HS256": {
    type: "cbc",
    keyLength: 256, // Combined key length (encryption + HMAC)
    encKeyLength: 128,
    macKeyLength: 128,
    tagLength: 16,
    ivLength: 16,
    macAlgorithm: "SHA-256",
  },
  "A192CBC-HS384": {
    type: "cbc",
    keyLength: 384, // Combined key length (encryption + HMAC)
    encKeyLength: 192,
    macKeyLength: 192,
    tagLength: 24,
    ivLength: 16,
    macAlgorithm: "SHA-384",
  },
  "A256CBC-HS512": {
    type: "cbc",
    keyLength: 512, // Combined key length (encryption + HMAC)
    encKeyLength: 256,
    macKeyLength: 256,
    tagLength: 32,
    ivLength: 16,
    macAlgorithm: "SHA-512",
  },
});
