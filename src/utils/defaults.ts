/**
 * Supported JWS symmetric algorithms (HMAC)
 */
export const JWS_ALGORITHMS_SYMMETRIC = /* @__PURE__ */ Object.freeze({
  HS256: { name: "HMAC", hash: "SHA-256" },
  HS384: { name: "HMAC", hash: "SHA-384" },
  HS512: { name: "HMAC", hash: "SHA-512" },
} as const);

/**
 * Supported JWA asymmetric algorithms (RSA)
 */
export const JWS_ALGORITHMS_ASYMMETRIC_RSA = /* @__PURE__ */ Object.freeze({
  RS256: { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
  RS384: { name: "RSASSA-PKCS1-v1_5", hash: "SHA-384" },
  RS512: { name: "RSASSA-PKCS1-v1_5", hash: "SHA-512" },

  PS256: { name: "RSASSA-PSS", hash: "SHA-256", saltLength: 32 },
  PS384: { name: "RSASSA-PSS", hash: "SHA-384", saltLength: 48 },
  PS512: { name: "RSASSA-PSS", hash: "SHA-512", saltLength: 64 },
} as const);

/**
 * Supported JWA algorithms
 */
export const JWS_ALGORITHMS = /* @__PURE__ */ Object.freeze({
  ...JWS_ALGORITHMS_SYMMETRIC,
  ...JWS_ALGORITHMS_ASYMMETRIC_RSA,
  // TODO: add `none`
});

/**
 * Supported key wrapping algorithms (PBES2)
 */
export const JWE_KEY_WRAPPING_PBES2 = /* @__PURE__ */ Object.freeze({
  "PBES2-HS256+A128KW": {
    name: "PBES2",
    hash: "SHA-256",
    keyLength: 128,
  },
  "PBES2-HS384+A192KW": {
    name: "PBES2",
    hash: "SHA-384",
    keyLength: 192,
  },
  "PBES2-HS512+A256KW": {
    name: "PBES2",
    hash: "SHA-512",
    keyLength: 256,
  },
} as const);

/**
 * Supported key wrapping algorithms (RSA)
 */
export const JWE_KEY_WRAPPING_RSA = /* @__PURE__ */ Object.freeze({
  "RSA-OAEP": {
    name: "RSA-OAEP",
    hash: "SHA-1",
    length: 256,
  },
  "RSA-OAEP-256": {
    name: "RSA-OAEP",
    hash: "SHA-256",
    length: 256,
  },
  "RSA-OAEP-384": {
    name: "RSA-OAEP",
    hash: "SHA-384",
    length: 384,
  },
  "RSA-OAEP-512": {
    name: "RSA-OAEP",
    hash: "SHA-512",
    length: 512,
  },
} as const);

/**
 * Supported key wrapping algorithms
 */
export const JWE_KEY_WRAPPING = /* @__PURE__ */ Object.freeze({
  ...JWE_KEY_WRAPPING_PBES2,
  ...JWE_KEY_WRAPPING_RSA,
});

/**
 * Supported content encryption algorithms
 */
export const JWE_CONTENT_ENCRYPTION_ALGORITHMS = /* @__PURE__ */ Object.freeze({
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
} as const);

export const JOSE_ALGORITHMS = /* @__PURE__ */ Object.freeze({
  ...JWS_ALGORITHMS,
  ...JWE_KEY_WRAPPING,
  ...JWE_CONTENT_ENCRYPTION_ALGORITHMS,
});
