import { safeJsonParse } from "unsecure/sanitize";
import { textEncoder } from "unsecure/utils";
import { base64UrlParse } from "./utils/base64.ts";

import type {
  JWK,
  ContentEncryptionAlgorithm,
  JWEEncryptOptions,
  JWEKeyManagementHeaderParameters,
  JWK_EC_Public,
  JWK_EC_Private,
  JWK_OKP_Public,
  JWK_OKP_Private,
  JOSELimits,
  JWTClaimValidationOptions,
  JWTClaims,
  JWSAlgorithm,
  JWKAlgorithm,
  JWK_RSA_SIGN,
  JWK_RSA_PSS,
  JOSEPayloadMode,
  JWEHeaderParameters,
  JWSProtectedHeader,
  PayloadOf,
  KeyManagementAlgorithm,
  UnwrapKeyOptions,
} from "./types/index.ts";
import type { JWTErrorCode } from "./error.ts";
import { JWTError } from "./error.ts";
import { cryptoKeyCurve, jwsHashOf, modulusLengthOf } from "./_crypto/_key-algorithm.ts";
import {
  inferJWEAllowedAlgorithms,
  inferJWSAllowedAlgorithms,
  isContentEncryptionAlgorithm,
  isECDHESAlgorithm,
  isEd25519Signature,
  isJWSAlgorithm,
  isKeyManagementAlgorithm,
  isPBES2Algorithm,
} from "./utils/algorithms.ts";
import { quoteTokenValue } from "./utils/_text.ts";
import {
  assertPlainObject,
  isCryptoKey,
  isCryptoKeyPair,
  isJWK,
  isJWKSet,
  isPlainObject,
  isPublicJWK,
} from "./utils/guards.ts";
import { assertCritShape, parsePayloadBytes, parsePayloadSegment } from "./_jwt-internal.ts";
import { assertClaimValidationOptions, assertStringList, validateJwtClaims } from "./utils/jwt.ts";
import {
  DEFAULT_PBES2_ITERATIONS,
  assertOctKeyLength,
  assertPBES2Iterations,
  bitLengthCEK,
  bitLengthIV,
  bitLengthTag,
} from "./_crypto/index.ts";

/** RFC 7518 §4.6.1.2 / §4.6.1.3 — size bound on `apu` / `apv`. */
export const MAX_PARTY_INFO_BYTES = 1024;

export { DEFAULT_PBES2_ITERATIONS };

/**
 * Default per-call work limits: 16 signatures, 16 recipients, 8 JWK Set candidates,
 * and PBKDF2 iterations for four default-cost PBES2 attempts in total.
 */
export const DEFAULT_JOSE_LIMITS: Readonly<Required<JOSELimits>> = /* @__PURE__ */ Object.freeze({
  signatures: 16,
  recipients: 16,
  keyCandidates: 8,
  pbes2Iterations: 4 * DEFAULT_PBES2_ITERATIONS,
});

/** Read one limit or its default; a malformed value is `ERR_INVALID_OPTION`. */
export function resolveLimit(limits: JOSELimits | undefined, name: keyof JOSELimits): number {
  const value = limits?.[name];
  if (value === undefined) return DEFAULT_JOSE_LIMITS[name];
  if (typeof value !== "number" || !Number.isInteger(value) || value < 1) {
    throw new JWTError(`"limits.${name}" must be a positive integer.`, "ERR_INVALID_OPTION");
  }
  return value;
}

/** RFC 7515 §7.2.1 / RFC 7516 §7.2.1 — bound the signatures / recipients count. */
export function assertEntryLimit(
  count: number,
  limit: number,
  options: { family: "JWS" | "JWE"; what: "signatures" | "recipients" },
): void {
  if (count <= limit) return;
  throw new JWTError(
    `Invalid ${options.family}: ${count} ${options.what} exceed the limit of ${limit}.`,
    `ERR_${options.family}_INVALID`,
  );
}

export function assertCandidateLimit(count: number, limit: number): void {
  if (count <= limit) return;
  throw new JWTError(
    `${count} candidate keys exceed the limit of ${limit}, narrow them with a "kid".`,
    "ERR_JWK_KEY_NOT_FOUND",
  );
}

/** Refuse an empty or over-limit JWK Set candidate list with `ERR_JWK_KEY_NOT_FOUND`. */
export function assertJWKSetCandidates(
  candidates: readonly unknown[],
  options: { limit: number; kid: unknown },
): void {
  if (candidates.length === 0) {
    const { kid } = options;
    throw new JWTError(
      `No key found in JWK Set${kid ? ` with kid ${quoteTokenValue(kid)}` : ""}.`,
      "ERR_JWK_KEY_NOT_FOUND",
    );
  }
  assertCandidateLimit(candidates.length, options.limit);
}

/** PBKDF2 iterations one call may still spend, summed over every PBES2 attempt. */
export interface PBES2Budget {
  /** Charge one PBES2 attempt's `p2c`; throws without charging when out of bounds or over budget. */
  spend(attempt: Pick<UnwrapKeyOptions, "alg" | "p2c" | "minIterations" | "maxIterations">): void;
}

export function createPBES2Budget(limit: number): PBES2Budget {
  let remaining = limit;
  return {
    spend(attempt) {
      const { alg, p2c } = attempt;
      if (!alg.startsWith("PBES2")) return;
      // A non-positive `p2c` is rejected by the PBES2 primitive itself.
      if (typeof p2c !== "number" || !(p2c > 0)) return;
      assertPBES2Iterations(p2c, attempt);
      if (p2c > remaining) {
        throw new JWTError(`PBES2 iteration budget of ${limit} exhausted.`, "ERR_JWE_INVALID");
      }
      remaining -= p2c;
    },
  };
}

/** A header with no JSON form is `ERR_INVALID_OPTION`. */
export function serializeProtectedHeader(header: object): string {
  try {
    return JSON.stringify(header);
  } catch (error) {
    throw new JWTError(
      "The protected header is not JSON-serializable.",
      "ERR_INVALID_OPTION",
      error,
    );
  }
}

/** RFC 7515 §4.1.11 / RFC 7516 §4.1.13 — each `crit` entry is a parameter the header carries. */
export function assertProducerCrit(header: Record<string, unknown>, family: "JWS" | "JWE"): void {
  const crit = header.crit;
  if (crit === undefined) return;
  assertCritShape(crit, { family, code: "ERR_INVALID_OPTION" });
  for (const param of crit) {
    if (Object.hasOwn(header, param)) continue;
    throw new JWTError(
      `"crit" lists "${param}", which the protected header does not carry.`,
      "ERR_INVALID_OPTION",
    );
  }
}

const PROTECTED_ONLY_PARAMS = {
  JWS: ["crit", "b64"],
  JWE: ["crit"],
} as const;

/** Refuse `crit` (RFC 7515 §4.1.11 / RFC 7516 §4.1.13) and JWS `b64` (RFC 7797 §3) outside the protected header. */
export function assertProtectedOnlyOption(
  header: object | undefined,
  options: { tier: string; family: "JWS" | "JWE" },
): void {
  if (!header) return;
  const { tier, family } = options;
  for (const param of PROTECTED_ONLY_PARAMS[family]) {
    if (!Object.hasOwn(header, param)) continue;
    throw new JWTError(
      `${family} "${param}" must be in the protected header, not the ${tier} header.`,
      "ERR_INVALID_OPTION",
    );
  }
}

/**
 * RFC 7515 §4.1.3 / RFC 7516 §4.1.5: a `jwk` header carries the public key alone; `epk`
 * (RFC 7518 §4.6.1.1) is key-agreement output the producer writes itself.
 */
export function assertProducerKeyHeaders(
  header: object | undefined,
  options: { tier: string; family: "JWS" | "JWE" },
): void {
  if (!header) return;
  const { tier, family } = options;
  if (Object.hasOwn(header, "jwk") && !isPublicJWK(Reflect.get(header, "jwk"))) {
    throw new JWTError(
      `${family} "jwk" in the ${tier} header must be a public JWK.`,
      "ERR_INVALID_OPTION",
    );
  }
  if (Object.hasOwn(header, "epk")) {
    throw new JWTError(
      `${family} "epk" is not a header option, use "ecdh.ephemeralKey".`,
      "ERR_INVALID_OPTION",
    );
  }
}

/** RFC 7800 §3.2: a `cnf.jwk` confirmation key is a public JWK, never private material or a secret. */
export function assertProducerConfirmation(payload: unknown): void {
  if (typeof payload !== "object" || payload === null) return;
  const cnf: unknown = Reflect.get(payload, "cnf");
  if (typeof cnf !== "object" || cnf === null || !Object.hasOwn(cnf, "jwk")) return;
  if (!isPublicJWK(Reflect.get(cnf, "jwk"))) {
    throw new JWTError('Invalid JWT "cnf": "jwk" must be a public JWK.', "ERR_JWT_CLAIM_INVALID");
  }
}

/** Assert an options entry and each member listed in `objects` are plain objects. */
export function assertOptionEntry(
  entry: unknown,
  options: { label: string; objects: readonly string[] },
): void {
  const { label, objects } = options;
  assertPlainObject(entry, label);
  for (const member of objects) {
    if (entry[member] !== undefined) assertPlainObject(entry[member], `${label}.${member}`);
  }
}

/** RFC 7518 §4.6.1.2 / §4.6.1.3 — `apu` / `apv` are bytes within `MAX_PARTY_INFO_BYTES`. */
export function assertProducerPartyInfo(name: "apu" | "apv", value: unknown): void {
  if (!(value instanceof Uint8Array)) {
    throw new JWTError(
      `"${name === "apu" ? "partyUInfo" : "partyVInfo"}" (${name}) must be a Uint8Array.`,
      "ERR_INVALID_OPTION",
    );
  }
  if (value.length > MAX_PARTY_INFO_BYTES) {
    throw new JWTError(
      `"${name === "apu" ? "partyUInfo" : "partyVInfo"}" (${name}) must not exceed ${MAX_PARTY_INFO_BYTES} bytes (got ${value.length}).`,
      "ERR_INVALID_OPTION",
    );
  }
}

/** RFC 7518 §5 — the CEK size is fixed by `enc`. */
export function assertProducerCEK(
  cek: Uint8Array<ArrayBuffer> | undefined,
  enc: ContentEncryptionAlgorithm,
): void {
  if (cek === undefined) return;
  const expected = bitLengthCEK(enc) >> 3;
  if (!(cek instanceof Uint8Array) || cek.length !== expected) {
    throw new JWTError(`"cek" must be ${expected} bytes for ${enc}.`, "ERR_INVALID_OPTION");
  }
}

/** RFC 7518 §5.2 / §5.3 — the content IV length is fixed by `enc`. */
export function assertProducerIV(
  iv: Uint8Array<ArrayBuffer> | undefined,
  enc: ContentEncryptionAlgorithm,
): void {
  if (iv === undefined) return;
  const expected = bitLengthIV(enc) >> 3;
  if (!(iv instanceof Uint8Array) || iv.length !== expected) {
    throw new JWTError(
      `"contentEncryptionIV" must be ${expected} bytes for ${enc}.`,
      "ERR_INVALID_OPTION",
    );
  }
}

/** Refuse present-but-empty or malformed consumer options rather than reading them as "no check". */
export function assertConsumerOptions(
  options: JWTClaimValidationOptions & {
    algorithms?: readonly string[];
    encryptionAlgorithms?: readonly string[];
  },
): void {
  assertOptionEntry(options, { label: "options", objects: ["limits"] });
  const typ: unknown = options.typ;
  if (typ !== undefined && (typeof typ !== "string" || typ === "")) {
    throw new JWTError('"typ" must be a non-empty string.', "ERR_INVALID_OPTION");
  }
  assertStringList(options.algorithms, "algorithms");
  assertStringList(options.encryptionAlgorithms, "encryptionAlgorithms");
  assertStringList(options.recognizedHeaders, "recognizedHeaders");
  assertClaimValidationOptions(options);
}

export type JWKSetOperation = "sig" | "enc";

/** RFC 7517 §4.3 — `key_ops` values that serve each operation. */
const JWK_SET_KEY_OPS: Readonly<Record<JWKSetOperation, readonly string[]>> =
  /* @__PURE__ */ Object.freeze({
    sig: ["verify"],
    enc: ["unwrapKey", "decrypt", "deriveBits", "deriveKey"],
  });

/** JWK Set candidate filter by `kid`/`alg`/`use`/`key_ops`; `oct` entries only with `allowSymmetric`. */
export function buildJWKSetFilter(
  header: { kid?: string; alg?: JWKAlgorithm } | undefined,
  options: { op: JWKSetOperation; allowSymmetric?: boolean },
): (k: JWK) => boolean {
  const kid = header?.kid;
  const alg = header?.alg;
  const { op, allowSymmetric } = options;
  const use = op;
  const keyOps = JWK_SET_KEY_OPS[op];
  return (k) => {
    if (!isJWK(k)) return false;
    if (k.kty === "oct" && !allowSymmetric) return false;
    if (kid && k.kid !== kid) return false;
    if (k.alg && k.alg !== alg) return false;
    if (k.use !== undefined && k.use !== use) return false;
    const ops = k.key_ops;
    if (ops !== undefined && !(Array.isArray(ops) && ops.some((o) => keyOps.includes(o)))) {
      return false;
    }
    return true;
  };
}

/** Normalize a caller's ECDH-ES ephemeral key into `{ epk, epkPrivateKey }`. */
export function parseEphemeralKey(
  ephemeralKey: NonNullable<JWEEncryptOptions["ecdh"]>["ephemeralKey"],
): {
  epk: CryptoKey | JWK_EC_Public | JWK_OKP_Public;
  epkPrivateKey: CryptoKey | JWK_EC_Private | JWK_OKP_Private;
} {
  if (isCryptoKeyPair(ephemeralKey)) {
    return { epk: ephemeralKey.publicKey, epkPrivateKey: ephemeralKey.privateKey };
  }
  if (
    typeof ephemeralKey === "object" &&
    ephemeralKey !== null &&
    "publicKey" in ephemeralKey &&
    "privateKey" in ephemeralKey
  ) {
    if (!ephemeralKey.publicKey || !ephemeralKey.privateKey) {
      throw new JWTError(
        "ECDH-ES custom ephemeral key must include both publicKey and privateKey.",
        "ERR_JWK_INVALID",
      );
    }
    return { epk: ephemeralKey.publicKey, epkPrivateKey: ephemeralKey.privateKey };
  }
  if (isCryptoKey(ephemeralKey)) {
    if (ephemeralKey.type !== "private") {
      throw new JWTError(
        "ECDH-ES custom ephemeral CryptoKey must include private key material.",
        "ERR_JWK_INVALID",
      );
    }
    return { epk: ephemeralKey, epkPrivateKey: ephemeralKey };
  }
  if (isJWK(ephemeralKey)) {
    if (!("d" in ephemeralKey) || typeof ephemeralKey.d !== "string") {
      throw new JWTError(
        'ECDH-ES custom ephemeral JWK must include private parameter "d".',
        "ERR_JWK_INVALID",
      );
    }
    return {
      epk: ephemeralKey,
      epkPrivateKey: ephemeralKey,
    };
  }
  throw new JWTError("Unsupported ECDH-ES ephemeral key material provided.", "ERR_JWK_INVALID");
}

/** RFC 7518 §4.6.1.2 / §4.6.1.3 — ECDH-ES agreement params; an empty `apu` / `apv` is omitted. */
export function buildECDHAgreementParams(
  ecdh: JWEEncryptOptions["ecdh"],
): Pick<JWEKeyManagementHeaderParameters, "apu" | "apv" | "epk" | "epkPrivateKey"> {
  const params: Pick<JWEKeyManagementHeaderParameters, "apu" | "apv" | "epk" | "epkPrivateKey"> =
    {};
  if (!ecdh) return params;
  const { partyUInfo, partyVInfo, ephemeralKey } = ecdh;
  if (partyUInfo !== undefined) {
    assertProducerPartyInfo("apu", partyUInfo);
    if (partyUInfo.length > 0) params.apu = partyUInfo;
  }
  if (partyVInfo !== undefined) {
    assertProducerPartyInfo("apv", partyVInfo);
    if (partyVInfo.length > 0) params.apv = partyVInfo;
  }
  if (ephemeralKey) {
    const { epk, epkPrivateKey } = parseEphemeralKey(ephemeralKey);
    params.epk = epk;
    params.epkPrivateKey = epkPrivateKey;
  }
  return params;
}

/** Bytes become an HMAC key (`HS*` only); RSA needs `modulusLength ≥ 2048` (RFC 7518 §3.3 / §3.5). */
export async function resolveSigningKey(
  alg: JWSAlgorithm,
  key: CryptoKey | Uint8Array<ArrayBuffer>,
  usage: "sign" | "verify",
): Promise<CryptoKey> {
  if (key instanceof Uint8Array) {
    if (alg !== "HS256" && alg !== "HS384" && alg !== "HS512") {
      throw new JWTError(`${alg} needs an asymmetric key, not raw bytes.`, "ERR_JWK_INVALID");
    }
    assertOctKeyLength(key, alg);
    return crypto.subtle.importKey("raw", key, { name: "HMAC", hash: jwsHashOf(alg) }, false, [
      usage,
    ]);
  }
  if (RSA_SIGNATURE_ALGORITHMS.has(alg)) {
    const modulusLength = modulusLengthOf(key.algorithm);
    if (typeof modulusLength !== "number" || modulusLength < 2048) {
      throw new JWTError(
        `${alg} requires a key modulusLength of at least 2048 bits`,
        "ERR_JWK_INVALID",
      );
    }
  }
  return key;
}

/** Validate JWT claims of a `"json"` payload unless `validateClaims: false`. */
export function validateClaimsIfJson(
  payload: unknown,
  mode: JOSEPayloadMode,
  options: JWTClaimValidationOptions & { validateClaims?: boolean },
): void {
  if (mode !== "json" || options.validateClaims === false) return;
  // oxlint-disable-next-line typescript/no-unsafe-type-assertion -- validateJwtClaims checks each claim it reads
  validateJwtClaims(payload as JWTClaims, options);
}

const PAYLOAD_MODES: ReadonlySet<string> = /* @__PURE__ */ new Set([
  "json",
  "string",
  "bytes",
] satisfies JOSEPayloadMode[]);

/** Resolve the payload mode from `payload` / deprecated `forceUint8Array`; contradictions are `ERR_INVALID_OPTION`. */
export function resolvePayloadMode(options: {
  payload?: JOSEPayloadMode;
  forceUint8Array?: boolean;
  validateClaims?: boolean;
}): JOSEPayloadMode {
  const { payload, forceUint8Array, validateClaims } = options;

  if (payload !== undefined && !PAYLOAD_MODES.has(payload)) {
    throw new JWTError('"payload" must be "json", "string" or "bytes".', "ERR_INVALID_OPTION");
  }

  let mode: JOSEPayloadMode = payload ?? "json";
  if (forceUint8Array !== undefined) {
    if (payload === undefined) {
      mode = forceUint8Array ? "bytes" : "json";
    } else if (forceUint8Array !== (payload === "bytes")) {
      throw new JWTError(
        '"forceUint8Array" contradicts "payload", pass "payload" alone.',
        "ERR_INVALID_OPTION",
      );
    }
  }

  if (validateClaims === true && mode !== "json") {
    throw new JWTError('"validateClaims" requires payload: "json".', "ERR_INVALID_OPTION");
  }

  return mode;
}

export function stringKeyError(): JWTError {
  return new JWTError(
    "Key must be a JWK, CryptoKey or Uint8Array, not a string.",
    "ERR_JWK_INVALID",
  );
}

export function assertNotStringKey<K>(key: K): asserts key is Exclude<K, string> {
  if (typeof key === "string") throw stringKeyError();
}

/** RFC 7518 §4.8.1 — a string key is a UTF-8 PBES2 password, refused under any other `alg`. */
export function resolvePasswordKey<K>(
  alg: KeyManagementAlgorithm,
  key: K | string,
): K | Uint8Array<ArrayBuffer> {
  if (typeof key !== "string") return key;
  if (!isPBES2Algorithm(alg)) throw stringKeyError();
  return textEncoder.encode(key);
}

export interface AlgCheckContext {
  infer: (
    key: unknown,
    options?: { allowSymmetric?: boolean },
  ) => readonly JWKAlgorithm[] | undefined;
  /** An `oct` JWK's `alg` names a role, not the header `alg` (JWE). */
  octRoles: boolean;
  errorCode: "ERR_JWS_ALG_NOT_ALLOWED" | "ERR_JWE_ALG_NOT_ALLOWED";
  label: string;
  op: JWKSetOperation;
}

export const JWS_ALG_CTX: AlgCheckContext = /* @__PURE__ */ Object.freeze({
  infer: inferJWSAllowedAlgorithms,
  octRoles: false,
  errorCode: "ERR_JWS_ALG_NOT_ALLOWED",
  label: "Algorithm",
  op: "sig",
});

export const JWE_ALG_CTX: AlgCheckContext = /* @__PURE__ */ Object.freeze({
  infer: inferJWEAllowedAlgorithms,
  octRoles: true,
  errorCode: "ERR_JWE_ALG_NOT_ALLOWED",
  label: "Key management algorithm",
  op: "enc",
});

/** Check the header `alg` against the allowlist, else the JWK's own `alg`, else the key-shape inference. */
export function checkAlgAllowed<A extends JWKAlgorithm>(
  alg: A,
  key: unknown,
  options: {
    ctx: AlgCheckContext;
    algorithms?: readonly A[];
    allowSymmetric?: boolean;
  },
): JWTError | undefined {
  const { ctx, algorithms, allowSymmetric } = options;
  if (algorithms !== undefined) {
    return algorithms.includes(alg) ? undefined : notAllowed(alg, ctx);
  }
  if (isJWK(key) && typeof key.alg === "string" && (!ctx.octRoles || key.kty !== "oct")) {
    const served = key.alg === alg || (isEd25519Signature(key.alg) && isEd25519Signature(alg));
    return served ? undefined : notAllowed(alg, ctx);
  }
  const inferred = ctx.infer(key, { allowSymmetric });
  if (!inferred) {
    return new JWTError(
      'Cannot infer allowed algorithms from this key, pass "algorithms".',
      ctx.errorCode,
    );
  }
  return inferred.includes(alg) ? undefined : notAllowed(alg, ctx);
}

function notAllowed(alg: JWKAlgorithm, ctx: AlgCheckContext): JWTError {
  return new JWTError(`${ctx.label} not allowed: ${alg}`, ctx.errorCode);
}

/** Whether key material could be the one the header was produced for (RFC 7515 §4.1.4 / RFC 7516 §4.1.6 `kid` hint). */
export function keyMatchesHeader(
  header: { alg?: JWKAlgorithm; kid?: string; epk?: { crv?: string } },
  keyMaterial: unknown,
  options: { ctx: AlgCheckContext; allowSymmetric?: boolean },
): boolean {
  const { ctx, allowSymmetric } = options;
  if (isJWKSet(keyMaterial)) {
    const candidates = keyMaterial.keys.filter(
      buildJWKSetFilter(header, { op: ctx.op, allowSymmetric }),
    );
    return candidates.length === 0 || candidates.some((k) => keyServesHeaderAlg(header, k, ctx));
  }
  if (isJWK(keyMaterial)) return keyServesHeaderAlg(header, keyMaterial, ctx);
  if (isCryptoKey(keyMaterial)) return keyServesHeaderAlg(header, keyMaterial, ctx);
  return true;
}

/** Reject `"none"` (RFC 7518 §3.6) and any `alg` outside `JWSAlgorithm`. */
export function assertJWSAlgSupported(alg: string): asserts alg is JWSAlgorithm {
  const error = checkJWSAlgSupported(alg);
  if (error) throw error;
}

export function checkJWSAlgSupported(alg: string): JWTError | undefined {
  return checkAlgSupported(alg, {
    supported: isJWSAlgorithm,
    code: "ERR_JWS_ALG_NOT_ALLOWED",
    label: "Algorithm",
    role: "signing algorithm",
  });
}

/** RFC 7797 §3 / §6 — `b64` is a boolean, and `b64: false` must be listed in `crit`. */
export function checkJWSB64(header: { b64?: unknown; crit?: unknown }): JWTError | undefined {
  if (Object.hasOwn(header, "b64") && typeof header.b64 !== "boolean") {
    return new JWTError('Invalid JWS: "b64" must be a boolean.', "ERR_JWS_INVALID");
  }
  if (header.b64 !== false) return undefined;
  if (Array.isArray(header.crit) && header.crit.includes("b64")) return undefined;
  return new JWTError('Invalid JWS: "b64" must be listed in "crit".', "ERR_JWS_INVALID");
}

/** RFC 7797 §3 — a caller's `b64` is a boolean. */
export function assertB64Option(header: { b64?: unknown } | undefined): void {
  if (!header || !Object.hasOwn(header, "b64") || typeof header.b64 === "boolean") return;
  throw new JWTError('"b64" must be a boolean.', "ERR_INVALID_OPTION");
}

/** Drop a default `b64: true` unless `crit` lists it; list `b64: false` in `crit` (RFC 7797 §3 / §6). */
export function applyB64Header(header: { b64?: boolean; crit?: string[] }): void {
  assertB64Option(header);
  if (header.b64 === true) {
    if (!(Array.isArray(header.crit) && header.crit.includes("b64"))) delete header.b64;
    return;
  }
  if (header.b64 !== false) return;
  const crit = header.crit;
  if (crit === undefined) header.crit = ["b64"];
  else if (Array.isArray(crit) && !crit.includes("b64")) header.crit = [...crit, "b64"];
}

export function assertCompactToken(token: unknown, family: "JWS" | "JWE"): asserts token is string {
  if (typeof token !== "string") {
    throw new JWTError(`Invalid ${family}: token must be a string.`, `ERR_${family}_INVALID`);
  }
}

export function assertSerializationObject(
  value: unknown,
  family: "JWS" | "JWE",
): asserts value is object {
  if (!isPlainObject(value)) {
    throw new JWTError(
      `Invalid ${family} JSON Serialization: expected an object.`,
      `ERR_${family}_INVALID_SERIALIZATION`,
    );
  }
}

/** RFC 7515 §7.2.1 / RFC 7516 §7.2.1 — an entry is an object with object `objects` and string `strings` members. */
export function checkSerializationEntry(
  entry: unknown,
  options: {
    family: "JWS" | "JWE";
    label: string;
    objects: readonly string[];
    strings: readonly string[];
  },
): JWTError | undefined {
  const { family, label, objects, strings } = options;
  const code = `ERR_${family}_INVALID` as JWTErrorCode;
  if (!isPlainObject(entry)) {
    return new JWTError(`Invalid ${family}: ${label} must be a JSON object.`, code);
  }
  for (const member of objects) {
    if (entry[member] !== undefined && !isPlainObject(entry[member])) {
      return new JWTError(`Invalid ${family}: ${label} "${member}" must be a JSON object.`, code);
    }
  }
  for (const member of strings) {
    if (entry[member] !== undefined && typeof entry[member] !== "string") {
      return new JWTError(`Invalid ${family}: ${label} "${member}" must be a string.`, code);
    }
  }
  return undefined;
}

/** Wrap a non-`JWTError` thrown by a key lookup as `ERR_JWK_KEY_NOT_FOUND`. */
export function asKeyLookupError(error: unknown, what: string): JWTError {
  return asJWTError(error, {
    code: "ERR_JWK_KEY_NOT_FOUND",
    message: `Key lookup failed for ${what}.`,
  });
}

/** Pass a `JWTError` through; wrap anything else under `message` / `code` with it as `cause`. */
export function asJWTError(
  error: unknown,
  options: { code: JWTErrorCode; message: string },
): JWTError {
  if (error instanceof JWTError) return error;
  return new JWTError(options.message, options.code, error);
}

/** RFC 7516 §11.5 — a failed unwrap or decryption says only that it failed. */
export function asDecryptionError(error: unknown): JWTError {
  return asJWTError(error, {
    code: "ERR_JWE_DECRYPTION_FAILED",
    message: "JWE decryption failed.",
  });
}

export type ResolvedKeyInput<K> = K extends (...args: never[]) => infer R
  ? NonNullable<Awaited<R>>
  : K;

/** Run a key-lookup function; a throw or no key is `ERR_JWK_KEY_NOT_FOUND`. */
export async function resolveKeyInput<K>(
  key: K,
  options: { header: unknown; token: string; what: string },
): Promise<ResolvedKeyInput<K>>;
export async function resolveKeyInput(
  key: unknown,
  options: { header: unknown; token: string; what: string },
): Promise<unknown> {
  if (typeof key !== "function") return key;
  const { header, token, what } = options;
  let resolved: unknown;
  try {
    resolved = await key(header, token);
  } catch (error) {
    throw asKeyLookupError(error, what);
  }
  if (resolved === undefined || resolved === null) {
    throw new JWTError(`Key lookup returned no key for ${what}.`, "ERR_JWK_KEY_NOT_FOUND");
  }
  return resolved;
}

export function asKeyUsageError(error: unknown, alg: JWKAlgorithm): JWTError {
  return asJWTError(error, { code: "ERR_JWK_INVALID", message: `Key is not usable for ${alg}.` });
}

const JWE_ENC_CEK_FORMAT = /* @__PURE__ */ Object.freeze({
  "A128GCM": "cryptokey",
  "A192GCM": "cryptokey",
  "A256GCM": "cryptokey",
  "A128CBC-HS256": "raw",
  "A192CBC-HS384": "raw",
  "A256CBC-HS512": "raw",
} satisfies Record<ContentEncryptionAlgorithm, "cryptokey" | "raw">);

/** RFC 7518 §4.5 — a `dir` JWK's `alg` is `dir` or the token's `enc`. */
export function assertDirectKeyRole(
  key: unknown,
  enc: ContentEncryptionAlgorithm | undefined,
): void {
  if (!isJWK(key) || typeof key.alg !== "string" || key.alg === "dir") return;
  if (enc !== undefined && key.alg === enc) return;
  throw new JWTError(
    `JWK "alg" is "${key.alg}" but "dir" requires "dir" or the token's "enc".`,
    "ERR_JWK_INVALID",
  );
}

/** RFC 7518 §4.5 / §4.6 — algorithms that agree on the CEK directly. */
export const JWE_DIRECT_ALGS: ReadonlySet<string> = /* @__PURE__ */ new Set(["dir", "ECDH-ES"]);

/** Reject `"none"` and any key management `alg` outside the implemented set. */
export function checkJWEAlgSupported(alg: string): JWTError | undefined {
  return checkAlgSupported(alg, {
    supported: isKeyManagementAlgorithm,
    code: "ERR_JWE_ALG_NOT_ALLOWED",
    label: "Key management algorithm",
    role: "key management algorithm",
  });
}

export function checkJWEEncSupported(enc: unknown): JWTError | undefined {
  if (typeof enc === "string" && isContentEncryptionAlgorithm(enc)) return undefined;
  return new JWTError(`Invalid JWE: unsupported "enc" ${quoteTokenValue(enc)}`, "ERR_JWE_INVALID");
}

export function isJWEAlgSupported(alg: string): alg is KeyManagementAlgorithm {
  return isKeyManagementAlgorithm(alg);
}

export function assertJWEAlgSupported(alg: string): asserts alg is KeyManagementAlgorithm {
  const error = checkJWEAlgSupported(alg);
  if (error) throw error;
}

export function assertJWEEncSupported(enc: unknown): asserts enc is ContentEncryptionAlgorithm {
  const error = checkJWEEncSupported(enc);
  if (error) throw error;
}

export function checkJWEEncAllowed(
  enc: ContentEncryptionAlgorithm,
  encryptionAlgorithms: readonly ContentEncryptionAlgorithm[] | undefined,
): JWTError | undefined {
  if (encryptionAlgorithms === undefined || encryptionAlgorithms.includes(enc)) return undefined;
  return new JWTError(
    `Content encryption algorithm not allowed: ${enc}`,
    "ERR_JWE_ALG_NOT_ALLOWED",
  );
}

/** The CEK as bytes for `returnCek`; a non-extractable key is `ERR_INVALID_OPTION`. */
export async function exportReturnedCek(
  cek: CryptoKey | Uint8Array<ArrayBuffer>,
): Promise<Uint8Array<ArrayBuffer>> {
  if (!isCryptoKey(cek)) return cek;
  if (!cek.extractable) {
    throw new JWTError(
      '"returnCek" requires an extractable content encryption key.',
      "ERR_INVALID_OPTION",
    );
  }
  return new Uint8Array(await crypto.subtle.exportKey("raw", cek));
}

export function cekFormatForEnc(enc: ContentEncryptionAlgorithm): "cryptokey" | "raw" {
  return JWE_ENC_CEK_FORMAT[enc];
}

/** One recipient's unwrap options; header parameters it lacks are left off, not `undefined`. */
export function buildUnwrapKeyOptions(
  header: JWEHeaderParameters,
  algorithms: { alg: KeyManagementAlgorithm; enc: ContentEncryptionAlgorithm },
  options:
    | Pick<
        UnwrapKeyOptions,
        "keyUsage" | "unwrappedKeyAlgorithm" | "extractable" | "minIterations" | "maxIterations"
      >
    | undefined,
): UnwrapKeyOptions {
  const { alg, enc } = algorithms;
  const opts: UnwrapKeyOptions = {
    alg,
    enc,
    format: cekFormatForEnc(enc),
    keyUsage: options?.keyUsage || ["decrypt"],
  };
  if (header.iv) opts.iv = header.iv;
  if (header.tag) opts.tag = header.tag;
  if (header.p2s) opts.p2s = header.p2s;
  if (header.p2c) opts.p2c = header.p2c;
  if (header.epk) opts.epk = header.epk;
  if (header.apu) opts.apu = header.apu;
  if (header.apv) opts.apv = header.apv;
  if (options?.unwrappedKeyAlgorithm) opts.unwrappedKeyAlgorithm = options.unwrappedKeyAlgorithm;
  if (options?.extractable !== undefined) opts.extractable = options.extractable;
  if (options?.minIterations !== undefined) opts.minIterations = options.minIterations;
  if (options?.maxIterations !== undefined) opts.maxIterations = options.maxIterations;
  return opts;
}

/** RFC 7516 §5.2 step 6 — direct key agreement carries an empty encrypted key. */
export function checkJWEDirectEncryptedKey(
  alg: KeyManagementAlgorithm,
  encryptedKey: string | undefined,
): JWTError | undefined {
  if (!JWE_DIRECT_ALGS.has(alg) || !encryptedKey) return undefined;
  return new JWTError(`Invalid JWE: Encrypted key must be empty for ${alg}.`, "ERR_JWE_INVALID");
}

/** RFC 7518 §5.2 / §5.3 — the IV and authentication tag sizes are fixed by `enc`. */
export function checkJWEContentSegments(
  enc: ContentEncryptionAlgorithm,
  iv: Uint8Array<ArrayBuffer>,
  tag: Uint8Array<ArrayBuffer>,
): JWTError | undefined {
  const ivBytes = bitLengthIV(enc) >> 3;
  if (iv.length !== ivBytes) {
    return new JWTError(
      `Invalid JWE: Initialization vector must be ${ivBytes} bytes for ${enc} (got ${iv.length}).`,
      "ERR_JWE_INVALID",
    );
  }
  const tagBytes = bitLengthTag(enc) >> 3;
  if (tag.length !== tagBytes) {
    return new JWTError(
      `Invalid JWE: Authentication tag must be ${tagBytes} bytes for ${enc} (got ${tag.length}).`,
      "ERR_JWE_INVALID",
    );
  }
  return undefined;
}

/** RFC 7516 §4.1.3 — the library does not implement compression. */
export function checkJWEZip(header: object | undefined): JWTError | undefined {
  if (!header || !Object.hasOwn(header, "zip")) return undefined;
  return new JWTError("Invalid JWE: compression is not supported.", "ERR_JWE_INVALID");
}

export function assertNoZipOption(header: object | undefined, tier: string): void {
  if (!header || !Object.hasOwn(header, "zip")) return;
  throw new JWTError(
    `JWE compression ("zip") in the ${tier} header is not supported.`,
    "ERR_INVALID_OPTION",
  );
}

/** RFC 7516 §4.1.13 — `crit` is only meaningful when it is integrity protected. */
export function checkJWEUnprotectedCrit(header: object | undefined): JWTError | undefined {
  if (!header || !Object.hasOwn(header, "crit")) return undefined;
  return new JWTError('Invalid JWE: "crit" must be integrity protected.', "ERR_JWE_INVALID");
}

/** RFC 7515 §4.1.9 — case-insensitive `typ` match with an optional `application/` prefix. */
export function typMatches(expected: string, actual: unknown): boolean {
  if (typeof actual !== "string") return false;
  return normalizeTyp(expected) === normalizeTyp(actual);
}

/** RFC 7515 §4.1.9 / RFC 7516 §4.1.11 — an expected `typ` is matched against the protected header only. */
export function checkProtectedTyp(
  expected: string | undefined,
  protectedHeader: { typ?: unknown },
  options: { family: "JWS" | "JWE"; label?: string },
): JWTError | undefined {
  if (expected === undefined) return undefined;
  const actual = protectedHeader.typ;
  if (typMatches(expected, actual)) return undefined;
  const { family, label } = options;
  const where = label ? ` on ${label}` : "";
  const message =
    actual === undefined
      ? `Invalid ${family}: the protected header${where} carries no "typ", expected "${expected}".`
      : `Invalid ${family}: "typ" mismatch${where}, expected "${expected}".`;
  return new JWTError(message, `ERR_${family}_INVALID`);
}

function normalizeTyp(typ: string): string {
  const lowered = typ.toLowerCase();
  return lowered.includes("/") ? lowered : `application/${lowered}`;
}

export interface ProtectedHeaderOf {
  JWS: JWSProtectedHeader;
  JWE: JWEHeaderParameters;
}

/** Decode a protected header; absent is `{}` (RFC 7515 §7.2 / RFC 7516 §7.2.1). */
export function decodeProtectedHeader<F extends keyof ProtectedHeaderOf>(
  encoded: string | undefined,
  family: F,
): ProtectedHeaderOf[F] {
  let parsed: unknown = {};
  if (encoded) {
    try {
      parsed = safeJsonParse(base64UrlParse(encoded));
    } catch (error) {
      throw new JWTError(
        `Invalid ${family}: Protected header could not be decoded.`,
        `ERR_${family}_INVALID`,
        error,
      );
    }
    // RFC 7515 §4 / RFC 7516 §4: the header is a JSON object.
    if (!isPlainObject(parsed)) {
      throw new JWTError(
        `Invalid ${family}: Protected header must be a JSON object.`,
        `ERR_${family}_INVALID`,
      );
    }
  }
  // oxlint-disable-next-line typescript/no-unsafe-type-assertion -- each consumer checks the members it reads
  return parsed as ProtectedHeaderOf[F];
}

/** Strictly decode a base64url segment (RFC 7515 §2); failure is `ERR_{family}_INVALID`. */
export function decodeSegment(
  encoded: string,
  options: { family: "JWS" | "JWE" | "JWK"; what: string },
): Uint8Array<ArrayBuffer> {
  try {
    return base64UrlParse(encoded, { returnAs: "uint8array" });
  } catch (error) {
    throw new JWTError(
      `Invalid ${options.family}: ${options.what} could not be decoded.`,
      `ERR_${options.family}_INVALID`,
      error,
    );
  }
}

/** Decode a JWS payload segment under the payload mode, honouring `b64: false` (RFC 7797). */
export function decodeJWSPayload(
  payloadSegment: string,
  useB64: boolean,
  mode: JOSEPayloadMode,
): PayloadOf<JOSEPayloadMode> {
  if (!useB64) {
    return mode === "string"
      ? payloadSegment
      : parsePayloadBytes(textEncoder.encode(payloadSegment), {
          payload: mode,
          family: "JWS",
        });
  }
  try {
    return parsePayloadSegment(payloadSegment, {
      payload: mode,
      family: "JWS",
    });
  } catch (error) {
    if (error instanceof JWTError) throw error;
    throw new JWTError("Invalid JWS: Payload could not be decoded.", "ERR_JWS_INVALID", error);
  }
}

export function decodeJWEPayload(
  plaintext: Uint8Array<ArrayBuffer>,
  mode: JOSEPayloadMode,
): PayloadOf<JOSEPayloadMode> {
  return parsePayloadBytes(plaintext, { payload: mode, family: "JWE" });
}

function checkAlgSupported(
  alg: string,
  options: {
    supported: (alg: string) => boolean;
    code: "ERR_JWS_ALG_NOT_ALLOWED" | "ERR_JWE_ALG_NOT_ALLOWED";
    label: string;
    role: string;
  },
): JWTError | undefined {
  const { supported, code, label, role } = options;
  if (alg === "none") return new JWTError(`"none" is not a valid ${role}`, code);
  if (!supported(alg)) {
    return new JWTError(`${label} not supported: ${quoteTokenValue(alg)}`, code);
  }
  return undefined;
}

function keyServesHeaderAlg(
  header: { alg?: JWKAlgorithm; epk?: { crv?: string } },
  key: JWK | CryptoKey,
  ctx: AlgCheckContext,
): boolean {
  const { alg } = header;
  if (!alg) return false;
  const inferred = ctx.infer(key);
  if (inferred && !inferred.includes(alg)) return false;
  if (!isECDHESAlgorithm(alg)) return true;
  const epkCurve = header.epk?.crv;
  const keyCurve = isCryptoKey(key) ? cryptoKeyCurve(key) : "crv" in key ? key.crv : undefined;
  return !epkCurve || !keyCurve || epkCurve === keyCurve;
}

/** RFC 7518 §3.3 / §3.5 — the signature algorithms bound to an RSA modulus. */
const RSA_SIGNATURE_ALGORITHMS: ReadonlySet<string> = /* @__PURE__ */ new Set<
  JWK_RSA_SIGN | JWK_RSA_PSS
>(["RS256", "RS384", "RS512", "PS256", "PS384", "PS512"]);
