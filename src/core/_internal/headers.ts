import { safeJsonParse } from "unsecure/sanitize";
import { base64UrlParse } from "../../utils/base64.ts";
import type {
  JWTClaimValidationOptions,
  JWEHeaderParameters,
  JWSProtectedHeader,
} from "../types/index.ts";
import type { JWTErrorCode } from "../../error.ts";
import { JWTError } from "../../error.ts";
import { assertPlainObject, isPlainObject, isPublicJWK } from "../../utils/guards.ts";
import { assertCritShape } from "./jwt.ts";
import { assertClaimValidationOptions, assertStringList } from "../../utils/jwt.ts";

/** Serializes a protected header as JSON. A header `JSON.stringify` rejects is `ERR_INVALID_OPTION`. */
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

/** RFC 7515 §4.1.11 and RFC 7516 §4.1.13: each `crit` entry names a member of the header, else `ERR_INVALID_OPTION`. */
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

/** Refuses `crit` (RFC 7515 §4.1.11, RFC 7516 §4.1.13) and JWS `b64` (RFC 7797 §3) outside the protected header. */
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
 * RFC 7515 §4.1.3 and RFC 7516 §4.1.5: a `jwk` header holds a public JWK only.
 * `epk` (RFC 7518 §4.6.1.1) is refused: the producer writes it from `ecdh.ephemeralKey`.
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

/** RFC 7800 §3.2: a `cnf.jwk` confirmation key is a public JWK, else `ERR_JWT_CLAIM_INVALID`. */
export function assertProducerConfirmation(payload: unknown): void {
  if (typeof payload !== "object" || payload === null) return;
  const cnf: unknown = Reflect.get(payload, "cnf");
  if (typeof cnf !== "object" || cnf === null || !Object.hasOwn(cnf, "jwk")) return;
  if (!isPublicJWK(Reflect.get(cnf, "jwk"))) {
    throw new JWTError('Invalid JWT "cnf": "jwk" must be a public JWK.', "ERR_JWT_CLAIM_INVALID");
  }
}

/** Asserts that an options entry and each member listed in `objects` are plain objects. */
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

/** Refuses empty or malformed consumer options with `ERR_INVALID_OPTION` instead of skipping the check. */
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

/** RFC 7515 §7.2.1 and RFC 7516 §7.2.1: an entry is an object, its `objects` members objects and its `strings` members strings. */
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

/** RFC 7515 §4.1.9: matches `typ` case-insensitively, with an optional `application/` prefix. */
export function typMatches(expected: string, actual: unknown): boolean {
  if (typeof actual !== "string") return false;
  return normalizeTyp(expected) === normalizeTyp(actual);
}

/** RFC 7515 §4.1.9 and RFC 7516 §4.1.11: an expected `typ` is matched against the protected header only. */
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

/** Decodes a protected header. An absent header is `{}` (RFC 7515 §7.2, RFC 7516 §7.2.1). */
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

/** Strictly decodes a base64url segment (RFC 7515 §2). A failure is `ERR_{family}_INVALID`. */
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
