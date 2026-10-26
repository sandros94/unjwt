import type { KeyManagementAlgorithm } from "../../types/jwk.ts";
import type {
  JWEEncryptJWK,
  JWEHeaderParameters,
  JWEGeneralSerialization,
  JWEGeneralRecipient,
  JWEFlattenedSerialization,
  JWEMultiRecipient,
} from "../../types/jwe.ts";
import { JWTError } from "../../../error.ts";
import { isContentEncryptionAlgorithm } from "../../../utils/algorithms.ts";
import { isJWK } from "../../../utils/guards.ts";
import { JWE_DIRECT_ALGS, assertJWEAlgSupported } from "./algorithms.ts";
import { assertSerializationObject } from "../../_internal/headers.ts";
import { copyJsonObject } from "../../_internal/errors.ts";

export function _resolveRecipientAlg(key: JWEEncryptJWK, index: number): KeyManagementAlgorithm {
  if (!isJWK(key)) {
    throw new JWTError(`Recipient[${index}] key is not a JWK.`, "ERR_JWE_RECIPIENT_ALG_INFERENCE");
  }
  const declared = key.alg;
  if (!declared) {
    throw new JWTError(
      `Cannot infer "alg" for recipient[${index}]: the JWK has no "alg" property.`,
      "ERR_JWE_RECIPIENT_ALG_INFERENCE",
    );
  }
  // An `oct` JWK declaring a content encryption algorithm is a CEK, i.e. `dir`.
  const alg = key.kty === "oct" && isContentEncryptionAlgorithm(declared) ? "dir" : declared;
  if (JWE_DIRECT_ALGS.has(alg)) {
    throw new JWTError(
      `Recipient[${index}] "${alg}" allows a single recipient, use encrypt().`,
      "ERR_JWE_ALG_FORBIDDEN_IN_MULTI",
    );
  }
  assertJWEAlgSupported(alg);
  return alg;
}

export function _buildPerRecipientHeader(
  recipient: JWEMultiRecipient,
  alg: KeyManagementAlgorithm,
  keyMgmtOut: JWEHeaderParameters | undefined,
): JWEHeaderParameters {
  const header = {} as JWEHeaderParameters;
  if (recipient.key.kid) header.kid = recipient.key.kid;
  const userHeader = copyJsonObject(recipient.header, {
    code: "ERR_INVALID_OPTION",
    message: 'A recipient "header" must hold only JSON values.',
  });
  if (userHeader) Object.assign(header, userHeader);
  if (keyMgmtOut) Object.assign(header, keyMgmtOut);
  header.alg = alg;
  return header;
}

/** RFC 7516 §7.2.1: the protected, shared unprotected and per-recipient headers are disjoint. */
export function _assertDisjointHeaders(
  protectedHeader: Record<string, unknown> | undefined,
  sharedUnprotected: Record<string, unknown> | undefined,
  recipientHeader: Record<string, unknown> | undefined,
): void {
  const seen = new Set<string>();
  const check = (obj: Record<string, unknown> | undefined) => {
    if (!obj) return;
    for (const k of Object.keys(obj)) {
      if (seen.has(k)) {
        throw new JWTError(
          `Invalid JWE: header parameter "${k}" is set in more than one header.`,
          "ERR_JWE_HEADER_PARAMS_NOT_DISJOINT",
        );
      }
      seen.add(k);
    }
  };
  check(protectedHeader);
  check(sharedUnprotected);
  check(recipientHeader);
}

export function _mergeHeaders(
  protectedHeader: JWEHeaderParameters,
  sharedUnprotected: JWEHeaderParameters | undefined,
  recipientHeader: JWEHeaderParameters | undefined,
): JWEHeaderParameters {
  const merged: JWEHeaderParameters = { ...protectedHeader };
  if (sharedUnprotected) Object.assign(merged, sharedUnprotected);
  if (recipientHeader) Object.assign(merged, recipientHeader);
  return merged;
}

export function _normalizeSerialization(
  input: JWEGeneralSerialization | JWEFlattenedSerialization,
): JWEGeneralSerialization {
  assertSerializationObject(input, "JWE");

  // RFC 7516 §7.2: only `recipients` tells General from Flattened. The two forms never mix.
  if ("recipients" in input) {
    if ("encrypted_key" in input || "header" in input) {
      throw new JWTError(
        'Invalid JWE JSON Serialization: "recipients" excludes top-level "header" and "encrypted_key".',
        "ERR_JWE_INVALID_SERIALIZATION",
      );
    }
    return input;
  }

  const flattened = input;
  const recipient: JWEGeneralRecipient = {};
  if (flattened.header !== undefined) recipient.header = flattened.header;
  if (flattened.encrypted_key !== undefined) recipient.encrypted_key = flattened.encrypted_key;
  const general: JWEGeneralSerialization = {
    recipients: [recipient],
    iv: flattened.iv,
    ciphertext: flattened.ciphertext,
    tag: flattened.tag,
  };
  if (flattened.protected !== undefined) general.protected = flattened.protected;
  if (flattened.unprotected !== undefined) general.unprotected = flattened.unprotected;
  if (flattened.aad !== undefined) general.aad = flattened.aad;
  return general;
}

/** RFC 7516 §7.2.1: the JWE AAD is octets, given as bytes or as text to UTF-8 encode. */
export function _assertAADOption(aad: unknown): void {
  if (aad === undefined || typeof aad === "string" || aad instanceof Uint8Array) return;
  throw new JWTError('"aad" must be a string or a Uint8Array.', "ERR_INVALID_OPTION");
}
