import { base64Stringify, base64Parse } from "../utils/base64";

import { isCryptoKey } from "../utils/guards";
import { JWTError } from "../error";
import { ECDSA_CURVES, jwsHashOf, rsaOaepHashOf } from "./_key-algorithm";

export interface KeyImportOptions {
  /** `extractable` for `SubtleCrypto.importKey`; defaults to `false` for private keys, `true` otherwise. */
  extractable?: boolean;
}

export const toSPKI = (key: unknown): Promise<string> => {
  return genericExport("public", "spki", key);
};

export const toPKCS8 = (key: unknown): Promise<string> => {
  return genericExport("private", "pkcs8", key);
};

export const fromPKCS8: PEMImportFunction = (pem, alg, options?) => {
  return genericImport("PRIVATE KEY", "pkcs8", pem, alg, options);
};

export const fromSPKI: PEMImportFunction = (pem, alg, options?) => {
  return genericImport("PUBLIC KEY", "spki", pem, alg, options);
};

export const fromX509: PEMImportFunction = (pem, alg, options?) => {
  let spki: string;
  try {
    spki = getSPKI(pem);
  } catch (error_) {
    throw new JWTError("Failed to parse the X.509 certificate.", "ERR_JWK_INVALID", error_);
  }
  return fromSPKI(spki, alg, options);
};

type PEMImportFunction = (
  pem: string,
  alg: string,
  options?: KeyImportOptions,
) => Promise<CryptoKey>;

const formatPEM = (b64: string, descriptor: string) => {
  const newlined = (b64.match(/.{1,64}/g) || []).join("\n");
  return `-----BEGIN ${descriptor}-----\n${newlined}\n-----END ${descriptor}-----`;
};

/** The base64 body of the single armoured block `descriptor` names; leading text is allowed (RFC 7468 §2). */
const pemBody = (pem: string, descriptor: string): string => {
  const begin = `-----BEGIN ${descriptor}-----`;
  const end = `-----END ${descriptor}-----`;

  const start = pem.indexOf(begin);
  if (start === -1) {
    const found = pem.match(/-----BEGIN [^-]+-----/)?.[0];
    throw new JWTError(
      found
        ? `PEM label mismatch: expected "${begin}", got "${found}".`
        : `PEM label missing: expected "${begin}".`,
      "ERR_JWK_INVALID",
    );
  }

  const bodyStart = start + begin.length;
  const bodyEnd = pem.indexOf(end, bodyStart);
  if (bodyEnd === -1) {
    throw new JWTError(`PEM label missing: expected "${end}".`, "ERR_JWK_INVALID");
  }

  if (pem.includes("-----BEGIN", bodyStart) || pem.slice(bodyEnd + end.length).trim() !== "") {
    throw new JWTError(
      `PEM must contain exactly one ${descriptor} block, with nothing after it.`,
      "ERR_JWK_INVALID",
    );
  }

  return pem.slice(bodyStart, bodyEnd).replaceAll(/\s/g, "");
};

const genericExport = async (
  keyType: "private" | "public",
  keyFormat: "spki" | "pkcs8",
  key: unknown,
) => {
  if (!isCryptoKey(key)) {
    throw new JWTError(`Key must be of type CryptoKey, got ${typeof key}`, "ERR_INVALID_OPTION");
  }

  if (!key.extractable) {
    throw new JWTError("CryptoKey is not extractable", "ERR_JWK_INVALID");
  }

  if (key.type !== keyType) {
    throw new JWTError(`key is not a ${keyType} key`, "ERR_JWK_INVALID");
  }

  return formatPEM(
    base64Stringify(new Uint8Array(await crypto.subtle.exportKey(keyFormat, key))),
    `${keyType.toUpperCase()} KEY`,
  );
};

const genericImport = async (
  descriptor: "PRIVATE KEY" | "PUBLIC KEY",
  keyFormat: "spki" | "pkcs8",
  pem: string,
  alg: string,
  options?: KeyImportOptions,
) => {
  let algorithm: RsaHashedImportParams | EcKeyAlgorithm | Algorithm;
  let keyUsages: KeyUsage[];

  const body = pemBody(pem, descriptor);
  let keyData: Uint8Array<ArrayBuffer>;
  try {
    keyData = base64Parse(body, { returnAs: "uint8array" });
  } catch (error) {
    throw new JWTError("Invalid PEM: body could not be decoded.", "ERR_JWK_INVALID", error);
  }

  const isPublic = keyFormat === "spki";

  switch (alg) {
    case "PS256":
    case "PS384":
    case "PS512": {
      algorithm = { name: "RSA-PSS", hash: jwsHashOf(alg) };
      keyUsages = isPublic ? ["verify"] : ["sign"];
      break;
    }
    case "RS256":
    case "RS384":
    case "RS512": {
      algorithm = { name: "RSASSA-PKCS1-v1_5", hash: jwsHashOf(alg) };
      keyUsages = isPublic ? ["verify"] : ["sign"];
      break;
    }
    case "RSA-OAEP":
    case "RSA-OAEP-256":
    case "RSA-OAEP-384":
    case "RSA-OAEP-512": {
      algorithm = { name: "RSA-OAEP", hash: rsaOaepHashOf(alg) };
      keyUsages = isPublic ? ["encrypt", "wrapKey"] : ["decrypt", "unwrapKey"];
      break;
    }
    case "ES256":
    case "ES384":
    case "ES512": {
      algorithm = { name: "ECDSA", namedCurve: ECDSA_CURVES[alg] };
      keyUsages = isPublic ? ["verify"] : ["sign"];
      break;
    }
    case "ECDH-ES":
    case "ECDH-ES+A128KW":
    case "ECDH-ES+A192KW":
    case "ECDH-ES+A256KW": {
      const namedCurve = getNamedCurve(keyData);
      if (namedCurve) {
        algorithm = { name: "ECDH", namedCurve };
      } else {
        algorithm = { name: requireOKPCurve(keyData, "X25519") };
      }
      keyUsages = isPublic ? [] : ["deriveBits"];
      break;
    }
    case "Ed25519":
    case "EdDSA": {
      algorithm = { name: requireOKPCurve(keyData, "Ed25519") };
      keyUsages = isPublic ? ["verify"] : ["sign"];
      break;
    }
    default: {
      throw new JWTError('Invalid or unsupported "alg" (Algorithm) value', "ERR_JWK_UNSUPPORTED");
    }
  }

  try {
    return await crypto.subtle.importKey(
      keyFormat,
      keyData,
      algorithm,
      options?.extractable ?? isPublic,
      keyUsages,
    );
  } catch (error) {
    throw new JWTError(
      `Invalid PEM: the body could not be imported as "${alg}".`,
      "ERR_JWK_INVALID",
      error,
    );
  }
};

const findOid = (keyData: Uint8Array<ArrayBuffer>, oid: readonly number[]): boolean => {
  const needle = [0x06, oid.length, ...oid];
  const last = keyData.length - needle.length;

  for (
    let i = keyData.indexOf(needle[0]);
    i !== -1 && i <= last;
    i = keyData.indexOf(needle[0], i + 1)
  ) {
    if (needle.every((byte, index) => keyData[i + index] === byte)) return true;
  }

  return false;
};

/** Object identifiers of the supported Edwards / Montgomery curves, RFC 8410 §3. */
const OKP_CURVE_OIDS = {
  X25519: [0x2b, 0x65, 0x6e],
  Ed25519: [0x2b, 0x65, 0x70],
} as const satisfies Readonly<Record<string, readonly number[]>>;

/** The WebCrypto name of the key body's curve OID; never assumed from `alg`. */
const requireOKPCurve = (
  keyData: Uint8Array<ArrayBuffer>,
  crv: keyof typeof OKP_CURVE_OIDS,
): string => {
  if (findOid(keyData, OKP_CURVE_OIDS[crv])) return crv;

  throw new JWTError(`Invalid PEM: unsupported curve, expected the ${crv} OID.`, "ERR_JWK_INVALID");
};

const getNamedCurve = (keyData: Uint8Array<ArrayBuffer>): string | undefined => {
  switch (true) {
    case findOid(keyData, [0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07]): {
      return "P-256";
    }
    case findOid(keyData, [0x2b, 0x81, 0x04, 0x00, 0x22]): {
      return "P-384";
    }
    case findOid(keyData, [0x2b, 0x81, 0x04, 0x00, 0x23]): {
      return "P-521";
    }
    default: {
      return undefined;
    }
  }
};

const getElement = (seq: Uint8Array<ArrayBuffer>) => {
  const result = [];
  let next = 0;

  while (next < seq.length) {
    const nextPart = parseElement(seq.subarray(next));
    if (nextPart.byteLength <= 0) {
      throw new JWTError("Invalid DER: zero-length element", "ERR_JWK_INVALID");
    }
    result.push(nextPart);
    next += nextPart.byteLength;
  }
  return result;
};

const parseElement = (bytes: Uint8Array<ArrayBuffer>) => {
  let position = 0;
  const at = (index: number): number => {
    const byte = bytes[index];
    if (byte === undefined) {
      throw new JWTError("Invalid DER: element is truncated", "ERR_JWK_INVALID");
    }
    return byte;
  };

  let tag = at(0) & 0x1f;
  position++;
  if (tag === 0x1f) {
    tag = 0;
    while (at(position) >= 0x80) {
      tag = tag * 128 + at(position) - 0x80;
      position++;
    }
    tag = tag * 128 + at(position) - 0x80;
    position++;
  }

  let length = 0;
  if (at(position) < 0x80) {
    length = at(position);
    position++;
  } else if (at(position) === 0x80) {
    length = 0;

    while (position + length + 1 < bytes.byteLength) {
      if (at(position + length) === 0 && at(position + length + 1) === 0) break;
      length++;
    }
    if (position + length + 1 >= bytes.byteLength) {
      throw new JWTError("Invalid DER: invalid indefinite form length", "ERR_JWK_INVALID");
    }

    const byteLength = position + length + 2;
    return {
      byteLength,
      contents: bytes.subarray(position, position + length),
      raw: bytes.subarray(0, byteLength),
    };
  } else {
    const numberOfDigits = at(position) & 0x7f;
    position++;
    length = 0;
    for (let i = 0; i < numberOfDigits; i++) {
      length = length * 256 + at(position);
      position++;
    }
  }

  const byteLength = position + length;
  if (byteLength > bytes.byteLength) {
    throw new JWTError(
      "Invalid DER: element length exceeds the available bytes",
      "ERR_JWK_INVALID",
    );
  }

  return {
    byteLength,
    contents: bytes.subarray(position, byteLength),
    raw: bytes.subarray(0, byteLength),
  };
};

const spkiFromX509 = (buf: Uint8Array<ArrayBuffer>) => {
  const certificate = getElement(parseElement(buf).contents);
  const tbs = certificate[0];
  if (!tbs) {
    throw new JWTError("Invalid X.509 certificate: missing tbsCertificate", "ERR_JWK_INVALID");
  }

  const tbsCertificate = getElement(tbs.contents);
  const first = tbsCertificate[0];
  if (!first) {
    throw new JWTError("Invalid X.509 certificate: empty tbsCertificate", "ERR_JWK_INVALID");
  }

  const spki = tbsCertificate[first.raw[0] === 0xa0 ? 6 : 5];
  if (!spki) {
    throw new JWTError(
      "Invalid X.509 certificate: missing subjectPublicKeyInfo",
      "ERR_JWK_INVALID",
    );
  }

  return base64Stringify(spki.raw);
};

/** The slice of `node:crypto`'s `createPublicKey` used to read a certificate's SPKI. */
type NodeCreatePublicKey = new (pem: string) => {
  export(options: { format: "pem"; type: "spki" }): string;
};

let createPublicKey: NodeCreatePublicKey | 0 | undefined;
const getSPKI = (x509: string): string => {
  try {
    // @ts-ignore
    createPublicKey ??= globalThis.process?.getBuiltinModule?.("node:crypto")?.createPublicKey;
  } catch {
    createPublicKey = 0;
  }

  const body = pemBody(x509, "CERTIFICATE");

  if (createPublicKey) {
    try {
      return new createPublicKey(x509).export({ format: "pem", type: "spki" });
    } catch {}
  }

  let raw: Uint8Array<ArrayBuffer>;
  try {
    raw = base64Parse(body, { returnAs: "uint8array" });
  } catch (error) {
    throw new JWTError(
      "Invalid X.509 certificate: body could not be decoded.",
      "ERR_JWK_INVALID",
      error,
    );
  }
  return formatPEM(spkiFromX509(raw), "PUBLIC KEY");
};
