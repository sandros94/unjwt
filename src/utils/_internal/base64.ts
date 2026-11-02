import { UnsecureError } from "unsecure/errors";
import { textEncoder } from "unsecure/utils";

/** The decoder output: `"string"` for UTF-8 text, `"uint8array"` or `"bytes"` for the bytes. */
export type DecodeReturnAs = "string" | "uint8array" | "bytes";

export interface Base64ParseOptions {
  /**
   * Return the decoded bytes as UTF-8 text (`"string"`) or as a `Uint8Array`.
   * @default "string"
   */
  returnAs?: DecodeReturnAs;
}

/**
 * Encodes bytes, or the UTF-8 bytes of a string, as unpadded base64url (RFC 7515 §2).
 * @throws {UnsecureError} `INVALID_TYPE` if `data` is neither a string nor a `Uint8Array`.
 */
export function base64UrlStringify(data: string | Uint8Array): string {
  return encode(bytesOf(data, "Base64Url"), "base64url");
}

/**
 * Encodes bytes, or the UTF-8 bytes of a string, as padded standard base64 (RFC 4648 §4).
 * @throws {UnsecureError} `INVALID_TYPE` if `data` is neither a string nor a `Uint8Array`.
 */
export function base64Stringify(data: string | Uint8Array): string {
  return encode(bytesOf(data, "Base64"), "base64");
}

/**
 * Decodes unpadded base64url (RFC 7515 §2). Only the canonical encoding of a byte string passes.
 * `=`, whitespace, characters outside the URL-safe alphabet and set bits past the final byte fail.
 * A `string` result must be valid UTF-8.
 *
 * @throws {UnsecureError} `MALFORMED` if `text` is not such an encoding.
 * @throws {UnsecureError} `INVALID_TYPE` if `text` is not a string.
 */
export function base64UrlParse<T extends DecodeReturnAs>(
  text: string,
  options: Base64ParseOptions & { returnAs: T },
): T extends "string" ? string : Uint8Array<ArrayBuffer>;
export function base64UrlParse(text: string, options?: Base64ParseOptions): string;
export function base64UrlParse(
  text: string,
  options?: Base64ParseOptions,
): string | Uint8Array<ArrayBuffer> {
  return parse(text, URL, false, "Base64Url", options);
}

/**
 * Decodes padded standard base64 (RFC 4648 §4). Only the canonical encoding passes.
 * The `=` padding must be present. Whitespace and set bits past the final byte fail.
 * A `string` result must be valid UTF-8.
 *
 * @throws {UnsecureError} `MALFORMED` if `text` is not such an encoding.
 * @throws {UnsecureError} `INVALID_TYPE` if `text` is not a string.
 */
export function base64Parse<T extends DecodeReturnAs>(
  text: string,
  options: Base64ParseOptions & { returnAs: T },
): T extends "string" ? string : Uint8Array<ArrayBuffer>;
export function base64Parse(text: string, options?: Base64ParseOptions): string;
export function base64Parse(
  text: string,
  options?: Base64ParseOptions,
): string | Uint8Array<ArrayBuffer> {
  return parse(text, STD, true, "Base64", options);
}

const URL = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
const STD = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
const fatalDecoder: TextDecoder = /* @__PURE__ */ new TextDecoder("utf-8", {
  ignoreBOM: true,
  fatal: true,
});

function bytesOf(data: string | Uint8Array, label: string): Uint8Array {
  if (typeof data === "string") return textEncoder.encode(data);
  if (data instanceof Uint8Array) return data;
  throw new UnsecureError("INVALID_TYPE", `${label}.stringify: expected a string or Uint8Array.`);
}

interface NodeBufferCtor {
  from(
    buffer: ArrayBufferLike,
    byteOffset: number,
    length: number,
  ): { toString(encoding: Alphabet): string };
}
interface ToBase64 {
  toBase64(options: { alphabet: Alphabet; omitPadding: boolean }): string;
}
type Alphabet = "base64" | "base64url";

/**
 * Node's `Buffer` writes padded `base64` and unpadded `base64url`, the two outputs required here.
 * `toBase64` writes the same when told so. The loop serves runtimes without either.
 * `toBase64` receives only a view spanning its whole buffer: an engine behind a flag reads a
 * subarray from its buffer's start.
 */
function encode(bytes: Uint8Array, name: Alphabet): string {
  const buffer = (globalThis as { Buffer?: NodeBufferCtor }).Buffer;
  if (typeof buffer?.from === "function") {
    return buffer.from(bytes.buffer, bytes.byteOffset, bytes.byteLength).toString(name);
  }
  if ("toBase64" in Uint8Array.prototype) {
    const whole =
      bytes.byteOffset === 0 && bytes.byteLength === bytes.buffer.byteLength
        ? bytes
        : bytes.slice();
    // oxlint-disable-next-line typescript/no-unsafe-type-assertion -- the method's presence is checked above
    return (whole as unknown as ToBase64).toBase64({
      alphabet: name,
      omitPadding: name === "base64url",
    });
  }
  const alphabet = name === "base64url" ? URL : STD;
  const padded = name === "base64";
  let out = "";
  let i = 0;
  for (; i + 2 < bytes.length; i += 3) {
    const n = (bytes[i] << 16) | (bytes[i + 1] << 8) | bytes[i + 2];
    out +=
      alphabet[n >>> 18] + alphabet[(n >>> 12) & 63] + alphabet[(n >>> 6) & 63] + alphabet[n & 63];
  }
  const rem = bytes.length - i;
  if (rem === 1) {
    const n = bytes[i] << 16;
    out += alphabet[n >>> 18] + alphabet[(n >>> 12) & 63] + (padded ? "==" : "");
  } else if (rem === 2) {
    const n = (bytes[i] << 16) | (bytes[i + 1] << 8);
    out +=
      alphabet[n >>> 18] +
      alphabet[(n >>> 12) & 63] +
      alphabet[(n >>> 6) & 63] +
      (padded ? "=" : "");
  }
  return out;
}

/**
 * Canonical means exactly one text per byte string: alphabet characters only, so whitespace and a
 * stray `=` fail. The symbol count must be one a byte string produces. The padding must be exactly
 * what the alphabet requires, and no bits may be set past the final byte.
 */
function parse(
  text: string,
  alphabet: string,
  padded: boolean,
  label: string,
  options: Base64ParseOptions | undefined,
): string | Uint8Array<ArrayBuffer> {
  if (typeof text !== "string") {
    throw new UnsecureError(
      "INVALID_TYPE",
      `${label}.parse: expected a string, got ${typeof text}.`,
    );
  }
  const wantString = options?.returnAs === undefined || options.returnAs === "string";
  let end = text.length;
  while (end > 0 && text.charCodeAt(end - 1) === 61) end--;
  const rem = end % 4;
  if (rem === 1) throw malformed(label, `${end} symbols cannot encode whole bytes.`);
  const padNeeded = padded && rem !== 0 ? 4 - rem : 0;
  if (text.length - end !== padNeeded) {
    throw malformed(
      label,
      `expected ${padNeeded} "=" padding characters, found ${text.length - end}.`,
    );
  }
  const out = new Uint8Array((end * 6) >>> 3);
  let acc = 0;
  let held = 0;
  let j = 0;
  for (let i = 0; i < end; i++) {
    const value = alphabet.indexOf(text[i]);
    if (value < 0)
      throw malformed(label, `invalid character ${JSON.stringify(text[i])} at index ${i}.`);
    acc = (acc << 6) | value;
    held += 6;
    if (held >= 8) {
      held -= 8;
      out[j++] = (acc >>> held) & 0xff;
    }
  }
  if (held !== 0 && (acc & ((1 << held) - 1)) !== 0) {
    throw malformed(label, "the last symbol sets bits past the final byte.");
  }
  if (!wantString) return out;
  try {
    return fatalDecoder.decode(out);
  } catch {
    throw malformed(label, "decoded bytes are not valid UTF-8.");
  }
}

function malformed(label: string, detail: string): UnsecureError {
  return new UnsecureError("MALFORMED", `${label}.parse: ${detail}`);
}
