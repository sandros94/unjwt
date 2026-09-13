import {
  base64Stringify as _base64Stringify,
  base64Parse as _base64Parse,
  type BytesSource,
  type DecodeOptions,
  type DecodeReturnAs,
} from "unsecure/utils";

export type { BytesSource, DecodeOptions, DecodeReturnAs };

/**
 * Encode bytes or a UTF-8 string as base64url the way JOSE defines it
 * (RFC 7515 §2): URL-safe alphabet, no `=` padding, no line breaks.
 */
export function base64UrlStringify(data: string | BytesSource): string {
  return _base64Stringify(data, { alphabet: "base64url" });
}

/**
 * Decode JOSE base64url (RFC 7515 §2). Strict: only the canonical, unpadded
 * encoding of a byte string is accepted — `=`, whitespace, characters outside
 * the URL-safe alphabet and set bits past the final byte are rejected, and a
 * `string` result must be valid UTF-8. The return type mirrors the input unless
 * `returnAs` is given. `{ loose: true }` drops what it cannot use instead of
 * throwing: meant for application data, never for token material.
 *
 * @throws {UnsecureError} `MALFORMED` unless `loose`; `INVALID_TYPE` for input that is neither text nor bytes
 */
export function base64UrlParse<T extends DecodeReturnAs>(
  input: string | Uint8Array,
  options: DecodeOptions & { returnAs: T },
): T extends "string" ? string : Uint8Array<ArrayBuffer>;
export function base64UrlParse(input: string, options?: DecodeOptions): string;
export function base64UrlParse(input: Uint8Array, options?: DecodeOptions): Uint8Array<ArrayBuffer>;
export function base64UrlParse(
  input: string | Uint8Array,
  options?: DecodeOptions,
): string | Uint8Array<ArrayBuffer> {
  return _base64Parse(input as string, { ...options, alphabet: "base64url", padding: false });
}

/** Encode bytes or a UTF-8 string as standard base64 (RFC 4648 §4), with `=` padding. */
export function base64Stringify(data: string | BytesSource): string {
  return _base64Stringify(data);
}

/**
 * Decode standard base64 (RFC 4648 §4). Strict: the canonical encoding with its
 * `=` padding present. Otherwise the same contract as {@link base64UrlParse}.
 *
 * @throws {UnsecureError} `MALFORMED` unless `loose`; `INVALID_TYPE` for input that is neither text nor bytes
 */
export function base64Parse<T extends DecodeReturnAs>(
  input: string | Uint8Array,
  options: DecodeOptions & { returnAs: T },
): T extends "string" ? string : Uint8Array<ArrayBuffer>;
export function base64Parse(input: string, options?: DecodeOptions): string;
export function base64Parse(input: Uint8Array, options?: DecodeOptions): Uint8Array<ArrayBuffer>;
export function base64Parse(
  input: string | Uint8Array,
  options?: DecodeOptions,
): string | Uint8Array<ArrayBuffer> {
  return _base64Parse(input as string, { ...options, alphabet: "base64", padding: true });
}

/** @deprecated Renamed to {@link base64UrlStringify} in v0.8.0; removed in v0.9.0. */
export const base64UrlEncode: typeof base64UrlStringify = base64UrlStringify;
/** @deprecated Renamed to {@link base64UrlParse} in v0.8.0; removed in v0.9.0. */
export const base64UrlDecode: typeof base64UrlParse = base64UrlParse;
/** @deprecated Renamed to {@link base64Stringify} in v0.8.0; removed in v0.9.0. */
export const base64Encode: typeof base64Stringify = base64Stringify;
/** @deprecated Renamed to {@link base64Parse} in v0.8.0; removed in v0.9.0. */
export const base64Decode: typeof base64Parse = base64Parse;
