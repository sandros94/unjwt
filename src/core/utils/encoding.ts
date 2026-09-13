import {
  base64Stringify,
  base64Parse,
  type BytesSource,
  type Base64ParseOptions,
  type DecodeReturnAs,
} from "unsecure/utils";

/** Options accepted by the Base64 decoders; the alphabet is fixed per function. */
export type Base64DecodeOptions = Omit<Base64ParseOptions, "alphabet">;

/** Encode bytes or a UTF-8 string as unpadded Base64URL (RFC 4648 §5). */
export function base64UrlEncode(data: string | BytesSource): string {
  return base64Stringify(data, { alphabet: "base64url" });
}

/**
 * Decode Base64URL text. Strict by default: only the canonical encoding of a
 * byte string is accepted, padding may be present or absent. Return type mirrors
 * the input unless `returnAs` is given.
 */
export function base64UrlDecode<T extends DecodeReturnAs>(
  input: string | Uint8Array,
  options: Base64DecodeOptions & { returnAs: T },
): T extends "string" ? string : Uint8Array<ArrayBuffer>;
export function base64UrlDecode(input: string, options?: Base64DecodeOptions): string;
export function base64UrlDecode(
  input: Uint8Array,
  options?: Base64DecodeOptions,
): Uint8Array<ArrayBuffer>;
export function base64UrlDecode(
  input: string | Uint8Array,
  options?: Base64DecodeOptions,
): string | Uint8Array<ArrayBuffer> {
  return base64Parse(input as string, { ...options, alphabet: "base64url" });
}

/** Encode bytes or a UTF-8 string as padded standard Base64 (RFC 4648 §4). */
export function base64Encode(data: string | BytesSource): string {
  return base64Stringify(data);
}

/** Decode standard Base64 text; same contract as {@link base64UrlDecode}. */
export function base64Decode<T extends DecodeReturnAs>(
  input: string | Uint8Array,
  options: Base64DecodeOptions & { returnAs: T },
): T extends "string" ? string : Uint8Array<ArrayBuffer>;
export function base64Decode(input: string, options?: Base64DecodeOptions): string;
export function base64Decode(
  input: Uint8Array,
  options?: Base64DecodeOptions,
): Uint8Array<ArrayBuffer>;
export function base64Decode(
  input: string | Uint8Array,
  options?: Base64DecodeOptions,
): string | Uint8Array<ArrayBuffer> {
  return base64Parse(input as string, { ...options, alphabet: "base64" });
}
