import type { BytesSource } from "unsecure/utils";
import {
  type Base64ParseOptions,
  type DecodeReturnAs,
  base64Parse,
  base64Stringify,
  base64UrlParse,
  base64UrlStringify,
} from "./_internal/base64.ts";

export type { Base64ParseOptions, DecodeReturnAs };

/** @deprecated The codecs take a `string` or `Uint8Array`; removed in v0.9.0. */
export type { BytesSource };
export { base64Parse, base64Stringify, base64UrlParse, base64UrlStringify };

/** @deprecated Renamed to {@link Base64ParseOptions}; removed in v0.9.0. */
export type DecodeOptions = Base64ParseOptions;

/** @deprecated Renamed to {@link base64UrlStringify} in v0.8.0; removed in v0.9.0. */
export const base64UrlEncode: typeof base64UrlStringify = base64UrlStringify;
/** @deprecated Renamed to {@link base64UrlParse} in v0.8.0; removed in v0.9.0. */
export const base64UrlDecode: typeof base64UrlParse = base64UrlParse;
/** @deprecated Renamed to {@link base64Stringify} in v0.8.0; removed in v0.9.0. */
export const base64Encode: typeof base64Stringify = base64Stringify;
/** @deprecated Renamed to {@link base64Parse} in v0.8.0; removed in v0.9.0. */
export const base64Decode: typeof base64Parse = base64Parse;
