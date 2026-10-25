import { JWTError } from "../../error.ts";
import type { DPoPValidationCode } from "./validation.ts";

export function normalizeTargetURI(value: unknown, options: { code: DPoPValidationCode }): string {
  const uri = typeof value === "string" ? value.split(/[?#]/, 1)[0] : value;
  const authority = typeof uri === "string" ? /^https?:\/\/([^/]+)/i.exec(uri)?.[1] : undefined;
  if (
    typeof uri !== "string" ||
    authority === undefined ||
    /[@%]/.test(authority) ||
    // oxlint-disable-next-line no-control-regex -- reject controls before URL can discard them
    /[\x00-\x20\x7F\\]/.test(uri) ||
    /%(?![\da-f]{2})/i.test(uri)
  ) {
    throw new JWTError(
      "DPoP htu must be an absolute HTTP(S) URI without credentials or escapes in its authority.",
      options.code,
    );
  }
  const origin = uri.slice(0, uri.indexOf("://") + 3 + authority.length);
  const path = uri.slice(origin.length).replace(/%[\da-f]{2}/gi, (escape) => {
    const character = String.fromCharCode(Number.parseInt(escape.slice(1), 16));
    return /^[\w.~-]$/.test(character) ? character : escape.toUpperCase();
  });
  try {
    return new URL(origin + path).href;
  } catch (cause) {
    throw new JWTError("DPoP htu must be a valid absolute HTTP(S) URI.", options.code, cause);
  }
}
