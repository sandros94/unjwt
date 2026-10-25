import { JWTError } from "../core/error.ts";
import type { DPoPValidationCode } from "./_validation.ts";

export function normalizeTargetURI(value: unknown, options: { code: DPoPValidationCode }): string {
  const uri = typeof value === "string" ? value.split(/[?#]/, 1)[0] : value;
  if (
    typeof uri !== "string" ||
    !/^https?:\/\/[^/?#]+/i.test(uri) ||
    // oxlint-disable-next-line no-control-regex -- reject controls before URL can discard them
    /[\x00-\x20\x7F\\]/.test(uri) ||
    /%(?![\da-f]{2})/i.test(uri)
  ) {
    throw new JWTError(
      "DPoP htu must be an absolute HTTP(S) URI without credentials.",
      options.code,
    );
  }
  try {
    const normalized = uri.replace(/%[\da-f]{2}/gi, (escape) => {
      const character = String.fromCharCode(Number.parseInt(escape.slice(1), 16));
      return /^[\w.~-]$/.test(character) ? character : escape.toUpperCase();
    });
    const url = new URL(normalized);
    if (
      url.username ||
      url.password ||
      normalized
        .slice(normalized.indexOf("://") + 3)
        .split(/[/?#]/, 1)[0]
        .includes("@")
    ) {
      throw new Error("URI credentials are not permitted.");
    }
    url.search = "";
    url.hash = "";
    return url.href;
  } catch (cause) {
    throw new JWTError(
      "DPoP htu must be a valid absolute HTTP(S) URI without credentials.",
      options.code,
      cause,
    );
  }
}
