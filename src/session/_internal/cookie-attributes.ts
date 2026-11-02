/** The `Set-Cookie` attributes of a session cookie (RFC 6265, RFC 6265bis, and CHIPS: Cookies Having Independent Partitioned State). */
export interface CookieAttributes {
  /** `Domain`. A `__Host-` name refuses it. */
  domain?: string;
  /** `Expires`. An issued token with an `exp` sets it to that time. */
  expires?: Date;
  /** `HttpOnly`: page scripts cannot read the cookie. */
  httpOnly?: boolean;
  /** `Max-Age` in seconds. An issued token with an `exp` replaces it with `expires`. */
  maxAge?: number;
  /** `Path`. A `__Host-` name requires `"/"`. */
  path?: string;
  /** `Priority`. */
  priority?: "low" | "medium" | "high";
  /** `SameSite`. `true` is `Strict`, and `"none"` requires `secure`. */
  sameSite?: boolean | "lax" | "strict" | "none";
  /** `Secure`. A `__Host-` or `__Secure-` name requires it. */
  secure?: boolean;
  /** `Partitioned` (CHIPS). Requires `secure`. */
  partitioned?: boolean;
}

/** The attributes a session cookie gets unless its config sets them: `path` `"/"`, `secure`, `httpOnly` and `sameSite` `"lax"`. */
export const DEFAULT_SESSION_COOKIE: Readonly<CookieAttributes> = /* @__PURE__ */ Object.freeze({
  path: "/",
  secure: true,
  httpOnly: true,
  sameSite: "lax",
});
