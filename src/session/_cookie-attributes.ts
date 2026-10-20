/** The `Set-Cookie` attributes of a session cookie (RFC 6265, RFC 6265bis, CHIPS). */
export interface CookieAttributes {
  domain?: string;
  expires?: Date;
  httpOnly?: boolean;
  maxAge?: number;
  path?: string;
  priority?: "low" | "medium" | "high";
  sameSite?: boolean | "lax" | "strict" | "none";
  secure?: boolean;
  partitioned?: boolean;
}
