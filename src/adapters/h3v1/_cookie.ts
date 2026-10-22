import { type H3Event, getResponseHeader, type setCookie } from "h3v1";

export type CookieSerializeOptions = NonNullable<Parameters<typeof setCookie>[3]>;

/** The `Set-Cookie` headers the response carries so far. */
export function responseSetCookies(event: H3Event): string[] {
  const value = getResponseHeader(event, "set-cookie");
  if (Array.isArray(value)) return value;
  return typeof value === "string" ? [value] : [];
}
