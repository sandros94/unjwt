import type { H3Event, setCookie } from "h3v1";

export type CookieSerializeOptions = NonNullable<Parameters<typeof setCookie>[3]>;

/** The `Set-Cookie` headers the response carries so far. */
export function responseSetCookies(event: H3Event): string[] {
  const value = event.node.res.getHeader("set-cookie");
  if (Array.isArray(value)) return value;
  return typeof value === "string" ? [value] : [];
}
