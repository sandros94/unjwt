import { type H3Event, getCookie, getResponseHeader, setCookie } from "h3v1";
import { type ChunkedCookieStore, responseCookieStore } from "../_chunked-cookie";

export type CookieSerializeOptions = NonNullable<Parameters<typeof setCookie>[3]>;

/** The h3 v1 event's cookies as a chunked-cookie store, in the same layout as h3 v2. */
export function eventCookieStore(event: H3Event): ChunkedCookieStore<CookieSerializeOptions> {
  return responseCookieStore({
    request: (name) => getCookie(event, name),
    response: () => responseSetCookies(event),
    write: (name, value, attrs) => setCookie(event, name, value, attrs),
  });
}

/** The `Set-Cookie` headers the response carries so far. */
export function responseSetCookies(event: H3Event): string[] {
  const value = getResponseHeader(event, "set-cookie");
  if (Array.isArray(value)) return value;
  return typeof value === "string" ? [value] : [];
}
