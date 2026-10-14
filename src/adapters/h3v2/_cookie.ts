import type { CookieSerializeOptions } from "cookie-esv3";
import { type H3Event, getCookie, setCookie } from "h3v2";
import { type ChunkedCookieStore, responseCookieStore } from "../_chunked-cookie";

/** The h3 v2 event's cookies as a chunked-cookie store, with the adapters' own chunk limit and cleanup bounds. */
export function eventCookieStore(event: H3Event): ChunkedCookieStore<CookieSerializeOptions> {
  return responseCookieStore({
    request: (name) => getCookie(event, name),
    response: () => event.res.headers.getSetCookie(),
    write: (name, value, attrs) => setCookie(event, name, value, attrs),
  });
}
