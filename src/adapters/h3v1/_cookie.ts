import type { CookieSerializeOptions } from "cookie-esv1";
import { type H3Event, getCookie, setCookie } from "h3v1";
import { type ChunkedCookieStore, writeChunked, removeChunked } from "../_chunked-cookie";

export type ChunkedCookieOptions = CookieSerializeOptions & { chunkMaxLength?: number };

const PREFIX = "[unjwt/h3]";

/**
 * Write a session token to the response cookies, splitting it across
 * `<name>.1` … `<name>.N` behind a `__chunked__N` marker when it is too long
 * for one cookie. The layout matches h3 v2's own chunked cookies, so a cookie
 * written by either adapter is readable by the other.
 */
export function setChunkedCookie(
  event: H3Event,
  name: string,
  value: string,
  options: ChunkedCookieOptions = {},
): void {
  const { chunkMaxLength, ...attrs } = options;
  writeChunked(eventStore(event), name, value, { attrs, chunkMaxLength, prefix: PREFIX });
}

export function deleteChunkedCookie(
  event: H3Event,
  name: string,
  attrs: CookieSerializeOptions = {},
): void {
  removeChunked(eventStore(event), name, { attrs });
}

function eventStore(event: H3Event): ChunkedCookieStore<CookieSerializeOptions> {
  return {
    read: (name) => getCookie(event, name),
    write: (name, value, attrs) => setCookie(event, name, value, attrs),
    expire: (name, attrs) =>
      setCookie(event, name, "", { ...attrs, expires: new Date(0), maxAge: undefined }),
  };
}
