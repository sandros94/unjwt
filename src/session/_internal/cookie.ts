import { parse, parseSetCookie, serialize } from "cookie-es";
import { mirrorSetCookie, setCookieName, setCookieValues } from "./chunked-cookie.ts";
import type { CookieAttributes } from "./cookie-attributes.ts";
import type { CookieJar } from "./driver.ts";

export type { CookieAttributes };

/**
 * A cookie jar over a request's `Headers` and, when given, its response's: `read` parses the request's `Cookie` header,
 * `write` sets a `Set-Cookie` line on `response.headers` through `serializeCookie`, replacing the line of the same cookie
 * (name, domain, path, partition) instead of adding a second one, and `written` reads back what the response sets.
 * Each write is copied to `errHeaders` too: h3 and Nitro send only these for a thrown handler.
 * Without `response`, the jar only reads.
 */
export function webCookieJar(
  request: Headers,
  response?: { headers: Headers; errHeaders?: Headers },
): CookieJar<CookieAttributes> {
  let cookies: Record<string, string | undefined> | undefined;
  const jar: CookieJar<CookieAttributes> = {
    read: (name) => (cookies ||= parseCookie(request.get("cookie") ?? ""))[name],
  };
  if (response) {
    const { headers, errHeaders } = response;
    jar.written = (name) => setCookieValues(headers.getSetCookie())[name];
    jar.write = (name, value, attrs) => {
      setCookie(headers, { ...attrs, name, value });
      if (errHeaders) mirrorSetCookie(name, { from: headers, to: errHeaders });
    };
  }
  return jar;
}

/** The cookies of a `Cookie` header value, by name, values percent-decoded. The first of two cookies with one name wins. The record has no prototype. */
export function parseCookie(header: string): Record<string, string | undefined> {
  return parse(header);
}

/** One `Set-Cookie` line, the value percent-encoded and `path` `"/"` unless `attrs` sets one. Throws a `TypeError` for a name or attribute RFC 6265bis refuses. */
export function serializeCookie(name: string, value: string, attrs?: CookieAttributes): string {
  return serialize({ path: "/", ...attrs, name, value });
}

/** Replaces the `Set-Cookie` line of the same cookie (name, domain, path, partition) instead of adding a second one. */
function setCookie(
  headers: Headers,
  cookie: CookieAttributes & { name: string; value: string },
): void {
  const { name, value, ...attrs } = cookie;
  const line = serializeCookie(name, value, attrs);
  const key = cookieKey(cookie);
  const kept = headers.getSetCookie().filter((existing) => {
    const parsed = parseSetCookie(existing);
    return parsed ? cookieKey(parsed) !== key : setCookieName(existing) !== name;
  });
  headers.delete("set-cookie");
  for (const existing of kept) headers.append("set-cookie", existing);
  headers.append("set-cookie", line);
}

/** RFC 6265 §5.3 step 11: a cookie is replaced by one of the same name, domain and path. */
function cookieKey(cookie: {
  name: string;
  domain?: string | undefined;
  path?: string | undefined;
  partitioned?: boolean | undefined;
}): string {
  const domain = (cookie.domain || "").replace(/^\./, "").toLowerCase();
  return [cookie.name, domain, cookie.path || "/", cookie.partitioned ? "1" : "0"].join(";");
}
