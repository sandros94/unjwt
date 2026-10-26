import { parse, parseSetCookie, serialize } from "cookie-es";
import { mirrorSetCookie, setCookieName, setCookieValues } from "./chunked-cookie.ts";
import type { CookieAttributes } from "./cookie-attributes.ts";
import type { CookieJar } from "./driver.ts";

export type { CookieAttributes };

/**
 * A cookie jar over the request's `Headers` and, when given, the response's.
 * Each write is copied to `errHeaders` too: h3 sends only these for a thrown handler.
 */
export function webCookieJar(
  request: Headers,
  response?: { headers: Headers; errHeaders?: Headers },
): CookieJar<CookieAttributes> {
  let cookies: Record<string, string | undefined> | undefined;
  const jar: CookieJar<CookieAttributes> = {
    read: (name) => (cookies ||= requestCookies(request))[name],
  };
  if (response) {
    const { headers, errHeaders } = response;
    jar.written = (name) => setCookieValues(headers.getSetCookie())[name];
    jar.write = (name, value, attrs) => {
      setCookie(headers, { name, value, ...attrs });
      if (errHeaders) mirrorSetCookie(name, { from: headers, to: errHeaders });
    };
  }
  return jar;
}

export function requestCookies(request: Headers): Record<string, string | undefined> {
  const header = request.get("cookie");
  return header ? parse(header) : Object.create(null);
}

/** Replaces the `Set-Cookie` line of the same cookie (name, domain, path, partition) instead of adding a second one. */
function setCookie(
  headers: Headers,
  cookie: CookieAttributes & { name: string; value: string },
): void {
  const line = serialize({ path: "/", ...cookie });
  const key = cookieKey(cookie);
  const kept = headers.getSetCookie().filter((existing) => {
    const parsed = parseSetCookie(existing);
    return parsed ? cookieKey(parsed) !== key : setCookieName(existing) !== cookie.name;
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
