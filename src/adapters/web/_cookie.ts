import { parse, parseSetCookie, serialize } from "cookie-es";
import { setCookieName, setCookieValues } from "../_chunked-cookie";
import type { CookieAttributes } from "../_cookie-attributes";
import type { CookieJar } from "../_driver";

export type { CookieAttributes };

/** The cookies of a Web `Request`, and of the `Headers` its response is sent with when there are any. */
export function webCookieJar(request: Request, headers?: Headers): CookieJar<CookieAttributes> {
  let cookies: Record<string, string | undefined> | undefined;
  const jar: CookieJar<CookieAttributes> = {
    read: (name) => (cookies ||= requestCookies(request))[name],
  };
  if (headers) {
    jar.written = (name) => setCookieValues(headers.getSetCookie())[name];
    jar.write = (name, value, attrs) => {
      setCookie(headers, { name, value, ...attrs });
    };
  }
  return jar;
}

function requestCookies(request: Request): Record<string, string | undefined> {
  const header = request.headers.get("cookie");
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
