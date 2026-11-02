import { generateJWK } from "unjwt/jwk";

/** A session key as the recipes read it: the JSON of an `HS256` JWK. */
export async function sessionKeyJSON(): Promise<string> {
  return JSON.stringify(await generateJWK("HS256"));
}

/** The `Cookie` header a browser sends back after `response`: cookies set, cookies dropped. */
export function nextCookie(response: Response, previous = ""): string {
  const jar = new Map(
    previous
      .split("; ")
      .filter(Boolean)
      .map((pair) => {
        const at = pair.indexOf("=");
        return [pair.slice(0, at), pair.slice(at + 1)] as const;
      }),
  );
  for (const line of response.headers.getSetCookie()) {
    const [pair = ""] = line.split(";", 1);
    const at = pair.indexOf("=");
    const name = pair.slice(0, at);
    if (/;\s*max-age=0/i.test(line) || pair.slice(at + 1) === "") jar.delete(name);
    else jar.set(name, pair.slice(at + 1));
  }
  return [...jar].map(([name, value]) => `${name}=${value}`).join("; ");
}

export function login(origin: string, user: string): Request {
  return new Request(`${origin}/login`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ user }),
  });
}

export function get(url: string, cookie?: string): Request {
  return new Request(url, { headers: cookie ? { cookie } : {} });
}

export function post(url: string, cookie?: string): Request {
  return new Request(url, { method: "POST", headers: cookie ? { cookie } : {} });
}
