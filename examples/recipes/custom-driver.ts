// #region event
import {
  type CookieAttributes,
  type CookieJar,
  type SessionConfigJWS,
  defineJWSSession,
  defineSessionDriver,
} from "unjwt/session";

/** The request and response pair an Express handler receives, as far as sessions need it. */
export interface ExpressEvent {
  req: { headers: Record<string, string | string[] | undefined>; body?: unknown };
  res: {
    locals: Record<string, unknown>;
    headersSent: boolean;
    statusCode: number;
    getHeader(name: string): number | string | string[] | undefined;
    setHeader(name: string, value: string | string[]): unknown;
    end(body?: string): unknown;
  };
}
// #endregion

// #region driver
export const express = defineSessionDriver<ExpressEvent>({
  prefix: "[express-session]",
  state: ({ res }) => (res.locals.sessions ??= {}) as Record<string, unknown>,
  header: ({ req }, name) => {
    const value = req.headers[name];
    return Array.isArray(value) ? value.join(", ") : value;
  },
  cookies: ({ req, res }): CookieJar<CookieAttributes> => ({
    read: (name) => parseCookies(req.headers.cookie)[name],
    written: (name) => {
      const line = setCookieLines(res).find((existing) => cookieName(existing) === name);
      return line?.slice(name.length + 1).split(";", 1)[0];
    },
    write: (name, value, attrs) => {
      const kept = setCookieLines(res).filter((existing) => cookieName(existing) !== name);
      res.setHeader("set-cookie", [...kept, serializeCookie(name, value, attrs)]);
    },
  }),
  writable: ({ res }) => !res.headersSent,
});
// #endregion

// #region session
const SESSION_KEY = process.env.SESSION_KEY;
if (!SESSION_KEY) throw new Error("SESSION_KEY is not set");

interface SessionData {
  user: string;
}

const config: SessionConfigJWS<SessionData, "1h", ExpressEvent> = {
  key: JSON.parse(SESSION_KEY),
  maxAge: "1h",
  rolling: "15m",
};

export const appSession = defineJWSSession(config, { driver: express });

export async function login({ req, res }: ExpressEvent) {
  const body = req.body as { user?: unknown } | undefined;
  if (typeof body?.user !== "string") return send(res, 400, { message: "user required" });
  const session = await appSession.use({ req, res });
  await session.update({ user: body.user });
  send(res, 200, { user: session.data.user });
}

export async function me({ req, res }: ExpressEvent) {
  const session = await appSession.use({ req, res });
  if (!session.id) return send(res, 401, { message: "Sign in first" });
  send(res, 200, session.data);
}

export async function logout({ req, res }: ExpressEvent) {
  const session = await appSession.use({ req, res });
  await session.clear();
  send(res, 200, { ok: true });
}
// #endregion

// #region helpers
/** `name=value` pairs of a `Cookie` header (RFC 6265 §5.4); the first of a repeated name wins. */
function parseCookies(header: string | string[] | undefined): Record<string, string> {
  const cookies: Record<string, string> = Object.create(null);
  for (const pair of String(header ?? "").split(";")) {
    const at = pair.indexOf("=");
    if (at < 1) continue;
    const name = pair.slice(0, at).trim();
    cookies[name] ??= pair.slice(at + 1).trim();
  }
  return cookies;
}

/** One `Set-Cookie` line (RFC 6265 §4.1); session values are base64url and dots, safe as they are. */
function serializeCookie(name: string, value: string, attrs: CookieAttributes): string {
  const parts = [`${name}=${value}`, `Path=${attrs.path ?? "/"}`];
  if (attrs.domain) parts.push(`Domain=${attrs.domain}`);
  if (attrs.maxAge !== undefined) parts.push(`Max-Age=${Math.floor(attrs.maxAge)}`);
  if (attrs.expires) parts.push(`Expires=${attrs.expires.toUTCString()}`);
  if (attrs.httpOnly) parts.push("HttpOnly");
  if (attrs.secure) parts.push("Secure");
  if (attrs.sameSite) {
    const sameSite = attrs.sameSite === true ? "strict" : attrs.sameSite;
    parts.push(`SameSite=${{ strict: "Strict", lax: "Lax", none: "None" }[sameSite]}`);
  }
  if (attrs.priority) parts.push(`Priority=${attrs.priority}`);
  if (attrs.partitioned) parts.push("Partitioned");
  return parts.join("; ");
}

function setCookieLines(res: ExpressEvent["res"]): string[] {
  const current = res.getHeader("set-cookie");
  if (current === undefined) return [];
  return Array.isArray(current) ? current : [String(current)];
}

function cookieName(line: string): string {
  return line.slice(0, line.indexOf("="));
}

function send(res: ExpressEvent["res"], status: number, body: unknown): void {
  res.statusCode = status;
  res.setHeader("content-type", "application/json");
  res.end(JSON.stringify(body));
}
// #endregion
