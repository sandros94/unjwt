import { quoteTokenValue } from "../core/utils/_text";
import {
  type ChunkedCookieStore,
  type ExpirableCookieAttributes,
  readChunked,
  removeChunked,
  writeChunked,
} from "./_chunked-cookie";
import type { CookieJar, SessionDriver } from "./_driver";
import { invalidConfigError, isToken, readOnlyEventError } from "./_session";

/** Where a session's token can travel. */
export interface SessionTokenSource {
  /** Request header to read the token from: a name, `true` for `x-<name>-session`, or `false` for none. */
  sessionHeader?: boolean | string;
  /** Cookie options, or `false` for no cookie. */
  cookie?: false | object;
}

/** RFC 6265 cookie attributes plus the chunk size the token is split at. */
export interface SessionCookie {
  attrs: Record<string, unknown>;
  chunkMaxLength: number | undefined;
}

/** How one session's token reaches the request and leaves with the response. */
export interface SessionTransport {
  /** The token this response wrote, else the request cookie's, else the session header's; absent without a token source. */
  read?: () => string | undefined;
  /** Present while the session keeps its token in a cookie the context can write. */
  write?: (token: string, cookie: SessionCookie) => void;
  /** Present while the session keeps its token in a cookie the context can write. */
  drop?: (cookie: SessionCookie) => void;
  /** The session keeps its token in a cookie, but the context cannot take one (a headers-only event). */
  readonly: boolean;
  /** Platform signal that the response can still change; `false` once it was sent. */
  writable: () => boolean;
}

/** A token the driver hands in, else the cookie and header transports a config asks for, over the driver of one request. */
export function resolveTransport<TContext>(
  driver: SessionDriver<TContext>,
  context: TContext,
  options: { config: SessionTokenSource; name: string },
): SessionTransport {
  const handed = driver.handed?.(context);
  if (handed) return { read: () => handed.token, readonly: false, writable: () => true };

  const { config, name } = options;
  const header = headerReader(driver, context, options);
  if (config.cookie === false) {
    return { read: header, readonly: false, writable: () => true };
  }

  const jar = driver.cookies(context);
  const store = responseStore(jar);
  const transport: SessionTransport = {
    read: () => {
      const written = jar.written
        ? readChunked({ read: (key) => jar.written?.(key) }, name)
        : undefined;
      if (written === "") return undefined;
      return (written ?? readChunked(jar, name)) || header?.() || undefined;
    },
    readonly: !store,
    writable: () => driver.writable?.(context) ?? true,
  };
  if (!store) return transport;

  transport.write = (token, { attrs, chunkMaxLength }) => {
    writeChunked(store, name, token, { attrs, chunkMaxLength, prefix: driver.prefix });
  };
  transport.drop = ({ attrs }) => {
    removeChunked(store, name, { attrs });
  };
  return transport;
}

/** A transport without a reader has no token source: reading or clearing it is a config failure. */
export function assertTokenSource(
  transport: SessionTransport,
  options: { prefix: string },
): asserts transport is SessionTransport & { read: () => string | undefined } {
  if (!transport.read) {
    throw invalidConfigError(
      `${options.prefix} Session has no token source: "cookie" and "sessionHeader" are both disabled.`,
    );
  }
}

/** No update where the context takes no cookie the session keeps its token in; no update or clear once the response was sent. */
export function assertWritable(
  transport: SessionTransport,
  options: { operation: "update" | "clear"; prefix: string },
): void {
  const { operation, prefix } = options;
  if (operation === "update" && transport.readonly) {
    throw readOnlyEventError(`${prefix} Cannot update session on read-only event.`);
  }
  if (!transport.writable()) {
    throw readOnlyEventError(
      `${prefix} Cannot update/clear session: the response was already sent.`,
    );
  }
}

/** Reject a `sessionHeader` that is neither a boolean nor a header name (RFC 7230 §3.2). */
export function assertSessionHeader(header: unknown, options: { prefix: string }): void {
  if (header === undefined || typeof header === "boolean") return;
  if (isToken(header)) return;
  throw invalidConfigError(
    `${options.prefix} Session "sessionHeader" must be true, false or a header name: letters, digits and !#$%&'*+-.^_\`|~ only. Got ${quoteTokenValue(header)}.`,
  );
}

/** The configured header, else `x-<name>-session` without a `__Host-`/`__Secure-` prefix. */
export function sessionHeaderName(
  sessionName: string,
  configured: boolean | string | undefined,
): string {
  if (typeof configured === "string") return configured.toLowerCase();
  // RFC 6265bis §4.1.3 — cookie prefixes are matched case-insensitively.
  const bare = sessionName.replace(/^__(?:host|secure)-/i, "");
  return `x-${bare.toLowerCase()}-session`;
}

/** A bare token or `Bearer <token>` (RFC 7235 §2.1, case-insensitive); anything else is `undefined`. */
export function headerToken(value: string | null | undefined): string | undefined {
  if (typeof value !== "string") return undefined;
  const words = value.trim().split(/\s+/);
  const [first = "", second] = words;
  if (/^bearer$/i.test(first)) return words.length === 2 ? second : undefined;
  return words.length === 1 && first ? first : undefined;
}

/** Reads the session header `sessionHeader` names, else `x-<name>-session`. */
function headerReader<TContext>(
  driver: SessionDriver<TContext>,
  context: TContext,
  options: { config: SessionTokenSource; name: string },
): (() => string | undefined) | undefined {
  const { config, name } = options;
  if (config.sessionHeader === false) return undefined;
  const header = sessionHeaderName(name, config.sessionHeader);
  return () => headerToken(driver.header(context, header));
}

/** The jar as the chunked layer writes it, this response's value first; absent when it takes no cookie. */
function responseStore(jar: CookieJar): ChunkedCookieStore<ExpirableCookieAttributes> | undefined {
  const write = jar.write?.bind(jar);
  if (!write) return undefined;
  return { read: (name) => jar.written?.(name) ?? jar.read(name), write };
}
