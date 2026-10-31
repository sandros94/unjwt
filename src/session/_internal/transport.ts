import { quoteTokenValue } from "../../utils/_internal/text.ts";
import {
  type ChunkedCookieStore,
  type ExpirableCookieAttributes,
  readChunked,
  removeChunked,
  writeChunked,
} from "./chunked-cookie.ts";
import type { CookieJar, SessionDriver } from "./driver.ts";
import type { JWTError } from "../../error.ts";
import type { SessionSource } from "../types.ts";
import { invalidConfigError, invalidTokenError, isToken, readOnlyEventError } from "./contract.ts";

/** The token sources a session config enables. */
export interface SessionTokenSource {
  /** Request header to read the token from, before the cookie: a name, or `true` for `x-<name>-session`. Unset or `false` reads no header. */
  sessionHeader?: boolean | string;
  /** Cookie options, or `false` for no cookie. */
  cookie?: false | object;
}

/** RFC 6265 cookie attributes plus the chunk size the token is split at. */
export interface SessionCookie {
  attrs: Record<string, unknown>;
  chunkMaxLength: number | undefined;
}

/** How one session reads its token from the request and writes it to the response. */
export interface SessionTransport {
  /** Where the token is read from: the driver's token in hand, the session header, or the cookie. Only a cookie is written back. */
  source: SessionSource;
  /** The token in hand, else the session header's, else the cookie this response wrote, else the request's. Absent without a token source. */
  read?: () => string | undefined;
  /** The session header is present but holds neither a bare token nor `Bearer <token>`. */
  malformed?: JWTError<"ERR_SESSION_TOKEN_INVALID">;
  /** Present when the session reads its token from a cookie the event can write. */
  write?: (token: string, cookie: SessionCookie) => void;
  /** Present when the session reads its token from a cookie the event can write. */
  drop?: (cookie: SessionCookie) => void;
  /** The session reads its token from a cookie, but the event cannot write one (a request without a response). */
  readonly: boolean;
  /** Whether the response can still change. `false` once it was sent. */
  writable: () => boolean;
}

/**
 * Resolves the transport of one request, before any token is opened: a token the driver hands in, else the session header the request sends, else the cookie.
 * A header that holds the very token of the request's cookie is the cookie. Any other header is read alone, the cookie left as it is.
 * A token in hand or a header token is reissued onto the session only. Only a cookie session writes back.
 */
export function resolveTransport<TEvent>(
  driver: SessionDriver<TEvent>,
  event: TEvent,
  options: { config: SessionTokenSource; name: string },
): SessionTransport {
  const handed = driver.handed?.(event);
  if (handed) {
    return { source: "token", read: () => handed.token, readonly: false, writable: () => true };
  }

  const { config, name } = options;
  const header = presentedHeader(driver, event, options);
  if (config.cookie === false) return headerTransport(config, header);
  const jar = driver.cookies(event);
  if (header && (header.token === undefined || header.token !== readChunked(jar, name))) {
    return headerTransport(config, header);
  }

  const store = responseStore(jar);
  const transport: SessionTransport = {
    source: "cookie",
    read: () => cookieToken(jar, name),
    readonly: !store,
    writable: () => driver.writable?.(event) ?? true,
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
      `${options.prefix} Session has no token source, enable "cookie" or "sessionHeader".`,
    );
  }
}

/** Throws `ERR_SESSION_READONLY_EVENT` on an update when a cookie session cannot write its cookie, and on an update or clear once the response was sent. */
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

/** Refuses a `sessionHeader` that is neither a boolean nor a header name (RFC 7230 §3.2). */
export function assertSessionHeader(header: unknown, options: { prefix: string }): void {
  if (header === undefined || typeof header === "boolean") return;
  if (isToken(header)) return;
  throw invalidConfigError(
    `${options.prefix} Session "sessionHeader" must be true, false or a header name (got ${quoteTokenValue(header)}).`,
  );
}

/** The configured header, else `x-<name>-session` without a `__Host-`/`__Secure-` prefix. */
export function sessionHeaderName(
  sessionName: string,
  configured: boolean | string | undefined,
): string {
  if (typeof configured === "string") return configured.toLowerCase();
  // RFC 6265bis §4.1.3: cookie prefixes are matched case-insensitively.
  const bare = sessionName.replace(/^__(?:host|secure)-/i, "");
  return `x-${bare.toLowerCase()}-session`;
}

/** A bare token or `Bearer <token>` (RFC 7235 §2.1, case-insensitive). Any other value is `undefined`. */
export function headerToken(value: string | null | undefined): string | undefined {
  if (typeof value !== "string") return undefined;
  const words = value.trim().split(/\s+/);
  const [first = "", second] = words;
  if (/^bearer$/i.test(first)) return words.length === 2 ? second : undefined;
  return words.length === 1 && first ? first : undefined;
}

/** The session header that `sessionHeader` enables, when the request sends it. A value without a token is malformed. */
function presentedHeader<TEvent>(
  driver: SessionDriver<TEvent>,
  event: TEvent,
  options: { config: SessionTokenSource; name: string },
): { token: string | undefined; malformed?: JWTError<"ERR_SESSION_TOKEN_INVALID"> } | undefined {
  const { config, name } = options;
  if (!readsHeader(config)) return undefined;
  const header = sessionHeaderName(name, config.sessionHeader);
  const value = driver.header(event, header);
  if (typeof value !== "string") return undefined;
  const token = headerToken(value);
  if (token) return { token };
  return {
    token: undefined,
    malformed: invalidTokenError(
      `${driver.prefix} Invalid session token: the "${header}" header holds neither a token nor "Bearer <token>".`,
    ),
  };
}

/** Reads the session header when `sessionHeader` enables it, and writes nothing back. */
function headerTransport(
  config: SessionTokenSource,
  header: ReturnType<typeof presentedHeader>,
): SessionTransport {
  return {
    source: "header",
    read: readsHeader(config) ? () => header?.token : undefined,
    malformed: header?.malformed,
    readonly: false,
    writable: () => true,
  };
}

/** `sessionHeader: true` or a name enables the header, read before the cookie. Unset or `false`, no header is read. */
function readsHeader(config: SessionTokenSource): boolean {
  return config.sessionHeader !== undefined && config.sessionHeader !== false;
}

/** The cookie this response wrote (none once deleted), else the request's, chunks joined. */
function cookieToken(jar: CookieJar, name: string): string | undefined {
  const written = jar.written
    ? readChunked({ read: (key) => jar.written?.(key) }, name)
    : undefined;
  if (written === "") return undefined;
  return (written ?? readChunked(jar, name)) || undefined;
}

/** The jar as the chunked layer uses it, this response's value read first. Absent when the jar cannot write. */
function responseStore(jar: CookieJar): ChunkedCookieStore<ExpirableCookieAttributes> | undefined {
  const write = jar.write?.bind(jar);
  if (!write) return undefined;
  return { read: (name) => jar.written?.(name) ?? jar.read(name), write };
}
