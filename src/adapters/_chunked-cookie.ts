import { invalidConfigError } from "./_session.ts";

/** Value prefix marking the base cookie of a chunked set, followed by the chunk count. */
export const CHUNK_MARKER = "__chunked__";

/** Chunk payload size before a token is split across `name.1` … `name.N`. */
export const DEFAULT_CHUNK_MAX_LENGTH = 4000;

/** Max chunks per session; also bounds the cleanup a forged `__chunked__N` marker can trigger. */
export const MAX_CHUNK_COUNT = 16;

export interface ExpirableCookieAttributes {
  expires?: Date;
  maxAge?: number;
}

/** The cookies the chunked layer reads and writes, one name at a time. */
export interface ChunkedCookieStore<A extends ExpirableCookieAttributes> {
  /** The value this response already wrote for `name`, else the request's. */
  read: (name: string) => string | undefined;
  write: (name: string, value: string, attrs: A) => void;
}

/** The full value of a chunked (or plain) cookie, or `undefined` when a chunk is missing. */
export function readChunked(
  store: { read(name: string): string | undefined },
  name: string,
): string | undefined {
  const main = store.read(name);
  if (main === undefined) return undefined;
  if (!main.startsWith(CHUNK_MARKER)) return main;

  const count = parseChunkCount(main);
  if (count === 0) return undefined;

  const parts: string[] = [];
  for (let index = 1; index <= count; index++) {
    const part = store.read(chunkName(name, index));
    if (part === undefined) return undefined;
    parts.push(part);
  }
  return parts.join("");
}

/** Writes a plain cookie or a marker plus `name.1` … `name.N`, expiring a longer previous set's surplus. */
export function writeChunked<A extends ExpirableCookieAttributes>(
  store: ChunkedCookieStore<A>,
  name: string,
  value: string,
  options: { attrs: A; chunkMaxLength?: number; prefix: string },
): void {
  const { attrs, chunkMaxLength, prefix } = options;
  const max = chunkMaxLength && chunkMaxLength > 0 ? chunkMaxLength : DEFAULT_CHUNK_MAX_LENGTH;
  const chunkCount = Math.ceil(value.length / max);

  if (chunkCount > MAX_CHUNK_COUNT) {
    throw invalidConfigError(
      `${prefix} Session token requires ${chunkCount} cookie chunks, exceeding the limit of ${MAX_CHUNK_COUNT}.`,
    );
  }

  const previousCount = parseChunkCount(store.read(name));
  const firstSurplus = chunkCount <= 1 ? 1 : chunkCount + 1;
  for (let index = firstSurplus; index <= previousCount; index++) {
    expire(store, chunkName(name, index), attrs);
  }

  if (chunkCount <= 1) {
    store.write(name, value, attrs);
    return;
  }

  store.write(name, `${CHUNK_MARKER}${chunkCount}`, attrs);
  for (let index = 1; index <= chunkCount; index++) {
    store.write(chunkName(name, index), value.slice((index - 1) * max, index * max), attrs);
  }
}

/** Expire the base cookie and every chunk the current value claims. */
export function removeChunked<A extends ExpirableCookieAttributes>(
  store: ChunkedCookieStore<A>,
  name: string,
  options: { attrs: A },
): void {
  const count = parseChunkCount(store.read(name));
  expire(store, name, options.attrs);
  for (let index = 1; index <= count; index++) {
    expire(store, chunkName(name, index), options.attrs);
  }
}

/** The value each cookie is assigned by a list of `Set-Cookie` headers, the last write winning. */
export function setCookieValues(setCookies: readonly string[]): Record<string, string> {
  const cookies: Record<string, string> = Object.create(null);
  for (const setCookie of setCookies) {
    const pair = setCookiePair(setCookie);
    if (pair) cookies[pair.name] = decodeValue(pair.value);
  }
  return cookies;
}

export function setCookieName(setCookie: string): string | undefined {
  return setCookiePair(setCookie)?.name;
}

export function chunkName(name: string, index: number): string {
  return `${name}.${index}`;
}

/** `0` for a value that only starts with the marker or claims more than `MAX_CHUNK_COUNT` chunks. */
export function parseChunkCount(main: string | undefined): number {
  if (main === undefined || !main.startsWith(CHUNK_MARKER)) return 0;
  const suffix = main.slice(CHUNK_MARKER.length);
  if (!/^\d+$/.test(suffix)) return 0;
  const count = Number.parseInt(suffix, 10);
  if (count < 1 || count > MAX_CHUNK_COUNT) return 0;
  return count;
}

/** RFC 6265 §5.2.2: `Max-Age=0`, plus the epoch `Expires` for clients that ignore `Max-Age`. */
function expire<A extends ExpirableCookieAttributes>(
  store: ChunkedCookieStore<A>,
  name: string,
  attrs: A,
): void {
  store.write(name, "", { ...attrs, maxAge: 0, expires: new Date(0) });
}

function setCookiePair(setCookie: string): { name: string; value: string } | undefined {
  const [pair = ""] = setCookie.split(";", 1);
  const separator = pair.indexOf("=");
  if (separator === -1) return undefined;
  return { name: pair.slice(0, separator).trim(), value: pair.slice(separator + 1).trim() };
}

function decodeValue(value: string): string {
  if (!value.includes("%")) return value;
  try {
    return decodeURIComponent(value);
  } catch {
    return value;
  }
}
