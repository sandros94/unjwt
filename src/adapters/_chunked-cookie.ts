import { invalidConfigError } from "./_session";

/** Value prefix marking the base cookie of a chunked set, followed by the chunk count. */
export const CHUNK_MARKER = "__chunked__";

/** Chunk payload size before a token is split across `name.1` … `name.N`. */
export const DEFAULT_CHUNK_MAX_LENGTH = 4000;

/**
 * Upper bound on the chunks a session may occupy. It also bounds the cleanup
 * of a previous set, so a forged `__chunked__N` marker cannot make one response
 * carry an unbounded number of `Set-Cookie` headers.
 */
export const MAX_CHUNK_COUNT = 16;

/** The cookie primitives a framework provides, over which chunking is layered. */
export interface ChunkedCookieStore<A> {
  read: (name: string) => string | undefined;
  write: (name: string, value: string, attrs: A) => void;
  expire: (name: string, attrs: A) => void;
}

/** The full value of a chunked (or plain) cookie, or `undefined` when a chunk is missing. */
export function readChunked<A>(store: ChunkedCookieStore<A>, name: string): string | undefined {
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

/**
 * Write `value` as a plain cookie, or as a marker plus `name.1` … `name.N`
 * chunks, expiring the chunks a previous, longer value left behind.
 */
export function writeChunked<A>(
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

  const previousCount = Math.min(parseChunkCount(store.read(name)), MAX_CHUNK_COUNT);
  const firstSurplus = chunkCount <= 1 ? 1 : chunkCount + 1;
  for (let index = firstSurplus; index <= previousCount; index++) {
    store.expire(chunkName(name, index), attrs);
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
export function removeChunked<A>(
  store: ChunkedCookieStore<A>,
  name: string,
  options: { attrs: A },
): void {
  const count = Math.min(parseChunkCount(store.read(name)), MAX_CHUNK_COUNT);
  store.expire(name, options.attrs);
  for (let index = 1; index <= count; index++) {
    store.expire(chunkName(name, index), options.attrs);
  }
}

/** {@link readChunked} over a read function alone, for a store nothing writes to. */
export function readChunkedBy(
  read: (name: string) => string | undefined,
  name: string,
): string | undefined {
  return readChunked({ read, write: noop, expire: noop }, name);
}

/** Reassemble a chunked value from cookies already parsed into a record. */
export function readChunkedFrom(
  cookies: Record<string, string | undefined>,
  name: string,
): string | undefined {
  return readChunkedBy((key) => cookies[key], name);
}

/**
 * The value a response's `Set-Cookie` headers assign to `name`, reassembled
 * when they carry a chunk set. A response that assigns nothing to `name`
 * yields `undefined`, so an unrelated cookie never masks the request's.
 */
export function readChunkedFromSetCookie(
  setCookies: readonly string[],
  name: string,
): string | undefined {
  const cookies: Record<string, string> = Object.create(null);
  for (const setCookie of setCookies) {
    const pair = setCookie.split(";", 1)[0]!;
    const separator = pair.indexOf("=");
    if (separator === -1) continue;
    cookies[pair.slice(0, separator).trim()] = decodeValue(pair.slice(separator + 1).trim());
  }
  if (cookies[name] === undefined) return undefined;
  return readChunkedFrom(cookies, name);
}

export function chunkName(name: string, index: number): string {
  return `${name}.${index}`;
}

/**
 * The chunk count a base cookie value claims. A value that merely starts with
 * the marker text, or claims more chunks than {@link MAX_CHUNK_COUNT} allows,
 * is not a chunk set and yields `0`.
 */
export function parseChunkCount(main: string | undefined): number {
  if (main === undefined || !main.startsWith(CHUNK_MARKER)) return 0;
  const suffix = main.slice(CHUNK_MARKER.length);
  if (!/^\d+$/.test(suffix)) return 0;
  const count = Number.parseInt(suffix, 10);
  if (count < 1 || count > MAX_CHUNK_COUNT) return 0;
  return count;
}

function decodeValue(value: string): string {
  if (!value.includes("%")) return value;
  try {
    return decodeURIComponent(value);
  } catch {
    return value;
  }
}

function noop(): void {}
