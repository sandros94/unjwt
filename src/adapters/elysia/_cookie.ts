export interface CookieAttributes {
  domain?: string;
  expires?: Date;
  httpOnly?: boolean;
  maxAge?: number;
  path?: string;
  priority?: "low" | "medium" | "high";
  sameSite?: boolean | "lax" | "strict" | "none";
  secure?: boolean;
  partitioned?: boolean;
}

export interface ChunkableCookie {
  value: unknown;
  set(config: CookieAttributes & { value: string }): unknown;
}

export type ChunkableCookieJar = Record<string, ChunkableCookie>;

export type WriteChunkedCookieOptions = CookieAttributes & { chunkMaxLength?: number };

const CHUNK_MARKER = "__chunked__";
const DEFAULT_CHUNK_MAX_LENGTH = 4000;
const MAX_CHUNK_COUNT = 100;

export function readChunkedCookie(jar: ChunkableCookieJar, name: string): string | undefined {
  const main = asString(jar[name]?.value);
  if (main === undefined) return undefined;
  if (!main.startsWith(CHUNK_MARKER)) return main;

  const count = parseChunkCount(main);
  if (count === 0) return undefined;

  const parts: string[] = [];
  for (let i = 1; i <= count; i++) {
    const part = asString(jar[chunkName(name, i)]?.value);
    if (part === undefined) return undefined;
    parts.push(part);
  }
  return parts.join("");
}

export function writeChunkedCookie(
  jar: ChunkableCookieJar,
  name: string,
  value: string,
  options: WriteChunkedCookieOptions = {},
): void {
  const { chunkMaxLength, ...attrs } = options;
  const max = chunkMaxLength && chunkMaxLength > 0 ? chunkMaxLength : DEFAULT_CHUNK_MAX_LENGTH;
  const chunkCount = Math.ceil(value.length / max);

  if (chunkCount > MAX_CHUNK_COUNT) {
    throw new Error(
      `[unjwt/elysia] Session token requires ${chunkCount} cookie chunks, exceeding the limit of ${MAX_CHUNK_COUNT}.`,
    );
  }

  const previousCount = parseChunkCount(asString(jar[name]?.value));
  const firstSurplus = chunkCount <= 1 ? 1 : chunkCount + 1;
  for (let i = firstSurplus; i <= previousCount; i++) {
    expireCookie(jar, chunkName(name, i), attrs);
  }

  if (chunkCount <= 1) {
    jar[name]!.set({ ...attrs, value });
    return;
  }

  jar[name]!.set({ ...attrs, value: `${CHUNK_MARKER}${chunkCount}` });
  for (let i = 1; i <= chunkCount; i++) {
    const slice = value.slice((i - 1) * max, i * max);
    jar[chunkName(name, i)]!.set({ ...attrs, value: slice });
  }
}

export function removeChunkedCookie(
  jar: ChunkableCookieJar,
  name: string,
  attrs: CookieAttributes = {},
): void {
  const count = parseChunkCount(asString(jar[name]?.value));
  expireCookie(jar, name, attrs);
  for (let i = 1; i <= count; i++) {
    expireCookie(jar, chunkName(name, i), attrs);
  }
}

function expireCookie(jar: ChunkableCookieJar, fullName: string, attrs: CookieAttributes): void {
  jar[fullName]!.set({ ...attrs, value: "", maxAge: 0, expires: new Date(0) });
}

function chunkName(name: string, index: number): string {
  return `${name}.${index}`;
}

function parseChunkCount(main: string | undefined): number {
  if (main === undefined || !main.startsWith(CHUNK_MARKER)) return 0;
  const count = Number.parseInt(main.slice(CHUNK_MARKER.length), 10);
  if (!Number.isInteger(count) || count < 1 || count > MAX_CHUNK_COUNT) return 0;
  return count;
}

function asString(value: unknown): string | undefined {
  return typeof value === "string" ? value : undefined;
}
