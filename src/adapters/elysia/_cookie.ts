import {
  type ChunkedCookieStore,
  readChunked,
  writeChunked,
  removeChunked,
} from "../_chunked-cookie";
import { invalidConfigError } from "../_session";

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

const PREFIX = "[unjwt/elysia]";

export function readChunkedCookie(jar: ChunkableCookieJar, name: string): string | undefined {
  return readChunked(cookieStore(jar), name);
}

export function writeChunkedCookie(
  jar: ChunkableCookieJar,
  name: string,
  value: string,
  options: WriteChunkedCookieOptions = {},
): void {
  const { chunkMaxLength, ...attrs } = options;
  writeChunked(cookieStore(jar), name, value, { attrs, chunkMaxLength, prefix: PREFIX });
}

export function removeChunkedCookie(
  jar: ChunkableCookieJar,
  name: string,
  attrs: CookieAttributes = {},
): void {
  removeChunked(cookieStore(jar), name, { attrs });
}

function cookieStore(jar: ChunkableCookieJar): ChunkedCookieStore<CookieAttributes> {
  return {
    read: (name) => {
      const value = jar[name]?.value;
      return typeof value === "string" ? value : undefined;
    },
    write: (name, value, attrs) => reactiveCookie(jar, name).set({ ...attrs, value }),
    expire: (name, attrs) =>
      reactiveCookie(jar, name).set({ ...attrs, value: "", maxAge: 0, expires: new Date(0) }),
  };
}

function reactiveCookie(jar: ChunkableCookieJar, name: string): ChunkableCookie {
  const cookie = jar[name];
  if (!cookie || typeof cookie.set !== "function") {
    throw invalidConfigError(
      `${PREFIX} Session cookie jar must expose a reactive cookie at "${name}" with a set() method — pass Elysia's own \`cookie\` context property.`,
    );
  }
  return cookie;
}
