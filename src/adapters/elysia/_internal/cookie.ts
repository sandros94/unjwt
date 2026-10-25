import {
  type ChunkedCookieStore,
  readChunked,
  writeChunked,
  removeChunked,
} from "../../../session/_internal/chunked-cookie.ts";
import type { CookieAttributes } from "../../../session/_internal/cookie-attributes.ts";
import { invalidConfigError } from "../../../session/_internal/contract.ts";

export type { CookieAttributes };

export interface ChunkableCookie {
  value: unknown;
  set(config: CookieAttributes & { value: string }): unknown;
}

export type ChunkableCookieJar = Record<string, ChunkableCookie>;

export type WriteChunkedCookieOptions = CookieAttributes & { chunkMaxLength?: number };

const PREFIX = "[unjwt/elysia]";

export function readChunkedCookie(jar: ChunkableCookieJar, name: string): string | undefined {
  return readChunked(reactiveCookieJar(jar), name);
}

export function writeChunkedCookie(
  jar: ChunkableCookieJar,
  name: string,
  value: string,
  options: WriteChunkedCookieOptions = {},
): void {
  const { chunkMaxLength, ...attrs } = options;
  writeChunked(reactiveCookieJar(jar), name, value, { attrs, chunkMaxLength, prefix: PREFIX });
}

export function removeChunkedCookie(
  jar: ChunkableCookieJar,
  name: string,
  attrs: CookieAttributes = {},
): void {
  removeChunked(reactiveCookieJar(jar), name, { attrs });
}

/** Elysia's reactive cookie jar, whose values already reflect this response's writes. */
export function reactiveCookieJar(jar: ChunkableCookieJar): ChunkedCookieStore<CookieAttributes> {
  return {
    read: (name) => {
      const value = jar[name]?.value;
      return typeof value === "string" ? value : undefined;
    },
    write: (name, value, attrs) => reactiveCookie(jar, name).set({ ...attrs, value }),
  };
}

function reactiveCookie(jar: ChunkableCookieJar, name: string): ChunkableCookie {
  const cookie = jar[name];
  if (!cookie || typeof cookie.set !== "function") {
    throw invalidConfigError(
      `${PREFIX} Session cookie jar has no reactive cookie at "${name}", pass Elysia's \`cookie\`.`,
    );
  }
  return cookie;
}
