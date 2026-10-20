import type { ExpirableCookieAttributes } from "./_chunked-cookie.ts";

/** The cookies of one request and its response, as a framework exposes them. */
export interface CookieJar<A extends ExpirableCookieAttributes = ExpirableCookieAttributes> {
  /** The request's cookie. */
  read(name: string): string | undefined;
  /** The value this response already assigned to `name` (`""` once deleted), when the framework exposes it. */
  written?(name: string): string | undefined;
  /** Absent when this context cannot take a `Set-Cookie` (a headers-only event). */
  write?(name: string, value: string, attrs: A): void;
}

/** The primitives a framework supplies; the session core builds the cookie and header transports over them. */
export interface SessionDriver<TContext> {
  /** Message prefix for every error the adapter emits. */
  prefix: string;
  /** The per-request record session state and the session-name registry live in. */
  state(context: TContext): Record<string, unknown>;
  header(context: TContext, name: string): string | null | undefined;
  cookies(context: TContext): CookieJar;
  /** Platform signal that the response can still change (Node `headersSent`); absent = trust the jar. */
  writable?(context: TContext): boolean;
  /** A token the context carries directly, when it does: no cookie or header is consulted. */
  handed?(context: TContext): { token: string | undefined } | undefined;
}
