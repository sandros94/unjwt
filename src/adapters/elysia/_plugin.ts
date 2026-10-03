import { Elysia } from "elysia";

import type { SessionContext } from "./session/types";

/**
 * Explicit return type for the `jwsSession` / `jweSession` plugin factories.
 *
 * Modelling Elysia's generics by hand is required by `isolatedDeclarations`
 * (the factories return an inferred `new Elysia().resolve().macro()` type that
 * cannot otherwise be emitted). `Resolved` is the scoped `Ephemeral.resolve`
 * augmentation — typically `{ [P in ContextKey]: SessionManager }` — so consumers
 * read a typed `ctx[contextKey]`. `GuardName` is the guard macro key (derived
 * from the context key, e.g. `requireSession`), so multiple session plugins on
 * one app each expose a distinct guard rather than colliding. `macroFn` is left
 * `{}`: consumers only need `Metadata.macro` for the `{ [GuardName]: true }`
 * route option.
 */
export type SessionPlugin<
  Resolved extends Record<string, unknown>,
  GuardName extends string = "requireSession",
> = Elysia<
  "",
  { decorator: {}; store: {}; derive: {}; resolve: {} },
  { typebox: {}; error: {} },
  {
    schema: {};
    standaloneSchema: {};
    macro: { [M in GuardName]?: boolean };
    macroFn: {};
    parser: {};
    response: {};
  },
  {},
  { derive: {}; resolve: Resolved; schema: {}; standaloneSchema: {}; response: {} },
  { derive: {}; resolve: {}; schema: {}; standaloneSchema: {}; response: {} }
>;

/**
 * The plugin a session factory returns: it resolves the session `create`
 * opens onto the context under `contextKey` (default `"session"`), and adds
 * the guard macro that answers 401 while no session is established.
 */
export function sessionPlugin<
  Manager extends { readonly id: string | undefined },
  K extends string,
>(options: {
  name: string;
  sessionName: string;
  contextKey: string | undefined;
  create: (context: SessionContext) => Promise<Manager>;
}): SessionPlugin<{ [P in K]: Manager }, `require${Capitalize<K>}`> {
  // oxlint-disable-next-line typescript/no-unsafe-type-assertion -- the factory's config type requires `contextKey` whenever K is not "session", so the default only ever stands for K = "session"
  const contextKey = (options.contextKey ?? "session") as K;
  // The seed carries the session name as well as the context key, so two
  // differently-named sessions register as two plugins rather than one.
  const seed = `${options.sessionName}:${contextKey}`;
  // oxlint-disable-next-line typescript/no-unsafe-type-assertion -- SessionPlugin models by hand the type this chain infers, which isolatedDeclarations cannot emit
  return new Elysia({ name: options.name, seed })
    .resolve({ as: "scoped" }, async ({ cookie, request }) => {
      const session = await options.create({ cookie, request });
      // oxlint-disable-next-line typescript/no-unsafe-type-assertion -- an object with the single computed key `contextKey`, which is K
      return { [contextKey]: session } as { [P in K]: Manager };
    })
    .macro({
      [guardName(contextKey)]: {
        resolve(ctx) {
          if (!hasSessionId((ctx as Record<string, unknown>)[contextKey])) {
            return ctx.status(401, "Unauthorized");
          }
          return {};
        },
      },
    }) as unknown as SessionPlugin<{ [P in K]: Manager }, `require${Capitalize<K>}`>;
}

/** Guard macro key for a given context key, e.g. `"session"` → `"requireSession"`. */
export function guardName(contextKey: string): string {
  return `require${contextKey.charAt(0).toUpperCase()}${contextKey.slice(1)}`;
}

function hasSessionId(session: unknown): boolean {
  return typeof session === "object" && session !== null && "id" in session && Boolean(session.id);
}
