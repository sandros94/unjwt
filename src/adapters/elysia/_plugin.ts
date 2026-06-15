import type { Elysia } from "elysia";

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

/** Guard macro key for a given context key, e.g. `"session"` → `"requireSession"`. */
export function guardName(contextKey: string): string {
  return `require${contextKey.charAt(0).toUpperCase()}${contextKey.slice(1)}`;
}
