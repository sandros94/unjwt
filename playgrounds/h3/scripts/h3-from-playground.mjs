// `unjwt` is the workspace root linked into node_modules, so Node would resolve its `h3` peer
// from the repository root, where only the `h3v1`/`h3v2` aliases live. Re-anchor every `h3`
// import coming from outside this playground to the playground's own h3.
import { registerHooks } from "node:module";

const playground = new URL("../", import.meta.url).href;

registerHooks({
  resolve(specifier, context, nextResolve) {
    if (specifier === "h3" && context.parentURL && !context.parentURL.startsWith(playground)) {
      return nextResolve(specifier, { ...context, parentURL: playground });
    }
    return nextResolve(specifier, context);
  },
});
