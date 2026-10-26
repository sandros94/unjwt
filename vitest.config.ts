import { fileURLToPath } from "node:url";
import { defineConfig } from "vitest/config";

const entry = (path: string) => fileURLToPath(new URL(path, import.meta.url));

export default defineConfig({
  // `examples/` import the package by name, as a consumer would; the aliases
  // point that name at `src` so the examples run against the source.
  resolve: {
    alias: [
      { find: /^unjwt$/, replacement: entry("./src/index.ts") },
      { find: /^unjwt\/(jws|jwe|jwk)$/, replacement: entry("./src/core/$1/index.ts") },
      { find: /^unjwt\/internal$/, replacement: entry("./src/core/internal.ts") },
      { find: /^unjwt\/error$/, replacement: entry("./src/error.ts") },
      { find: /^unjwt\/(utils|session|dpop)$/, replacement: entry("./src/$1/index.ts") },
      { find: /^unjwt\/adapters\/elysia$/, replacement: entry("./src/adapters/elysia/index.ts") },
    ],
  },
  test: {
    coverage: {
      exclude: [
        "dist/**",
        "docs/**",
        "examples/**",
        "test/**",
        "src/core/_crypto/**",
        "build.config.ts",
        "eslint.config.mjs",
        "vitest.config.ts",
      ],
    },
  },
});
