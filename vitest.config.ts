import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    coverage: {
      exclude: [
        "dist/**",
        "test/**",
        "src/core/_crypto/**",
        "build.config.ts",
        "eslint.config.mjs",
        "vitest.config.ts",
      ],
    },
  },
});
