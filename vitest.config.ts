import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    coverage: {
      exclude: [
        "dist/**",
        "src/jose/**",
        "build.config.ts",
        "eslint.config.mjs",
        "vitest.config.ts",
      ],
    },
  },
});
