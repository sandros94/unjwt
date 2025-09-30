import { defineBuildConfig } from "unbuild";
import { readdir, rm } from "node:fs/promises";
import { join } from "node:path";

export default defineBuildConfig({
  entries: [
    "./src/index",
    {
      input: "./src/core/jwe",
      outDir: "./dist/jwe",
      name: "jwe",
    },
    {
      input: "./src/core/jwk",
      outDir: "./dist/jwk",
      name: "jwk",
    },
    {
      input: "./src/core/jws",
      outDir: "./dist/jws",
      name: "jws",
    },
    {
      input: "./src/core/utils",
      outDir: "./dist/utils",
      name: "utils",
    },
  ],
  declaration: true,
  hooks: {
    async "build:done"() {
      await removeDtsFiles("dist");
    },
  },
});

async function removeDtsFiles(directory: string) {
  try {
    const items = await readdir(directory, { recursive: true });
    for (const item of items) {
      const itemPath = join(directory, item);

      if (item.endsWith(".d.ts")) {
        await rm(itemPath);
      }
    }
  } catch (error) {
    if (
      error &&
      typeof error === "object" &&
      "code" in error &&
      (error.code === "ENOENT" || error.code === "ENOTDIR")
    ) {
      return;
    }
    console.error(`Error processing ${directory}: ${error}`);
  }
}
