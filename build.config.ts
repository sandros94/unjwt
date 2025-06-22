import { defineBuildConfig } from "unbuild";
import { readdir, rm } from "node:fs/promises";
import { join } from "node:path";

export default defineBuildConfig({
  entries: [
    "./src/index",
    {
      input: "./src/jwe",
      outDir: "./dist/jwe",
      name: "jwe",
    },
    {
      input: "./src/jwk",
      outDir: "./dist/jwk",
      name: "jwk",
    },
    {
      input: "./src/jws",
      outDir: "./dist/jws",
      name: "jws",
    },
    {
      input: "./src/utils",
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
    if (error.code === "ENOENT" || error.code === "ENOTDIR") {
      return;
    }
    console.error(`Error processing ${directory}: ${error}`);
  }
}
