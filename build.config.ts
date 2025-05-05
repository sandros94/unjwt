import { defineBuildConfig } from 'unbuild'

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
  rollup: {
    emitCJS: false,
  },
})
