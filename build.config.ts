import { defineBuildConfig } from "obuild/config";

export default defineBuildConfig({
  entries: [
    {
      type: "bundle",
      input: [
        "./src/index",
        "./src/core/jws/index",
        "./src/core/jwe/index",
        "./src/core/jwk/index",
        "./src/utils/index",
        "./src/error",
        "./src/core/internal",
        "./src/adapters/elysia/index",
        "./src/session/index",
        "./src/dpop/index",
      ],
      rolldown: {
        platform: "neutral",
        external: ["elysia"],
      },
    },
  ],
});
