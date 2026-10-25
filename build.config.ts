import { defineBuildConfig } from "obuild/config";
import { replacePlugin } from "rolldown/plugins";

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
        "./src/adapters/h3/index",
        "./src/adapters/h3v1/index",
        "./src/adapters/elysia/index",
        "./src/session/index",
        "./src/dpop/index",
      ],
      rolldown: {
        platform: "neutral",
        external: ["h3", "h3v1", "elysia"],
        plugins: [
          replacePlugin(
            {
              'h3v1"': 'h3"',
            },
            {
              delimiters: ["", ""],
            },
          ),
        ],
      },
    },
  ],
});
