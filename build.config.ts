import { defineBuildConfig } from "obuild/config";
import { replacePlugin } from "rolldown/plugins";

export default defineBuildConfig({
  entries: [
    {
      type: "bundle",
      input: [
        "./src/index",
        "./src/core/jws",
        "./src/core/jwe",
        "./src/core/jwk",
        "./src/core/utils/index",
        "./src/core/internal",
        "./src/adapters/h3/index",
        "./src/adapters/h3v1/index",
        "./src/adapters/elysia/index",
        "./src/session/index",
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
