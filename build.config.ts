import { defineBuildConfig } from "obuild/config";
import { replacePlugin } from "rolldown/plugins";
import { rm } from "node:fs/promises";
import { join } from "node:path";

export default defineBuildConfig({
  hooks: {
    async end(ctx) {
      const distDir = join(ctx.pkgDir, "dist");

      // Removing license from my own other library (`unsecure`)
      await rm(join(distDir, "THIRD-PARTY-LICENSES.md"), { force: true }).catch(() => void 0);
    },
  },
  entries: [
    {
      type: "bundle",
      input: [
        "./src/index",
        "./src/core/jws",
        "./src/core/jwe",
        "./src/core/jwk",
        "./src/core/utils/index",
        "./src/adapters/h3v1/index",
        "./src/adapters/h3v2/index",
      ],
      rolldown: {
        platform: "neutral",
        external: ["h3v1", "cookie-esv1", "h3v2", "cookie-esv3", "rou3"],
        plugins: [
          replacePlugin(
            {
              'h3v1"': 'h3"',
              'h3v2"': 'h3"',
              "cookie-esv1": "cookie-es",
              "cookie-esv3": "cookie-es",
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
