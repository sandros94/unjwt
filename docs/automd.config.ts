/// <reference types="node" />

import { readFile } from "node:fs/promises";
import { basename, extname } from "node:path";
import type { Config, Generator } from "automd";

/**
 * `<!-- automd:region src="../../examples/x.ts" name="docs" -->`
 *
 * Inlines the lines between `// #region <name>` and `// #endregion` of a file
 * as a code block, so a page shows exactly the code the repository typechecks
 * and tests, minus the harness around it. Inside the region, lines between
 * `// #hide <comment>` and `// #endhide` are replaced by `// <comment>`, so
 * storage stubs and fixtures stay out of the page without faking the code.
 */
const region: Generator = {
  name: "region",
  async generate({ args, url }) {
    const file = new URL(String(args.src), url);
    const source = await readFile(file, "utf8");
    const name = String(args.name ?? "docs");
    // `// #region` in scripts, `<!-- #region -->` in HTML.
    const open = new RegExp(`^[ \\t]*(?://|<!--) #region ${name}(?: -->)?\\s*$`, "m");
    const start = open.exec(source);
    if (!start) throw new Error(`no "#region ${name}" in ${file.pathname}`);
    const rest = source.slice(start.index + start[0].length);
    const end = /^[ \t]*(?:\/\/|<!--) #endregion(?: -->)?\s*$/m.exec(rest);
    if (!end) throw new Error(`no "#endregion" after "#region ${name}" in ${file.pathname}`);
    const lines: string[] = [];
    let hidden: string | undefined;
    for (const line of rest.slice(0, end.index).split("\n")) {
      const hide = /^([ \t]*)\/\/ #hide(?:\s+(.*))?$/.exec(line);
      if (hide) {
        hidden = `${hide[1]}// ${(hide[2] ?? "…").trim()}`;
        continue;
      }
      if (/^[ \t]*\/\/ #endhide\s*$/.test(line)) {
        if (hidden === undefined)
          throw new Error(`"// #endhide" without "// #hide" in ${file.pathname}`);
        lines.push(hidden);
        hidden = undefined;
        continue;
      }
      if (hidden === undefined) lines.push(line);
    }
    if (hidden !== undefined)
      throw new Error(`"// #hide" without "// #endhide" in ${file.pathname}`);
    // The published version, so a CDN pin on a page follows package.json.
    const code = _dedent(lines)
      .join("\n")
      .trim()
      .replaceAll("__UNJWT_VERSION__", await _version());
    const lang = String(args.lang ?? extname(file.pathname).slice(1));
    const title = args.name === false ? "" : ` [${String(args.title ?? basename(file.pathname))}]`;
    return { contents: `\`\`\`${lang}${title}\n${code}\n\`\`\`` };
  },
};

/** The library's current version, from the repository's package.json. */
async function _version(): Promise<string> {
  const pkg = JSON.parse(await readFile(new URL("../package.json", import.meta.url), "utf8")) as {
    version: string;
  };
  return pkg.version;
}

/** Drop the indentation the whole region shares, so nested code sits at the margin. */
function _dedent(lines: string[]): string[] {
  const indents = lines.filter((l) => l.trim()).map((l) => /^[ \t]*/.exec(l)![0].length);
  const cut = indents.length ? Math.min(...indents) : 0;
  return lines.map((l) => l.slice(cut));
}

// `pnpm automd` writes every generated block into the Markdown sources, so the
// committed pages, the `/raw/*.md` endpoints and `llms.txt` all carry the real
// code; the build-time pass in undocs then only re-confirms them.
export default {
  input: ["**/*.md"],
  ignore: ["**/node_modules", "**/.output", "**/.*"],
  generators: { region },
} satisfies Config;
