// The bundler's JS API is a build-time tool, so this one test file reaches for
// Node's path helpers; nothing in `src` may. The reference is file-local, so
// the rest of the project still typechecks without Node's globals.
/// <reference types="node" />
import path from "node:path";
import { fileURLToPath } from "node:url";
import { gzipSync } from "node:zlib";
import { describe, expect, it } from "vitest";
import { rolldown } from "rolldown";
import type { SizeMeta } from "./_size-reporter.ts";

/**
 * Every export path is a subpath of one code-split bundle, so a single import
 * must not drag the rest of the library along: `verify` has no business
 * carrying the PEM parser or PBES2, and a type guard must not pull in a codec
 * or the CSPRNG. `sideEffects: false` is what makes that true, and only a
 * bundler can tell whether it still does — an import moved to the wrong module
 * breaks it silently and shows up in someone's shipped bytes.
 *
 * Each row bundles one or more named imports from `src` — not from `dist`, so
 * the test needs no prior build — minifies them with every comment stripped,
 * so the `@__PURE__` annotations a minifier may keep do not count as code, and
 * asserts two things: the minified and the gzipped size are each within
 * `TOLERANCE` of the row's `measured` values, and the markers listed with it
 * are absent.
 *
 * Single-import rows guard tree-shaking; multi-import rows are what a consumer
 * actually ships for one use case, and are the numbers to watch. `measured` is
 * the size when the row was last measured, and the bound is two-sided: growth
 * means something was pulled in, a drastic shrink means a check or branch was
 * shaken out. A deliberate change in either direction is a one-line diff:
 * re-measure with `pnpm size` and update `measured`. A change you cannot
 * explain is the test doing its job.
 */

const SRC = fileURLToPath(new URL("../src/", import.meta.url));

/** Relative slack around `measured`, in both directions. */
const TOLERANCE = 0.03;

/** Absolute slack for rows too small for `TOLERANCE` to mean anything. */
const TOLERANCE_FLOOR_BYTES = 64;

/** Rolldown is fast, but a cold CI worker resolving a native binding is not. */
const TIMEOUT = 60_000;

/**
 * Strings that survive minification, so they can be asserted absent: an
 * armour label, an algorithm family name, an alphabet a codec is built around,
 * or a property name read off a global. Mangled local identifiers cannot be
 * used for this — these can.
 */
const MARKERS = {
  pem: "-----BEGIN",
  pbes2: "PBES2",
  base64: "abcdefghijklmnopqrstuvwxyz0123456789",
  randomBytes: "getRandomValues",
  subtleImport: "importKey",
  thumbprint: "JWK thumbprint",
  cookieEs: "cookie-es",
  h3Import: 'from"h3',
  elysiaImport: 'from"elysia"',
  dpop: "ERR_DPOP_",
} as const;

interface Entry {
  /** The names imported from the module; one for a tree-shaking guard, several for a use case. */
  imports: ReadonlyArray<string>;
  /** The module, relative to `src`. */
  module: string;
  /** Sizes when the row was last measured; the test allows `TOLERANCE` either way. */
  measured: { min: number; gzip: number };
  /** Strings that must not appear in the bundle. */
  absent: ReadonlyArray<string>;
  /** Imports left out of the bundle, as the build leaves out an adapter's framework. */
  external?: ReadonlyArray<string>;
}

const ENTRIES: ReadonlyArray<Entry> = [
  // --- one import: tree-shaking guards ---
  {
    imports: ["verify"],
    module: "core/jws.ts",
    measured: { min: 26503, gzip: 8860 },
    absent: [MARKERS.pem, MARKERS.pbes2, MARKERS.thumbprint],
  },
  {
    imports: ["sign"],
    module: "core/jws.ts",
    measured: { min: 21030, gzip: 7245 },
    absent: [MARKERS.pem, MARKERS.pbes2, MARKERS.thumbprint],
  },
  {
    imports: ["decrypt"],
    module: "core/jwe.ts",
    measured: { min: 38350, gzip: 12242 },
    absent: [MARKERS.thumbprint],
  },
  {
    imports: ["encrypt"],
    module: "core/jwe.ts",
    measured: { min: 32518, gzip: 10572 },
    absent: [MARKERS.thumbprint],
  },
  {
    imports: ["importKey"],
    module: "core/jwk.ts",
    measured: { min: 9377, gzip: 3626 },
    absent: [MARKERS.pem],
  },
  // the thumbprint is the default `kid` of every JWK it emits
  {
    imports: ["generateKey"],
    module: "core/jwk.ts",
    measured: { min: 11030, gzip: 4133 },
    absent: [MARKERS.pem],
  },
  {
    imports: ["importPEM"],
    module: "core/jwk.ts",
    measured: { min: 12116, gzip: 4698 },
    absent: [],
  },
  {
    imports: ["base64UrlParse"],
    module: "core/utils/base64.ts",
    measured: { min: 3277, gzip: 1578 },
    absent: [MARKERS.subtleImport],
  },
  {
    imports: ["isJWK"],
    module: "core/utils/index.ts",
    measured: { min: 132, gzip: 122 },
    absent: [MARKERS.randomBytes, MARKERS.base64],
  },
  {
    imports: ["validateJwtClaims"],
    module: "core/utils/jwt.ts",
    measured: { min: 4124, gzip: 1503 },
    absent: [MARKERS.subtleImport],
  },
  // --- use cases: what one consumer ships ---
  {
    imports: ["createDPoPProof"],
    module: "dpop/index.ts",
    measured: { min: 28281, gzip: 9416 },
    absent: [MARKERS.pem, MARKERS.pbes2, MARKERS.randomBytes, "ERR_DPOP_REPLAY"],
  },
  {
    imports: ["verifyDPoPProof"],
    module: "dpop/index.ts",
    measured: { min: 34225, gzip: 11200 },
    absent: [MARKERS.pem, MARKERS.pbes2, MARKERS.randomBytes, "randomUUID"],
  },
  {
    imports: ["createDPoPProof", "verifyDPoPProof"],
    module: "dpop/index.ts",
    measured: { min: 42689, gzip: 13373 },
    absent: [MARKERS.pem, MARKERS.pbes2, MARKERS.randomBytes],
  },
  {
    imports: ["sign", "verify"],
    module: "core/jws.ts",
    measured: { min: 33113, gzip: 10679 },
    absent: [MARKERS.pem, MARKERS.pbes2, MARKERS.thumbprint],
  },
  {
    imports: ["encrypt", "decrypt"],
    module: "core/jwe.ts",
    measured: { min: 53640, gzip: 16282 },
    absent: [MARKERS.thumbprint],
  },
  {
    imports: ["generateJWK", "exportJWK"],
    module: "core/jwk.ts",
    measured: { min: 11397, gzip: 4233 },
    absent: [MARKERS.pem],
  },
  // the Web entry imports no framework, and carries the cookie parser it uses
  {
    imports: ["defineJWSSession"],
    module: "session/index.ts",
    measured: { min: 54652, gzip: 17691 },
    absent: [MARKERS.cookieEs, MARKERS.h3Import, MARKERS.elysiaImport],
  },
  {
    imports: ["defineJWESession"],
    module: "session/index.ts",
    measured: { min: 76199, gzip: 24039 },
    absent: [MARKERS.cookieEs, MARKERS.h3Import, MARKERS.elysiaImport],
  },
  {
    imports: ["defineJWSSession"],
    module: "adapters/h3/index.ts",
    measured: { min: 48657, gzip: 15772 },
    absent: [MARKERS.cookieEs, MARKERS.elysiaImport],
    external: ["h3"],
  },
  // cookie-es is bundled, so the adapter must carry the parser rather than import it
  {
    imports: ["useJWSSession"],
    module: "adapters/h3v1/index.ts",
    measured: { min: 49691, gzip: 16148 },
    absent: [MARKERS.cookieEs],
    external: ["h3v1"],
  },
  {
    imports: ["jwsSession"],
    module: "adapters/elysia/index.ts",
    measured: { min: 48893, gzip: 15871 },
    absent: [MARKERS.cookieEs, MARKERS.h3Import],
    external: ["elysia"],
  },
];

/** The id of the generated entry, `\0`-prefixed so nothing tries to read it. */
const VIRTUAL_ENTRY = "\0unjwt-bundle-entry";

describe("tree-shaking", () => {
  for (const entry of ENTRIES) {
    const name = `${entry.imports.join(" + ")} (${entry.module})`;
    it(
      `ships ${name} in about ${entry.measured.min} bytes, and nothing else`,
      async (ctx) => {
        const code = await bundleImport(entry);
        const min = new TextEncoder().encode(code).length;
        const gzip = gzipSync(code, { level: 9 }).length;
        const size: SizeMeta = { min, gzip, measured: entry.measured };
        ctx.task.meta.size = size;

        expect(
          Math.abs(min - entry.measured.min),
          `${name} bundles to ${min} bytes minified, measured ${entry.measured.min}; re-measure with \`pnpm size\` and update the row if the change is deliberate`,
        ).toBeLessThanOrEqual(slack(entry.measured.min));
        expect(
          Math.abs(gzip - entry.measured.gzip),
          `${name} bundles to ${gzip} bytes gzipped, measured ${entry.measured.gzip}; re-measure with \`pnpm size\` and update the row if the change is deliberate`,
        ).toBeLessThanOrEqual(slack(entry.measured.gzip));
        const absent = entry.module.startsWith("dpop/")
          ? entry.absent
          : [...entry.absent, MARKERS.dpop];
        for (const marker of absent) {
          expect(code, `${name} bundle must not contain ${marker}`).not.toContain(marker);
        }
      },
      TIMEOUT,
    );
  }
});

function slack(measured: number): number {
  return Math.max(TOLERANCE_FLOOR_BYTES, measured * TOLERANCE);
}

/**
 * Bundle the named imports and return the minified code. `console.log` is what
 * keeps the imports alive: an unused one is exactly what tree-shaking removes,
 * which would measure nothing.
 */
async function bundleImport(entry: Entry): Promise<string> {
  const names = entry.imports.join(", ");
  const build = await rolldown({
    input: VIRTUAL_ENTRY,
    platform: "neutral",
    treeshake: true,
    logLevel: "silent",
    external: entry.external ? [...entry.external] : undefined,
    plugins: [
      {
        name: "virtual-entry",
        resolveId: (id) => (id === VIRTUAL_ENTRY ? id : null),
        load: (id) =>
          id === VIRTUAL_ENTRY
            ? `import { ${names} } from ${JSON.stringify(path.join(SRC, entry.module))};\nconsole.log(${names});\n`
            : null,
      },
    ],
  });
  try {
    const { output } = await build.generate({ format: "esm", minify: true, comments: false });
    return output
      .filter((chunk) => chunk.type === "chunk")
      .map((chunk) => chunk.code)
      .join("");
  } finally {
    await build.close();
  }
}
