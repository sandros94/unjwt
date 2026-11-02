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
}

const ENTRIES: ReadonlyArray<Entry> = [
  // --- one import: tree-shaking guards ---
  {
    imports: ["verify"],
    module: "core/jws/index.ts",
    measured: { min: 24768, gzip: 8250 },
    absent: [MARKERS.pem, MARKERS.pbes2, MARKERS.thumbprint],
  },
  {
    imports: ["sign"],
    module: "core/jws/index.ts",
    measured: { min: 21102, gzip: 7192 },
    absent: [MARKERS.pem, MARKERS.pbes2, MARKERS.thumbprint],
  },
  {
    imports: ["decrypt"],
    module: "core/jwe/index.ts",
    measured: { min: 36739, gzip: 11663 },
    absent: [MARKERS.thumbprint],
  },
  {
    imports: ["encrypt"],
    module: "core/jwe/index.ts",
    measured: { min: 32505, gzip: 10510 },
    absent: [MARKERS.thumbprint],
  },
  {
    imports: ["importKey"],
    module: "core/jwk/index.ts",
    measured: { min: 7755, gzip: 3015 },
    absent: [MARKERS.pem],
  },
  // the thumbprint is the default `kid` of every JWK it emits
  {
    imports: ["generateKey"],
    module: "core/jwk/index.ts",
    measured: { min: 12265, gzip: 4539 },
    absent: [MARKERS.pem],
  },
  {
    imports: ["importPEM"],
    module: "core/jwk/index.ts",
    measured: { min: 11146, gzip: 4320 },
    absent: [],
  },
  {
    imports: ["base64UrlParse"],
    module: "utils/base64.ts",
    measured: { min: 1134, gzip: 750 },
    absent: [MARKERS.subtleImport],
  },
  {
    imports: ["isJWK"],
    module: "utils/index.ts",
    measured: { min: 132, gzip: 122 },
    absent: [MARKERS.randomBytes, MARKERS.base64],
  },
  {
    imports: ["validateJwtClaims"],
    module: "utils/jwt.ts",
    measured: { min: 4172, gzip: 1530 },
    absent: [MARKERS.subtleImport],
  },
  // --- use cases: what one consumer ships ---
  {
    imports: ["createDPoPProof"],
    module: "dpop/index.ts",
    measured: { min: 28294, gzip: 9328 },
    absent: [MARKERS.pem, MARKERS.pbes2, MARKERS.randomBytes, "ERR_DPOP_REPLAY"],
  },
  {
    imports: ["verifyDPoPProof"],
    module: "dpop/index.ts",
    measured: { min: 32695, gzip: 10739 },
    absent: [MARKERS.pem, MARKERS.pbes2, MARKERS.randomBytes, "randomUUID"],
  },
  {
    imports: ["createDPoPProof", "verifyDPoPProof"],
    module: "dpop/index.ts",
    measured: { min: 43161, gzip: 13506 },
    absent: [MARKERS.pem, MARKERS.pbes2, MARKERS.randomBytes],
  },
  {
    imports: ["sign", "verify"],
    module: "core/jws/index.ts",
    measured: { min: 32807, gzip: 10518 },
    absent: [MARKERS.pem, MARKERS.pbes2, MARKERS.thumbprint],
  },
  {
    imports: ["encrypt", "decrypt"],
    module: "core/jwe/index.ts",
    measured: { min: 53619, gzip: 16239 },
    absent: [MARKERS.thumbprint],
  },
  {
    imports: ["generateJWK", "exportJWK"],
    module: "core/jwk/index.ts",
    measured: { min: 12632, gzip: 4630 },
    absent: [MARKERS.pem],
  },
  // the Web entry imports no framework, and carries the cookie parser it uses
  {
    imports: ["defineJWSSession"],
    module: "session/index.ts",
    measured: { min: 60046, gzip: 19427 },
    absent: [MARKERS.cookieEs, MARKERS.h3Import],
  },
  {
    imports: ["defineJWESession"],
    module: "session/index.ts",
    measured: { min: 80205, gzip: 25451 },
    absent: [MARKERS.cookieEs, MARKERS.h3Import],
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
