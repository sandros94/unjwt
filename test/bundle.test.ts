// The bundler's JS API is a build-time tool, so this one test file reaches for
// Node's path helpers; nothing in `src` may. The reference is file-local, so
// the rest of the project still typechecks without Node's globals.
/// <reference types="node" />
import path from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { rolldown } from "rolldown";

/**
 * Every export path is a subpath of one code-split bundle, so a single import
 * must not drag the rest of the library along: `verify` has no business
 * carrying the PEM parser or PBES2, and a type guard must not pull in a codec
 * or the CSPRNG. `sideEffects: false` is what makes that true, and only a
 * bundler can tell whether it still does — an import moved to the wrong module
 * breaks it silently and shows up in someone's shipped bytes.
 *
 * Each row bundles a single named import from `src` — not from `dist`, so the
 * test needs no prior build — minifies it with every comment stripped, so the
 * `@__PURE__` annotations a minifier may keep do not count as code, and asserts
 * two things: the byte size is within `TOLERANCE` of the row's `measured`
 * value, and the markers listed with it are absent.
 *
 * `measured` is the size when the row was last measured, and the bound is
 * two-sided: growth means something was pulled in, a drastic shrink means a
 * check or branch was shaken out. A deliberate change in either direction is a
 * one-line diff: re-measure and update `measured`. A change you cannot explain
 * is the test doing its job.
 */

const SRC = fileURLToPath(new URL("../src/", import.meta.url));

/** Relative slack around `measured`, in both directions. */
const TOLERANCE = 0.15;

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
} as const;

interface Entry {
  /** The single name imported from the module. */
  name: string;
  /** The module, relative to `src`. */
  module: string;
  /** Minified bytes when the row was last measured; the test allows `TOLERANCE` either way. */
  measured: number;
  /** Strings that must not appear in the bundle. */
  absent: ReadonlyArray<string>;
  /** Imports left out of the bundle, as the build leaves out an adapter's framework. */
  external?: ReadonlyArray<string>;
}

const ENTRIES: ReadonlyArray<Entry> = [
  {
    name: "verify",
    module: "core/jws.ts",
    measured: 26846,
    absent: [MARKERS.pem, MARKERS.pbes2, MARKERS.thumbprint],
  },
  {
    name: "sign",
    module: "core/jws.ts",
    measured: 19789,
    absent: [MARKERS.pem, MARKERS.pbes2, MARKERS.thumbprint],
  },
  { name: "decrypt", module: "core/jwe.ts", measured: 39335, absent: [MARKERS.thumbprint] },
  { name: "encrypt", module: "core/jwe.ts", measured: 31818, absent: [MARKERS.thumbprint] },
  { name: "importKey", module: "core/jwk.ts", measured: 9338, absent: [MARKERS.pem] },
  // the thumbprint is the default `kid` of every JWK it emits
  { name: "generateKey", module: "core/jwk.ts", measured: 10719, absent: [MARKERS.pem] },
  { name: "importPEM", module: "core/jwk.ts", measured: 12053, absent: [] },
  {
    name: "base64UrlParse",
    module: "core/utils/base64.ts",
    measured: 3225,
    absent: [MARKERS.subtleImport],
  },
  {
    name: "isJWK",
    module: "core/utils/index.ts",
    measured: 132,
    absent: [MARKERS.randomBytes, MARKERS.base64],
  },
  {
    name: "validateJwtClaims",
    module: "core/utils/jwt.ts",
    measured: 4524,
    absent: [MARKERS.subtleImport],
  },
  // cookie-es is bundled, so the adapter must carry the parser rather than import it
  {
    name: "useJWSSession",
    module: "adapters/h3v1/index.ts",
    measured: 49085,
    absent: [MARKERS.cookieEs],
    external: ["h3v1"],
  },
];

/** The id of the generated entry, `\0`-prefixed so nothing tries to read it. */
const VIRTUAL_ENTRY = "\0unjwt-bundle-entry";

describe("tree-shaking", () => {
  for (const entry of ENTRIES) {
    it(
      `ships ${entry.name} in about ${entry.measured} bytes, and nothing else`,
      async () => {
        const code = await bundleImport(entry);
        const size = new TextEncoder().encode(code).length;
        const drift = (size - entry.measured) / entry.measured;
        expect(
          Math.abs(drift),
          `${entry.name} bundles to ${size} bytes, measured ${entry.measured}; re-measure and update the row if the change is deliberate`,
        ).toBeLessThanOrEqual(TOLERANCE);
        for (const marker of entry.absent) {
          expect(code, `${entry.name} bundle must not contain ${marker}`).not.toContain(marker);
        }
      },
      TIMEOUT,
    );
  }
});

/**
 * Bundle one named import and return the minified code. `console.log` is what
 * keeps the import alive: an unused one is exactly what tree-shaking removes,
 * which would measure nothing.
 */
async function bundleImport(entry: Entry): Promise<string> {
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
            ? `import { ${entry.name} } from ${JSON.stringify(path.join(SRC, entry.module))};\nconsole.log(${entry.name});\n`
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
