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
 * test needs no prior build — minifies it, and asserts two things: the byte
 * size is at or under its ceiling, and the markers listed with it are absent.
 *
 * The ceiling is the size measured when the row was written, plus 15%, rounded
 * up to the next 100 bytes; the measurement is in the comment beside it. A
 * deliberate change that grows a bundle is a one-line diff: re-measure, and
 * update both the ceiling and the comment in the same edit.
 */

const SRC = fileURLToPath(new URL("../src/", import.meta.url));

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
} as const;

interface Entry {
  /** The single name imported from the module. */
  name: string;
  /** The module, relative to `src`. */
  module: string;
  /** Minified bytes this import may not exceed. */
  ceiling: number;
  /** Strings that must not appear in the bundle. */
  absent: ReadonlyArray<string>;
}

const ENTRIES: ReadonlyArray<Entry> = [
  // measured 23437
  {
    name: "verify",
    module: "core/jws.ts",
    ceiling: 26900,
    absent: [MARKERS.pem, MARKERS.pbes2, MARKERS.thumbprint],
  },
  // measured 17047
  {
    name: "sign",
    module: "core/jws.ts",
    ceiling: 19700,
    absent: [MARKERS.pem, MARKERS.pbes2, MARKERS.thumbprint],
  },
  // measured 36369
  { name: "decrypt", module: "core/jwe.ts", ceiling: 41700, absent: [MARKERS.thumbprint] },
  // measured 27772
  { name: "encrypt", module: "core/jwe.ts", ceiling: 32000, absent: [MARKERS.thumbprint] },
  // measured 8868
  { name: "importKey", module: "core/jwk.ts", ceiling: 10200, absent: [MARKERS.pem] },
  // measured 6929
  { name: "generateKey", module: "core/jwk.ts", ceiling: 8000, absent: [MARKERS.pem] },
  // measured 11451
  { name: "importPEM", module: "core/jwk.ts", ceiling: 13200, absent: [] },
  // measured 3225
  {
    name: "base64UrlParse",
    module: "core/utils/base64.ts",
    ceiling: 3800,
    absent: [MARKERS.subtleImport],
  },
  // measured 121
  {
    name: "isJWK",
    module: "core/utils/index.ts",
    ceiling: 200,
    absent: [MARKERS.randomBytes, MARKERS.base64],
  },
  // measured 3381
  {
    name: "validateJwtClaims",
    module: "core/utils/jwt.ts",
    ceiling: 3900,
    absent: [MARKERS.subtleImport],
  },
];

/** The id of the generated entry, `\0`-prefixed so nothing tries to read it. */
const VIRTUAL_ENTRY = "\0unjwt-bundle-entry";

describe("tree-shaking", () => {
  for (const entry of ENTRIES) {
    it(
      `ships ${entry.name} in at most ${entry.ceiling} bytes, and nothing else`,
      async () => {
        const code = await bundleImport(entry);
        const size = new TextEncoder().encode(code).length;
        expect(
          size,
          `${entry.name} bundles to ${size} bytes; re-measure and update the row if the growth is deliberate`,
        ).toBeLessThanOrEqual(entry.ceiling);
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
    const { output } = await build.generate({ format: "esm", minify: true });
    return output
      .filter((chunk) => chunk.type === "chunk")
      .map((chunk) => chunk.code)
      .join("");
  } finally {
    await build.close();
  }
}
