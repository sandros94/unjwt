import type { Reporter, TestCase } from "vitest/node";

/** What one bundle row measured, as `test/bundle.test.ts` records it on the task. */
export interface SizeMeta {
  /** Minified bytes. */
  min: number;
  /** Gzip (level 9) bytes of the minified code. */
  gzip: number;
  /** The row's recorded sizes, for the delta columns. */
  measured: { min: number; gzip: number };
}

declare module "vitest" {
  interface TaskMeta {
    size?: SizeMeta;
  }
}

/**
 * Prints the bundle rows as one table: minified and gzipped bytes, and the
 * drift from each row's recorded value. `pnpm size` runs the bundle test with
 * this reporter alone, so the table is the whole output.
 */
export default class SizeReporter implements Reporter {
  private readonly rows: Array<{ name: string; size: SizeMeta; failed: boolean }> = [];

  onTestCaseResult(testCase: TestCase): void {
    const { size } = testCase.meta();
    if (!size) return;
    const failed = testCase.result().state === "failed";
    this.rows.push({ name: rowName(testCase.name), size, failed });
  }

  onTestRunEnd(): void {
    const width = Math.max(8, ...this.rows.map((row) => row.name.length));
    const lines = [
      `${"scenario".padEnd(width)}  ${"min".padStart(8)}  ${"gzip".padStart(7)}  ${"Δmin".padStart(7)}  ${"Δgzip".padStart(7)}`,
    ];
    for (const { name, size, failed } of this.rows) {
      lines.push(
        `${name.padEnd(width)}  ${String(size.min).padStart(8)}  ${String(size.gzip).padStart(7)}  ${delta(size.min, size.measured.min).padStart(7)}  ${delta(size.gzip, size.measured.gzip).padStart(7)}${failed ? "  ✗" : ""}`,
      );
    }
    console.log(`\n${lines.join("\n")}\n`);
  }
}

function rowName(testName: string): string {
  return testName.replace(/^ships /, "").replace(/ in about .*$/, "");
}

function delta(actual: number, measured: number): string {
  if (measured === 0) return "new";
  const pct = ((actual - measured) / measured) * 100;
  return `${pct >= 0 ? "+" : ""}${pct.toFixed(1)}%`;
}
