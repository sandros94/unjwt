import { readFile } from "node:fs/promises";
import { describe, expect, it } from "vitest";
import * as jws from "unjwt/jws";
import { generateJWK } from "unjwt/jwk";

const html = await readFile(
  new URL("../../../examples/recipes/cdn-page.html", import.meta.url),
  "utf8",
);
const region = /<!-- #region docs -->\n([\s\S]*?)<!-- #endregion -->/.exec(html)?.[1] ?? "";
const script = /<script type="module">([\s\S]*?)<\/script>/.exec(region)?.[1] ?? "";
const pinned = 'import { verify } from "https://esm.sh/unjwt@__UNJWT_VERSION__/jws";';

/** Runs the page's module script against a stub document and submits the form once. */
async function submit(fields: { token: string; jwk: string }): Promise<string> {
  let onSubmit: ((event: { preventDefault(): void }) => Promise<void>) | undefined;
  const output = { textContent: "" };
  const form = {
    elements: { token: { value: fields.token }, jwk: { value: fields.jwk } },
    addEventListener: (_type: string, listener: typeof onSubmit) => {
      onSubmit = listener;
    },
  };
  const document = { querySelector: (selector: string) => (selector === "form" ? form : output) };
  // oxlint-disable-next-line typescript/no-implied-eval -- the page's own script, loaded from the repository
  const run = new Function(
    "document",
    "unjwt",
    script.replace(pinned, "const { verify } = unjwt;"),
  );
  run(document, jws);
  await onSubmit?.({ preventDefault() {} });
  return output.textContent;
}

describe("examples/recipes/cdn-page", () => {
  it("pins the version and imports one subpath in a module script", () => {
    expect(region).toMatch(/^<!doctype html>/);
    expect(script).toContain(pinned);
  });

  it("shows the claims and the expiry of a valid token", async () => {
    const { privateKey, publicKey } = await generateJWK("ES256");
    const token = await jws.sign({ sub: "user_1a2b" }, privateKey, { expiresIn: "1h" });
    const shown = await submit({ token, jwk: JSON.stringify(publicKey) });
    expect(shown).toMatch(/^Valid, expires /);
    expect(shown).toContain('"sub": "user_1a2b"');
  });

  it("shows the error code of an expired token, a foreign key and a pasted mistake", async () => {
    const { privateKey, publicKey } = await generateJWK("ES256");
    const other = await generateJWK("ES256");
    const expired = await jws.sign({ sub: "user_1a2b" }, privateKey, {
      expiresAt: new Date(Date.now() - 60_000),
    });
    const token = await jws.sign({ sub: "user_1a2b" }, privateKey);
    expect(await submit({ token: expired, jwk: JSON.stringify(publicKey) })).toBe(
      "Not valid: ERR_JWT_EXPIRED",
    );
    expect(await submit({ token, jwk: JSON.stringify(other.publicKey) })).toBe(
      "Not valid: ERR_JWS_SIGNATURE_INVALID",
    );
    expect(await submit({ token, jwk: "not json" })).toMatch(/^Not valid: /);
  });
});
