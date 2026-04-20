// @ts-nocheck

import { Resvg, initWasm } from "https://esm.sh/@resvg/resvg-wasm@2.6.2";
import pngToIco from "https://esm.sh/png-to-ico@2.1.8";
import { Buffer } from "node:buffer";

// resvg-wasm rasterizes the SVG. `@img/png` can only encode raw pixel
// buffers — it doesn't know how to read SVG markup — so we need a real
// renderer in between.
await initWasm(
  await fetch("https://unpkg.com/@resvg/resvg-wasm@2.6.2/index_bg.wasm"),
);

const DIR = ".docs/public";
const svg = await Deno.readTextFile(`${DIR}/icon.svg`);

const render = (size: number): Uint8Array =>
  new Resvg(svg, { fitTo: { mode: "width", value: size } }).render().asPng();

await Deno.writeFile(`${DIR}/icon.png`, render(512));
const ico = await pngToIco([16, 32, 48].map((s) => Buffer.from(render(s))));
await Deno.writeFile(`${DIR}/favicon.ico`, ico);

console.log("✓ icon.png (512×512)");
console.log("✓ favicon.ico (16+32+48)");
