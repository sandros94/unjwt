import { defineConfig } from "nitro";

export default defineConfig({
  serverDir: "./server",
  features: { websocket: true },
});
