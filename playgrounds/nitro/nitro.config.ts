// #region docs
import { defineConfig } from "nitro";

export default defineConfig({
  serverDir: "./server",
  features: { websocket: true },
  runtimeConfig: {
    sessionKey: "", // NITRO_SESSION_KEY: the JSON of an HS256 JWK
  },
});
// #endregion
