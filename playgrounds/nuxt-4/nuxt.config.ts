// #region docs
export default defineNuxtConfig({
  compatibilityDate: "2026-10-01",

  runtimeConfig: {
    sessionKey: "", // NUXT_SESSION_KEY: the JSON of an HS256 JWK
  },

  nitro: {
    experimental: { websocket: true },
  },
});
// #endregion
