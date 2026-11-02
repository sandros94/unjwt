// #region docs
import { defineEventHandler } from "nuxt/server";

export default defineEventHandler(async (event) => {
  const session = await requireAppSession(event);
  return session.data;
});
// #endregion
