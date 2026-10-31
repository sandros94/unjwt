// #region docs
import { defineEventHandler } from "nuxt/server";

export default defineEventHandler(async (event) => {
  const session = await useAppSession(event);
  await session.clear();
  return { ok: true };
});
// #endregion
