// #region docs
import { createError, defineEventHandler, readBody } from "nuxt/server";

export default defineEventHandler(async (event) => {
  const body = await readBody<{ user?: unknown } | undefined>(event);
  if (typeof body?.user !== "string") {
    throw createError({ statusCode: 400, message: "user required" });
  }
  const session = await useAppSession(event);
  await session.update({ user: body.user });
  return { user: session.data.user };
});
// #endregion
