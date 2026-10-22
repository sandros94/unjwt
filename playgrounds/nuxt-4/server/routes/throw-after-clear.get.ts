import { defineEventHandler, createError } from "nuxt/server";

export default defineEventHandler(async (event) => {
  const session = await requireAppSession(event);
  await session.clear();

  throw createError({
    statusCode: 401,
    message: "Session cleared; this response should drop the cookie",
  });
});
