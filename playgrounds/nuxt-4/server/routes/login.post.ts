import { defineEventHandler, readBody, createError } from "nuxt/server";

export default defineEventHandler(async (event) => {
  const body: { user?: unknown } | undefined = await readBody(event);

  if (typeof body?.user !== "string")
    throw createError({ statusCode: 400, message: "user required" });

  const session = await useAppSession(event);
  await session.update({ user: body.user });

  return { id: session.id, user: session.data.user, expiresAt: session.expiresAt };
});
