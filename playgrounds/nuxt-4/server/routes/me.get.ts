import { defineEventHandler } from "nuxt/server";

export default defineEventHandler(async (event) => {
  const session = await requireAppSession(event);

  return { id: session.id, user: session.data.user, expiresAt: session.expiresAt };
});
