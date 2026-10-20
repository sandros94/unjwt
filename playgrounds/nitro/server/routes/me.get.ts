import { defineHandler } from "nitro";

import { requireAppSession } from "../utils/session.ts";

export default defineHandler(async (event) => {
  const session = await requireAppSession(event);

  return { id: session.id, user: session.data.user, expiresAt: session.expiresAt };
});
