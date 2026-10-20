import { defineHandler } from "nitro";

import { useAppSession } from "../utils/session.ts";

export default defineHandler(async (event) => {
  const session = await useAppSession(event);
  await session.clear();

  return { ok: true };
});
