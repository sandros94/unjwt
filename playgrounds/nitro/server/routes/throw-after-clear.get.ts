import { HTTPError, defineHandler } from "nitro";

import { requireAppSession } from "../utils/session.ts";

export default defineHandler(async (event) => {
  const session = await requireAppSession(event);
  await session.clear();

  throw new HTTPError({
    status: 401,
    message: "Session cleared; this response should drop the cookie",
  });
});
