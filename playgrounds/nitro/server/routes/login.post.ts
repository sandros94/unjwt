// #region docs
import { HTTPError, defineHandler } from "nitro";
import { readBody } from "nitro/h3";

import { useAppSession } from "../utils/session.ts";

export default defineHandler(async (event) => {
  const body = await readBody<{ user?: unknown }>(event);
  if (typeof body?.user !== "string") {
    throw new HTTPError({ status: 400, message: "user required" });
  }
  const session = await useAppSession(event);
  await session.update({ user: body.user });
  return { user: session.data.user };
});
// #endregion
