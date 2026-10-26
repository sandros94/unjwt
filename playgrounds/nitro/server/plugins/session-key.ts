// #region docs
import { definePlugin } from "nitro";

import { appSession } from "../utils/session.ts";

// A missing or malformed key stops the server at start-up, not at the first sign-in
export default definePlugin(() => {
  appSession();
});
// #endregion
