// #region docs
import { defineWebSocketHandler } from "nitro";
import type { SessionManager } from "unjwt/session";

import { type SessionData, useAppSession } from "../utils/session.ts";

export default defineWebSocketHandler({
  async upgrade(request) {
    // Named, not spread: the request is a `Request`, and a spread loses its `headers`
    const headers = new Headers();
    const session = await useAppSession({
      headers: request.headers,
      context: request.context,
      res: { headers },
    });
    if (!session.id) throw new Response("Sign in first", { status: 401 });

    // `headers` ride on the 101 response; `context` becomes every later hook's `peer.context`
    return { headers, context: { ...session } };
  },

  open(peer) {
    const { data } = getContext(peer);
    peer.send(`hello ${data.user}`);
  },

  message(peer, message) {
    const { expiresAt } = getContext(peer);
    if (expiresAt < Date.now()) {
      peer.close(4401, "Session expired");
      return;
    }
    peer.send(`echo: ${message.text()}`);
  },
});

function getContext(peer: { context: Record<string, unknown> }): SessionManager<SessionData, "1h"> {
  return peer.context as unknown as SessionManager<SessionData, "1h">;
}
// #endregion
