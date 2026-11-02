// oxlint-disable typescript/consistent-return
// #region docs
import { defineWebSocketHandler } from "h3";
import type { SessionManager } from "unjwt/session";

export default defineWebSocketHandler({
  async upgrade(request) {
    // Named, not spread: on Nitro 3 the request is a `Request`, and a spread loses its `headers`
    const headers = new Headers();
    const session = await useAppSession({
      headers: request.headers,
      context: request.context,
      res: { headers },
    });
    if (!session.id) return new Response("Sign in first", { status: 401 });

    // `request.context` becomes every later hook's `peer.context`; `headers` ride on the 101 response
    Object.assign(request.context, session);
    return { headers };
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
