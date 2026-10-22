// oxlint-disable typescript/consistent-return
import { defineWebSocketHandler } from "h3";
import type { SessionManager } from "unjwt/session";

export default defineWebSocketHandler({
  async upgrade(request) {
    // Named, not spread: on Nitro 3 the request is a `Request`, and a spread loses its `headers`.
    const headers = new Headers();
    const session = await useAppSession({
      headers: request.headers,
      context: request.context,
      res: { headers },
    });
    if (!session.id) return new Response("Sign in first", { status: 401 });

    setContext(request, session);
    return { headers }; // a roll or a drop made during the read rides on the 101 upgrade
  },

  open(peer) {
    const { data } = getContext(peer);
    peer.send(`hello ${data.user}`);
  },

  message(peer, message) {
    const { expiresAt } = getContext(peer);
    if (expiresAt !== undefined && expiresAt < Date.now()) {
      peer.close(4401, "Session expired");
      return;
    }
    peer.send(`echo: ${message.text()}`);
  },

  close(peer, details) {
    const { data } = getContext(peer);
    console.log(`[ws] ${data.user} left (${details.code ?? "no code"})`);
  },
});

function setContext(
  request: { context: Record<string, unknown> },
  session: SessionManager<SessionData, "1h">,
) {
  Object.assign(request.context, session);
}
function getContext(peer: { context: Record<string, unknown> }): SessionManager<SessionData, "1h"> {
  return peer.context as unknown as SessionManager<SessionData, "1h">;
}
