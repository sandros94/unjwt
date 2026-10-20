import { defineWebSocketHandler } from "nitro";
import type { SessionManager } from "unjwt/session";

import { type SessionData, useAppSession } from "../utils/session.ts";

export default defineWebSocketHandler({
  async upgrade(request) {
    // Named, not spread: on Nitro 3 the request is a `Request`, and a spread loses its `headers`.
    const headers = new Headers();
    const session = await useAppSession({
      headers: request.headers,
      context: request.context,
      res: { headers },
    });
    if (!session.id) throw new Response("Sign in first", { status: 401 });

    // `headers` ride on the 101 upgrade (a roll or a drop made during the read); `context` is
    // what every later hook gets as `peer.context`: a snapshot of the session, read once here.
    return { headers, context: { ...session } };
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

function getContext(peer: { context: Record<string, unknown> }): SessionManager<SessionData, "1h"> {
  return peer.context as unknown as SessionManager<SessionData, "1h">;
}
