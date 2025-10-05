import { H3, HTTPError, serve } from "h3v2";

import {
  type SessionConfigJWE,
  type SessionConfigJWS,
  useJWESession,
  useJWSSession,
  generateJWK,
} from "../src/adapters/h3v2";

const atJwk = await generateJWK("RS256");

const jwsOptions = {
  key: atJwk,
  name: "access_token",
  maxAge: 15 * 60, // 15 minutes
} satisfies SessionConfigJWS;

const jweOptions = {
  key: "refresh_token_secret",
  name: "refresh_token",
} satisfies SessionConfigJWE;

const app = new H3();

app.post("/login", async (event) => {
  const data = (await event.req.json()) as {
    username?: string;
    password?: string;
  };

  if (!data.username || !data.password) {
    throw new HTTPError("Username and password are required", { status: 400 });
  }

  const accessSession = await useJWSSession(event, jwsOptions);
  await accessSession.update({
    sub: data.username,
    scope: ["read:profile"],
  });

  const refreshSession = await useJWESession(event, jweOptions);
  await refreshSession.update({
    sub: data.username,
  });

  return {
    accessToken: {
      id: accessSession.id,
      createdAt: accessSession.createdAt,
      expiresAt: accessSession.expiresAt,
      claims: accessSession.data,
    },
    refreshSession: {
      id: refreshSession.id,
      createdAt: refreshSession.createdAt,
      expiresAt: refreshSession.expiresAt,
      data: refreshSession.data,
    },
  };
});

serve(app);
