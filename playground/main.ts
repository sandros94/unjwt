import { H3, HTTPError, serve } from "h3v2";

import {
  type SessionConfigJWE,
  type SessionConfigJWS,
  useJWESession,
  useJWSSession,
  getJWESession,
  updateJWSSession,
  generateJWK,
} from "../src/adapters/h3v2";

const atJwk = await generateJWK("RS256");

const jweOptions = {
  key: "refresh_token_secret",
  name: "refresh_token",
} satisfies SessionConfigJWE;

const jwsOptions = {
  key: atJwk,
  name: "access_token",
  maxAge: 15 * 60, // 15 minutes
  hooks: {
    async onExpire(event, _error, config) {
      const refreshSession = await getJWESession(event, jweOptions);
      if (!refreshSession.data.sub) {
        // no valid refresh session, nothing to do
        return;
      }

      console.log("Access token expired, refreshing...");

      // refresh the access token
      await updateJWSSession(event, config, {
        sub: refreshSession.data.sub,
        scope: refreshSession.data.scope,
      });
    },
  },
} satisfies SessionConfigJWS;

const app = new H3();

app.post("/login", async (event) => {
  const refreshSession = await useJWESession(event, jweOptions);
  const accessSession = await useJWSSession(event, jwsOptions);

  if (accessSession.data.sub) {
    // user already logged in, return existing info
    return {
      accessToken: {
        id: accessSession.id,
        createdAt: accessSession.createdAt,
        expiresAt: accessSession.expiresAt,
        data: accessSession.data,
      },
      refreshSession: {
        id: refreshSession.id,
        createdAt: refreshSession.createdAt,
        expiresAt: refreshSession.expiresAt,
        data: refreshSession.data,
      },
    };
  }

  const data = (await event.req.json()) as {
    username?: string;
    password?: string;
  };

  if (!data.username || !data.password) {
    throw new HTTPError("Username and password are required", { status: 400 });
  }

  // validate user credentials here

  const claims = {
    sub: data.username,
    scope: ["read:profile"],
  };

  await accessSession.update(claims);

  await refreshSession.update(claims);

  return {
    accessToken: {
      id: accessSession.id,
      createdAt: accessSession.createdAt,
      expiresAt: accessSession.expiresAt,
      data: accessSession.data,
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
