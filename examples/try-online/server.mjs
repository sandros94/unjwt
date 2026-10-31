import { H3, HTTPError, serve } from "h3";

import {
  defineJWESession,
  defineJWSSession,
  generateJWK,
  deriveJWKFromPassword,
} from "unjwt/session";

const [atJwk, rtJwk] = await Promise.all([
  generateJWK("RS256"),
  deriveJWKFromPassword("refresh_token_secret", {
    alg: "PBES2-HS256+A128KW",
    salt: "playground-salt",
    iterations: 600_000,
  }),
]);

const refreshToken = defineJWESession({
  key: rtJwk,
  name: "refresh_token",
  maxAge: 7 * 24 * 60 * 60, // 7 days
});

const accessToken = defineJWSSession({
  key: atJwk,
  name: "access_token",
  maxAge: 15 * 60, // 15 minutes
  hooks: {
    async onExpire({ event }) {
      const refreshSession = await refreshToken.use(event);
      if (!refreshSession.data.sub) {
        // no valid refresh session, nothing to do
        return;
      }

      console.log("Access token expired, refreshing...");

      // refresh the access token
      const accessSession = await accessToken.use(event);
      await accessSession.update({
        sub: refreshSession.data.sub,
        scope: refreshSession.data.scope,
      });
    },
  },
});

const app = new H3();

app.post("/login", async (event) => {
  const refreshSession = await refreshToken.use(event);
  const accessSession = await accessToken.use(event);

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

  const data = await event.req.json();

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
