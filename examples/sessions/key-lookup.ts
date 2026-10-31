// #region docs
import { type JWESessionOctJWK, defineJWESession } from "unjwt/session";

// #hide const secrets = your secret manager: get(name) resolves the secret stored under that name
export const secretStore = new Map<string, string>(
  Object.entries(JSON.parse(process.env.SECRETS ?? "{}")),
);
const secrets = { get: async (name: string) => secretStore.get(name) };
// #endhide

// The kid of the key that issues, set at deploy. Every session key stays in the secret manager under its kid
const currentKid = process.env.SESSION_KEY_ID;
if (!currentKid) throw new Error("SESSION_KEY_ID is not set");
const current = await sessionKey(currentKid);
if (!current) throw new Error(`No session key "${currentKid}" in the secret manager`);

export const appSession = defineJWESession<{ userId: string }, "7D">({
  key: current,
  maxAge: "7D",
  hooks: {
    async onKeyLookup({ header }) {
      return header.kid ? sessionKey(header.kid) : undefined;
    },
  },
});

async function sessionKey(kid: string): Promise<JWESessionOctJWK | undefined> {
  const json = await secrets.get(`session-keys/${kid}`);
  return json ? JSON.parse(json) : undefined;
}
// #endregion
