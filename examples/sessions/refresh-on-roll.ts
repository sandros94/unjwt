import { generateJWK } from "unjwt/jwk";

// #region docs
import { defineJWESession } from "unjwt/session";

// #hide const key = the "oct" JWK from SESSION_KEY (see Configure a session)
const key = await generateJWK("A256GCM");
// #endhide

export interface AppSession {
  userId: string;
  /** Computed at sign-in and again at every roll. */
  grants: string[];
}

export const appSession = defineJWESession<AppSession, "7D">({
  key,
  maxAge: "7D",
  rolling: "1D",
  hooks: {
    async onRead({ session, roll }) {
      // The primary on a roll, a replica otherwise
      const user = await findUser(session.data.userId, { primary: roll.due });
      if (!user || user.blocked) {
        await session.clear();
        return;
      }
      if (roll.due) await session.update({ grants: user.grants });
    },
  },
});
// #endregion

export interface User {
  grants: string[];
  blocked: boolean;
}

/** Stands in for the application's user table. */
const users = new Map<string, User>();

export async function saveUser(userId: string, user: User): Promise<void> {
  users.set(userId, user);
}

/** `primary` picks the database an application reads: its primary, or a replica. */
async function findUser(userId: string, _options: { primary: boolean }): Promise<User | undefined> {
  return users.get(userId);
}
