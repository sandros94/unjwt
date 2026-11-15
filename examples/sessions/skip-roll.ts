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
      if (!roll.due) return;
      let grants: string[];
      try {
        grants = await loadGrants(session.data.userId);
      } catch (error) {
        if (!isUnavailable(error)) throw error;
        // Keep the session as issued, the next request tries again
        roll.skip();
        return;
      }
      await session.update({ grants });
    },
  },
});
// #endregion

/** Stands in for the error a database client throws when it cannot reach the database. */
export class DatabaseUnavailableError extends Error {}

/** Stands in for the application's grants table. */
const grantsTable = new Map<string, string[]>();

/** What every lookup throws while it is set. */
let failure: Error | undefined;

/** How many lookups ran. */
let lookups = 0;

export async function saveGrants(userId: string, grants: string[]): Promise<void> {
  grantsTable.set(userId, grants);
}

/** How many lookups ran so far, to tell whether a read asked the database. */
export function lookupCount(): number {
  return lookups;
}

/** Makes every lookup throw `error` until it is called again without one. */
export function failLookups(error?: Error): void {
  failure = error;
}

async function loadGrants(userId: string): Promise<string[]> {
  lookups++;
  if (failure) throw failure;
  return grantsTable.get(userId) ?? [];
}

/** Tells an unreachable database from any other failure, such as by its client's error code. */
function isUnavailable(error: unknown): boolean {
  return error instanceof DatabaseUnavailableError;
}
