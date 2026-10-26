import { generateJWK } from "unjwt/jwk";

// #region docs
import { type SessionSource, defineJWESession } from "unjwt/session";

// #hide const key = the "oct" JWK from SESSION_KEY (see Configure a session)
const key = await generateJWK("A256GCM");
// #endhide

const THIRTY_DAYS = 30 * 24 * 60 * 60 * 1000;

export interface AppSession {
  userId: string;
  /** Set at sign-in and kept by every later update. */
  signedInAt: number;
}

export const appSession = defineJWESession<AppSession, "7D">({
  key,
  maxAge: "7D",
  rolling: "1D",
  sessionHeader: true,
  hooks: {
    async onRead({ session }) {
      const { userId, signedInAt } = session.data;
      const signedOut = await signedOutEverywhereAt(userId);
      const tooOld = Date.now() - signedInAt > THIRTY_DAYS;
      if ((signedOut === undefined || signedInAt > signedOut) && !tooOld) return;
      if (session.source !== "cookie") await reportRevokedToken(userId, session.source);
      await session.clear();
    },
  },
});

/** "Sign out of all devices": every session signed in until now stops opening. */
export async function signOutEverywhere(userId: string) {
  await saveSignedOutEverywhereAt(userId, Date.now());
}
// #endregion

// #region sign-in
export async function signIn(req: Request, userId: string) {
  const headers = new Headers();
  const session = await appSession.use({ req, res: { headers } });
  await session.update({ userId, signedInAt: Date.now() });
  return new Response(null, { status: 204, headers });
}
// #endregion

/** Stands in for the application's security log. */
export const revokedTokenReports: { userId: string; source: SessionSource }[] = [];

async function reportRevokedToken(userId: string, source: SessionSource): Promise<void> {
  revokedTokenReports.push({ userId, source });
}

/** Stands in for the application's user table. */
const signedOutAt = new Map<string, number>();

async function signedOutEverywhereAt(userId: string): Promise<number | undefined> {
  return signedOutAt.get(userId);
}

async function saveSignedOutEverywhereAt(userId: string, at: number): Promise<void> {
  signedOutAt.set(userId, at);
}
