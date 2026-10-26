import { generateJWK } from "unjwt/jwk";

// #region docs
import { type SessionDefinition, defineJWSSession } from "unjwt/session";

// #hide const key = an HS256 JWK loaded at start-up (see Configure a session)
const key = await generateJWK("HS256");
// #endhide

export const appSession: SessionDefinition<{ userId: string }, "1h"> = defineJWSSession({
  key,
  maxAge: "1h",
  hooks: {
    onRead: ({ session }) => audit("read", session.id),
    onUpdate: ({ session, oldSession, trigger }) =>
      audit(trigger === "rolling" ? "rolled" : "issued", session.id, oldSession.id),
    onClear: ({ oldSession }) => audit("signed out", oldSession?.id),
    onExpire: ({ session }) => audit("expired", session.id),
    onError: ({ error }) => audit("refused", undefined, error.code),
  },
});
// #endregion

/** What the hooks recorded, oldest first. */
export const auditLog: string[][] = [];

function audit(event: string, ...details: Array<string | undefined>): void {
  auditLog.push([event, ...details.map((detail) => detail ?? "-")]);
}
