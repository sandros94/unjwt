// #region docs
import { sign, verify } from "unjwt/jws";
// #hide The issuer's key pair, loaded once at start-up: see /jwk/generate.
import { generateJWK } from "unjwt/jwk";
import type { JWSAsymmetricPrivateJWK, JWSAsymmetricPublicJWK } from "unjwt/jws";

const issuer = await generateJWK("ES256");
const privateKey: JWSAsymmetricPrivateJWK = issuer.privateKey;
const publicKey: JWSAsymmetricPublicJWK = issuer.publicKey;
// #endhide

export interface AccessClaims {
  sub: string;
  scope: string;
  iat: number;
  exp: number;
}

/** Issue an access token for one user, valid for 15 minutes. */
export function issueAccessToken(userId: string, scope: string): Promise<string> {
  return sign(
    { iss: "https://auth.example.com", aud: "https://api.example.com", sub: userId, scope },
    privateKey,
    {
      expiresIn: "15m",
      protectedHeader: { typ: "at+jwt" },
    },
  );
}

/** The claims of a token this API accepts, or a `JWTError` saying why not. */
export async function readAccessToken(token: string): Promise<AccessClaims> {
  const { payload } = await verify<AccessClaims>(token, publicKey, {
    algorithms: ["ES256"],
    typ: "at+jwt",
    issuer: "https://auth.example.com",
    audience: "https://api.example.com",
    requiredClaims: ["sub", "scope", "exp"],
    maxTokenAge: "1h",
    clockTolerance: 30,
  });
  return payload;
}
// #endregion

// #region time
/** Valid from the start of the event until it ends, whenever the ticket was issued. */
export function issueEventTicket(
  holder: string,
  event: { startsAt: Date; endsAt: Date },
): Promise<string> {
  return sign({ sub: holder, aud: "https://tickets.example.com" }, privateKey, {
    notBeforeAt: event.startsAt,
    expiresAt: event.endsAt,
  });
}
// #endregion

// #region crit
import type { JWTClaims } from "unjwt";

/** A token whose `crit` header names `tenant`, so a reader must say it understands it. */
export async function readTenantToken(
  token: string,
): Promise<{ tenant: unknown; payload: JWTClaims }> {
  const { payload, protectedHeader } = await verify(token, publicKey, {
    algorithms: ["ES256"],
    recognizedHeaders: ["tenant"],
  });
  return { tenant: protectedHeader.tenant, payload };
}
// #endregion

export { privateKey, publicKey };
