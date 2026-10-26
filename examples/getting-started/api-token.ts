// #region docs
import { sign, verify } from "unjwt/jws";
import type { JWSSignJWK, JWSVerifyJWK, JWTClaims } from "unjwt";

function jwkFromEnv(name: string) {
  const json = process.env[name];
  if (!json) throw new Error(`${name} is not set`);
  return JSON.parse(json);
}

const privateKey: JWSSignJWK = jwkFromEnv("TOKEN_PRIVATE_JWK");
const publicKey: JWSVerifyJWK = jwkFromEnv("TOKEN_PUBLIC_JWK");
const AUDIENCE = "https://api.example.com";

/** A token that lets `clientId` call the API for the next 15 minutes. */
export async function issueToken(clientId: string, scope: string): Promise<string> {
  return sign({ sub: clientId, aud: AUDIENCE, scope }, privateKey, { expiresIn: "15m" });
}

/** The claims of the request's bearer token; throws a `JWTError` when the token is bad. */
export async function authenticate(request: Request): Promise<JWTClaims> {
  const header = request.headers.get("authorization") ?? "";
  const token = header.startsWith("Bearer ") ? header.slice(7) : "";
  const { payload } = await verify(token, publicKey, {
    algorithms: ["ES256"],
    audience: AUDIENCE,
  });
  return payload;
}
// #endregion
