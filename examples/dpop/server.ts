// #region token
import { isJWTError, verifyDPoPProof, type DPoPVerifyResult } from "unjwt/dpop";
import { generateJWK } from "unjwt/jwk";
import { sign, verify } from "unjwt/jws";
import { base64UrlStringify, digestUrl, secureRandomBytes } from "unjwt/utils";

const ISSUER = "https://auth.example.com";
const API = "https://api.example.com";
const MAX_AGE = 60;
const TOLERANCE = 5;

// #hide The issuer's key pair, loaded once at start-up: see /jwk/generate.
const { privateKey, publicKey } = await generateJWK("ES256");
// #endhide

/** `POST /token`, once your own code has authenticated the user. */
export async function tokenEndpoint(request: Request, userId: string) {
  const proof = request.headers.get("dpop");
  if (!proof || proof.includes(",")) {
    return Response.json({ error: "invalid_dpop_proof" }, { status: 400 });
  }
  let thumbprint: string;
  try {
    ({ thumbprint } = await verifyDPoPProof(proof, request, {
      algorithms: ["ES256", "EdDSA"],
      maxTokenAge: MAX_AGE,
      clockTolerance: TOLERANCE,
      consumeProof: consumeOnce,
    }));
  } catch (error) {
    if (isProofRejection(error)) {
      return Response.json({ error: "invalid_dpop_proof" }, { status: 400 });
    }
    throw error;
  }
  const token = await sign(
    { iss: ISSUER, aud: API, sub: userId, cnf: { jkt: thumbprint } },
    privateKey,
    {
      expiresIn: "10m",
      protectedHeader: { typ: "at+jwt" },
    },
  );
  return Response.json({ access_token: token, token_type: "DPoP", expires_in: 600 });
}
// #endregion

// #region resource
/** `GET /orders`, for `Authorization: DPoP <token>` plus one `DPoP` proof header. */
export async function ordersEndpoint(request: Request) {
  const authorization = request.headers.get("authorization") ?? "";
  const proof = request.headers.get("dpop");
  if (!authorization.startsWith("DPoP ") || !proof || proof.includes(",")) {
    return challenge("invalid_request");
  }
  const accessToken = authorization.slice(5);

  // 1. The access token is yours to validate. Its cnf.jkt names the bound key.
  let claims: { sub?: string; cnf?: { jkt?: string } };
  try {
    ({ payload: claims } = await verify(accessToken, publicKey, {
      algorithms: ["ES256"],
      typ: "at+jwt",
      issuer: ISSUER,
      audience: API,
    }));
  } catch (error) {
    if (isJWTError(error) && error.code !== "ERR_INVALID_OPTION") return challenge("invalid_token");
    throw error;
  }
  const jkt = claims.cnf?.jkt;
  if (!jkt) return challenge("invalid_token");

  // 2. The proof: this request, this token, the key the token is bound to.
  try {
    await verifyDPoPProof(proof, request, {
      algorithms: ["ES256", "EdDSA"],
      maxTokenAge: MAX_AGE,
      clockTolerance: TOLERANCE,
      nonce: currentNonce(),
      accessToken: { token: accessToken, thumbprint: jkt },
      consumeProof: consumeOnce,
    });
  } catch (error) {
    if (isJWTError(error, "ERR_DPOP_NONCE_INVALID")) {
      return challenge("use_dpop_nonce", { "dpop-nonce": currentNonce() });
    }
    if (isProofRejection(error)) return challenge("invalid_dpop_proof");
    throw error;
  }
  return Response.json({ sub: claims.sub, orders: [] });
}

/** A rejected proof, as opposed to a misconfigured server or a replay store that failed. */
function isProofRejection(error: unknown): boolean {
  if (isJWTError(error, "ERR_DPOP_REPLAY")) return error.cause === undefined;
  return isJWTError(error, "ERR_DPOP_INVALID") || isJWTError(error, "ERR_DPOP_CLAIM_INVALID");
}

function challenge(error: string, headers: Record<string, string> = {}): Response {
  return new Response(null, {
    status: 401,
    headers: { ...headers, "www-authenticate": `DPoP error="${error}", algs="ES256 EdDSA"` },
  });
}
// #endregion

// #region nonce
const NONCE_LIFETIME_MS = 5 * 60_000;
let nonce = { value: newNonce(), issuedAt: Date.now() };

/** The nonce proofs must carry; replaced every five minutes. */
export function currentNonce(now = Date.now()) {
  if (now - nonce.issuedAt >= NONCE_LIFETIME_MS) nonce = { value: newNonce(), issuedAt: now };
  return nonce.value;
}

function newNonce(): string {
  return base64UrlStringify(secureRandomBytes(16));
}
// #endregion

// #region replay
// One process only: several servers need a shared store with an atomic insert.
const seen = new Map<string, number>();

/** Accepts each proof once, per key, for as long as its `iat` keeps it acceptable. */
export async function consumeOnce({ payload, thumbprint }: DPoPVerifyResult) {
  const id = await digestUrl(`${thumbprint}.${payload.jti}`);
  const now = Math.floor(Date.now() / 1000);
  for (const [key, expiresAt] of seen) if (expiresAt < now) seen.delete(key);
  if (seen.has(id)) return false;
  seen.set(id, payload.iat + MAX_AGE + TOLERANCE);
  return true;
}
// #endregion
