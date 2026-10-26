// #region docs
import { isJWTError } from "unjwt/error";
import type { JWTClaims } from "unjwt";
import { authenticate } from "./api-token.ts";

export async function listInvoices(request: Request): Promise<Response> {
  let claims: JWTClaims;
  try {
    claims = await authenticate(request);
  } catch (error) {
    if (isJWTError(error, "ERR_JWT_EXPIRED")) {
      return unauthorized('error="invalid_token", error_description="expired"');
    }
    if (isJWTError(error) && REJECTED.has(error.code)) {
      return unauthorized('error="invalid_token"');
    }
    throw error;
  }
  return Response.json({ client: claims.sub, invoices: [] });
}

// Codes that mean the client sent a bad token, not that your setup is wrong
const REJECTED = new Set<string>([
  "ERR_JWS_INVALID",
  "ERR_JWS_SIGNATURE_INVALID",
  "ERR_JWS_ALG_NOT_ALLOWED",
  "ERR_JWK_KEY_NOT_FOUND",
  "ERR_JWT_NBF",
  "ERR_JWT_CLAIM_INVALID",
  "ERR_JWT_CLAIM_MISSING",
]);

function unauthorized(challenge: string): Response {
  return new Response(null, {
    status: 401,
    headers: { "www-authenticate": `Bearer ${challenge}` },
  });
}
// #endregion
