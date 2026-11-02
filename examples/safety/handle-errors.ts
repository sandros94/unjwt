// #region docs
import { isJWTError, type KnownJWTErrorCode } from "unjwt/error";
import type { JWKSet } from "unjwt/jwk";
import { verify } from "unjwt/jws";

/** Codes a bearer token can cause by itself: the client gets a 401, and nothing is logged as a bug. */
const TOKEN_CODES: ReadonlySet<string> = new Set([
  "ERR_JWS_INVALID",
  "ERR_JWS_SIGNATURE_INVALID",
  "ERR_JWS_ALG_NOT_ALLOWED",
  "ERR_JWK_KEY_NOT_FOUND",
  "ERR_JWT_NBF",
  "ERR_JWT_CLAIM_INVALID",
  "ERR_JWT_CLAIM_MISSING",
] satisfies KnownJWTErrorCode[]);

/** `GET /account`, for a request that carries `Authorization: Bearer <token>`. */
export function accountHandler(keys: JWKSet): (request: Request) => Promise<Response> {
  return async (request) => {
    const header = request.headers.get("authorization") ?? "";
    const token = header.startsWith("Bearer ") ? header.slice(7) : "";
    if (!token) return unauthorized("invalid_request", "A bearer token is required.");
    try {
      const { payload } = await verify(token, keys, {
        algorithms: ["ES256"],
        issuer: "https://auth.example.com",
        audience: "https://api.example.com",
      });
      return Response.json({ sub: payload.sub });
    } catch (error) {
      if (isJWTError(error, "ERR_JWT_EXPIRED")) {
        return unauthorized("invalid_token", "The token expired.");
      }
      if (isJWTError(error) && TOKEN_CODES.has(error.code)) {
        return unauthorized("invalid_token", "The token is not valid.");
      }
      // Anything else, such as ERR_INVALID_OPTION, is a bug on the server,
      // so it goes on to the fallback handler.
      throw error;
    }
  };
}

function unauthorized(code: string, description: string): Response {
  return new Response(null, {
    status: 401,
    headers: { "www-authenticate": `Bearer error="${code}", error_description="${description}"` },
  });
}
// #endregion

// #region fallback
/** The last stop for an error no route handled. */
export function errorResponse(error: unknown, log: (entry: object) => void) {
  if (isJWTError(error)) {
    // `cause` holds what failed underneath: the runtime's error, or one
    // error per key a JWK Set tried.
    log({ code: error.code, message: error.message, cause: error.cause });
  } else {
    log({ error });
  }
  return Response.json({ error: "Internal error." }, { status: 500 });
}
// #endregion
