import { deriveSecret, createError } from "nuxt/server";

import { type SessionDefinition, type WebSessionEvent, defineJWESession } from "unjwt/session";
import { base64UrlStringify } from "unjwt/utils";

type Definition = SessionDefinition<SessionData, "1h">;
let definition: Promise<Definition> | undefined;

/**
 * `deriveSecret` needs the Nuxt runtime config, so the definition is created on first use,
 * not at import time. Its 32 HKDF bytes are the A256GCM key as an `oct` JWK.
 */

async function define(): Promise<Definition> {
  const secret = await deriveSecret("unjwt:session");
  const bytes = Uint8Array.from(secret.match(/../g)!, (pair) => Number.parseInt(pair, 16));

  return defineJWESession<SessionData, "1h">({
    key: { kty: "oct", k: base64UrlStringify(bytes), alg: "A256GCM" },
    name: "unjwt-session",
    maxAge: "1h",
    rolling: "15m",
  });
}

export async function useAppSession(event: WebSessionEvent) {
  return (definition ??= define()).then((current) => current.use(event));
}

export async function requireAppSession(event: WebSessionEvent) {
  const current = await useAppSession(event);
  if (!current.id) throw createError({ statusCode: 401, message: "Sign in first" });
  return current;
}
