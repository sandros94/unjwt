import { textEncoder } from "unsecure/utils";
import type { JOSEPayloadMode, PayloadOf } from "../../types/index.ts";
import { JWTError } from "../../../error.ts";
import { parsePayloadBytes, parsePayloadSegment } from "../../_internal/jwt.ts";

/** RFC 7797 §3 / §6: `b64` is a boolean, and `b64: false` must be listed in `crit`. */
export function checkJWSB64(header: { b64?: unknown; crit?: unknown }): JWTError | undefined {
  if (Object.hasOwn(header, "b64") && typeof header.b64 !== "boolean") {
    return new JWTError('Invalid JWS: "b64" must be a boolean.', "ERR_JWS_INVALID");
  }
  if (header.b64 !== false) return undefined;
  if (Array.isArray(header.crit) && header.crit.includes("b64")) return undefined;
  return new JWTError('Invalid JWS: "b64" must be listed in "crit".', "ERR_JWS_INVALID");
}

/** RFC 7797 §3: a caller's `b64` is a boolean. */
export function assertB64Option(header: { b64?: unknown } | undefined): void {
  if (!header || !Object.hasOwn(header, "b64") || typeof header.b64 === "boolean") return;
  throw new JWTError('"b64" must be a boolean.', "ERR_INVALID_OPTION");
}

/** Drops a `b64: true` that `crit` does not list. Adds `b64` to `crit` for `b64: false` (RFC 7797 §3 / §6). */
export function applyB64Header(header: { b64?: boolean; crit?: string[] }): void {
  assertB64Option(header);
  if (header.b64 === true) {
    if (!(Array.isArray(header.crit) && header.crit.includes("b64"))) delete header.b64;
    return;
  }
  if (header.b64 !== false) return;
  const crit = header.crit;
  if (crit === undefined) header.crit = ["b64"];
  else if (Array.isArray(crit) && !crit.includes("b64")) header.crit = [...crit, "b64"];
}

/** Decodes a JWS payload segment under the payload mode, honouring `b64: false` (RFC 7797). */
export function decodeJWSPayload(
  payloadSegment: string,
  useB64: boolean,
  mode: JOSEPayloadMode,
): PayloadOf<JOSEPayloadMode> {
  if (!useB64) {
    return mode === "string"
      ? payloadSegment
      : parsePayloadBytes(textEncoder.encode(payloadSegment), {
          payload: mode,
          family: "JWS",
        });
  }
  try {
    return parsePayloadSegment(payloadSegment, {
      payload: mode,
      family: "JWS",
    });
  } catch (error) {
    if (error instanceof JWTError) throw error;
    throw new JWTError("Invalid JWS: Payload could not be decoded.", "ERR_JWS_INVALID", error);
  }
}
