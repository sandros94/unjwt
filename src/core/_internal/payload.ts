import type { JWTClaimValidationOptions, JWTClaims, JOSEPayloadMode } from "../types/index.ts";
import { JWTError } from "../../error.ts";
import { validateJwtClaims } from "../../utils/jwt.ts";

/** Validate JWT claims of a `"json"` payload unless `validateClaims: false`. */
export function validateClaimsIfJson(
  payload: unknown,
  mode: JOSEPayloadMode,
  options: JWTClaimValidationOptions & { validateClaims?: boolean },
): void {
  if (mode !== "json" || options.validateClaims === false) return;
  // oxlint-disable-next-line typescript/no-unsafe-type-assertion -- validateJwtClaims checks each claim it reads
  validateJwtClaims(payload as JWTClaims, options);
}

const PAYLOAD_MODES: ReadonlySet<string> = /* @__PURE__ */ new Set([
  "json",
  "string",
  "bytes",
] satisfies JOSEPayloadMode[]);

/** Resolve the payload mode from `payload` / deprecated `forceUint8Array`; contradictions are `ERR_INVALID_OPTION`. */
export function resolvePayloadMode(options: {
  payload?: JOSEPayloadMode;
  forceUint8Array?: boolean;
  validateClaims?: boolean;
}): JOSEPayloadMode {
  const { payload, forceUint8Array, validateClaims } = options;

  if (payload !== undefined && !PAYLOAD_MODES.has(payload)) {
    throw new JWTError('"payload" must be "json", "string" or "bytes".', "ERR_INVALID_OPTION");
  }

  let mode: JOSEPayloadMode = payload ?? "json";
  if (forceUint8Array !== undefined) {
    if (payload === undefined) {
      mode = forceUint8Array ? "bytes" : "json";
    } else if (forceUint8Array !== (payload === "bytes")) {
      throw new JWTError(
        '"forceUint8Array" contradicts "payload", pass "payload" alone.',
        "ERR_INVALID_OPTION",
      );
    }
  }

  if (validateClaims === true && mode !== "json") {
    throw new JWTError('"validateClaims" requires payload: "json".', "ERR_INVALID_OPTION");
  }

  return mode;
}
