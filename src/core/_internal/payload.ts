import type { JWTClaimValidationOptions, JWTClaims, JOSEPayloadMode } from "../types/index.ts";
import { JWTError } from "../../error.ts";
import { validateJwtClaims } from "../../utils/jwt.ts";

/** Validates the JWT claims of a `"json"` payload, unless `validateClaims` is `false`. */
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

const CLAIM_OPTIONS = [
  "audience",
  "issuer",
  "subject",
  "maxTokenAge",
  "requiredClaims",
] as const satisfies readonly (keyof JWTClaimValidationOptions)[];

/**
 * Returns the payload mode, `"json"` by default.
 *
 * @throws `ERR_INVALID_OPTION` if `payload` is not `"json"`, `"string"` or `"bytes"`, `validateClaims: true`
 *   is set with a non-JSON payload, or a claim option is set while claims go unchecked.
 */
export function resolvePayloadMode(
  options: JWTClaimValidationOptions & {
    payload?: JOSEPayloadMode;
    validateClaims?: boolean;
  },
): JOSEPayloadMode {
  const { payload, validateClaims } = options;

  if (payload !== undefined && !PAYLOAD_MODES.has(payload)) {
    throw new JWTError('"payload" must be "json", "string" or "bytes".', "ERR_INVALID_OPTION");
  }

  const mode: JOSEPayloadMode = payload ?? "json";

  if (validateClaims === true && mode !== "json") {
    throw new JWTError('"validateClaims" requires payload: "json".', "ERR_INVALID_OPTION");
  }

  if (mode === "json" && validateClaims !== false) return mode;
  const option = CLAIM_OPTIONS.find((name) => options[name] !== undefined);
  if (option === undefined) return mode;
  throw new JWTError(
    mode === "json"
      ? `"${option}" needs claim validation: drop validateClaims: false or the option.`
      : `"${option}" needs a JSON payload: pass payload: "json" or drop the option.`,
    "ERR_INVALID_OPTION",
  );
}
