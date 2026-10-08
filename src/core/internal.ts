/**
 * JOSE plumbing the `jws` and `jwe` modules are built from: header defaults,
 * payload parsing, plaintext encoding, time-claim computation and `crit`
 * checks.
 *
 * Internal: exposed for tests and tooling only. This entry point carries no
 * semver guarantee — any export may change or disappear in any release — and
 * it is not meant for production use. Production code reaches for `unjwt/jws`,
 * `unjwt/jwe` and `unjwt/utils`.
 *
 * @module
 */
export {
  type ParsePayloadOptions,
  type ComputeJwtTimeClaimsOptions,
  applyTypDefault,
  parsePayloadBytes,
  parsePayloadSegment,
  parsePayloadText,
  getPlaintextBytes,
  computeJwtTimeClaims,
  validateCriticalHeadersJWS,
  validateCriticalHeadersJWE,
  assertCritShape,
} from "./_jwt-internal";
