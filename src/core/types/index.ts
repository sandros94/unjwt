export * from "./jwk.ts";
export * from "./jwt.ts";
export * from "./jws.ts";
export * from "./jwe.ts";

/**
 * A duration: an integer number of seconds, or a string such as `"10m"`, `"2h"` or `"7D"`.
 * A string without a unit counts seconds. `"M"` is 30 days and `"Y"` is 365 days.
 * A non-integer number or an unparsed string throws `ERR_INVALID_OPTION`.
 */
export type Duration =
  | number
  | `${number}`
  | `${number}${
      | "s"
      | "second"
      | "seconds"
      | "m"
      | "minute"
      | "minutes"
      | "h"
      | "hour"
      | "hours"
      | "D"
      | "day"
      | "days"
      | "W"
      | "week"
      | "weeks"
      | "M"
      | "month"
      | "months"
      | "Y"
      | "year"
      | "years"}`;

/** The `expiresIn` option of `sign` and `encrypt`: `exp` is the current time plus this positive duration. */
export type ExpiresIn = Duration;

/** The `notBeforeIn` option of `sign` and `encrypt`: `nbf` is the current time plus this duration, zero or more. */
export type NotBeforeIn = Duration;

/** The `maxTokenAge` option of `verify` and `decrypt`: the oldest `iat` accepted, as a positive duration. */
export type MaxTokenAge = Duration;
