export * from "./jwk";
export * from "./jwt";
export * from "./jws";
export * from "./jwe";

/**
 * A time duration, expressed as an integer number of seconds or a human-readable
 * shorthand like `"10m"`, `"2h"`, `"7D"`.
 *
 * Shared base type for every duration-valued option in the library:
 * {@link ExpiresIn}, {@link NotBeforeIn}, {@link MaxTokenAge}.
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

/** Duration until `exp` — the `expiresIn` option on {@link sign} / {@link encrypt}. */
export type ExpiresIn = Duration;

/** Duration from `iat` for `nbf` — the `notBeforeIn` option on {@link sign} / {@link encrypt}. */
export type NotBeforeIn = Duration;

/** Duration for `maxTokenAge` validation on {@link verify} / {@link decrypt}. */
export type MaxTokenAge = Duration;
