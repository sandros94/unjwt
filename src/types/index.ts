export * from "./jwk";
export * from "./jwt";
export * from "./jws";
export * from "./jwe";

export type ExpiresIn =
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
