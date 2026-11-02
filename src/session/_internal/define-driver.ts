import type { SessionDriver } from "./driver.ts";

/** Returns `driver` typed as a `SessionDriver`. Pass it to `defineJWSSession` or `defineJWESession` as `{ driver }`. */
export function defineSessionDriver<TEvent>(driver: SessionDriver<TEvent>): SessionDriver<TEvent> {
  return driver;
}
