import type { SessionDriver } from "./driver.ts";

/**
 * Returns `driver` typed as a `SessionDriver`. Pass it to `defineJWSSession` or `defineJWESession` as `{ driver }`.
 * The Web driver, `webSessionDriver()`, is the reference implementation of the contract.
 */
export function defineSessionDriver<TEvent>(driver: SessionDriver<TEvent>): SessionDriver<TEvent> {
  return driver;
}
