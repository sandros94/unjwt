import type { SessionDriver } from "../_driver.ts";

/** Types a session driver for a framework; pass it to `defineJWSSession` / `defineJWESession` as `{ driver }`. */
export function defineSessionDriver<TContext>(
  driver: SessionDriver<TContext>,
): SessionDriver<TContext> {
  return driver;
}
