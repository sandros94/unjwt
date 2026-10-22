import type { SessionDriver } from "./_driver.ts";

/** Types a session driver for a framework; pass it to `defineJWSSession` / `defineJWESession` as `{ driver }`. */
export function defineSessionDriver<TEvent>(driver: SessionDriver<TEvent>): SessionDriver<TEvent> {
  return driver;
}
