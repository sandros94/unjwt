/**
 * Forked from unsecure@0.0.4
 * Licensed under the MIT License.
 *
 * Source: https://github.com/sandros94/unsecure/blob/913ed5580c551153a19154b4916c67a8efb2be85/src/sanitize.ts
 */

const DANGEROUS_KEYS = ["__proto__", "prototype", "constructor"] as const;

/**
 * Remove prototype-pollution vectors from a plain record in-place.
 * This strips __proto__, prototype, and constructor own properties.
 * Returns the same reference for convenience.
 */
export function sanitizeObject<T extends Record<string, unknown> | undefined>(
  obj: T,
): T {
  // Fast-path for non-objects and undefined
  if (!obj || typeof obj !== "object") return obj;

  const seen = new WeakSet<object>();

  visit(obj as any, seen);
  return obj;
}

function visit(current: any, seen: WeakSet<object>) {
  if (!current || typeof current !== "object") return;
  if (seen.has(current)) return;
  seen.add(current);

  // Remove dangerous own-properties with multiple strategies
  for (const key of DANGEROUS_KEYS) {
    if (Object.prototype.hasOwnProperty.call(current, key)) {
      try {
        // 1) direct delete
        // @ts-ignore
        delete current[key];
      } catch {
        /* ignore */
      }
      if (Object.prototype.hasOwnProperty.call(current, key)) {
        try {
          // 2) overwrite and try delete again
          (current as any)[key] = undefined;
          // @ts-ignore
          delete current[key];
        } catch {
          /* ignore */
        }
      }
      if (Object.prototype.hasOwnProperty.call(current, key)) {
        try {
          // 3) redefine as configurable then delete
          Object.defineProperty(current, key, {
            value: undefined,
            configurable: true,
            enumerable: false,
            writable: true,
          });
          // @ts-ignore
          delete current[key];
        } catch {
          /* ignore */
        }
      }
    }
  }
  // Attempt unconditional deletion as a final safeguard
  delete (current as any)["__proto__"];
  delete (current as any)["prototype"];
  delete (current as any)["constructor"];

  if (Array.isArray(current)) {
    for (const value of current) visit(value, seen);
    return;
  }

  // Only traverse own enumerable string-keyed properties
  for (const k of Object.keys(current))
    visit((current as Record<string, unknown>)[k], seen);
}
