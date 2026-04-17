/**
 * Originally derived from unsecure@0.0.4
 * Licensed under the MIT License.
 *
 * Source: https://github.com/sandros94/unsecure/blob/913ed5580c551153a19154b4916c67a8efb2be85/src/sanitize.ts
 */

/**
 * Returns a deep structural copy of `obj` with prototype-pollution vectors
 * stripped at every level (`__proto__`, `prototype`, `constructor`).
 *
 * The input is never modified. Arrays are copied element-by-element;
 * nested objects are recursed with a WeakSet cycle guard.
 */
export function sanitizeObject<T extends Record<string, unknown> | undefined>(obj: T): T {
  if (!obj || typeof obj !== "object") return obj;
  return _sanitizeCopy(obj, new WeakSet()) as T;
}

function _sanitizeCopy(current: object, seen: WeakSet<object>): unknown {
  seen.add(current);

  if (Array.isArray(current)) {
    return current.map((item) =>
      item && typeof item === "object" && !seen.has(item) ? _sanitizeCopy(item, seen) : item,
    );
  }

  const result: Record<string, unknown> = {};
  for (const [key, value] of Object.entries(current)) {
    if (key === "__proto__" || key === "prototype" || key === "constructor") continue;
    result[key] =
      value && typeof value === "object" && !seen.has(value as object)
        ? _sanitizeCopy(value as object, seen)
        : value;
  }
  return result;
}
