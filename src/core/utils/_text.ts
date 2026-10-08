const MAX_QUOTED_VALUE = 64;

/**
 * A token- or key-supplied value as an error message may name it: JSON-quoted
 * and cut to a bounded length.
 */
export function quoteTokenValue(value: unknown): string {
  const text = String(value);
  return JSON.stringify(
    text.length > MAX_QUOTED_VALUE ? `${text.slice(0, MAX_QUOTED_VALUE)}…` : text,
  );
}
