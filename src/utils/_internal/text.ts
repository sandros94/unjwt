const MAX_QUOTED_VALUE = 64;

/** Returns `value` as text an error message can quote: JSON-quoted, cut to 64 characters. */
export function quoteTokenValue(value: unknown): string {
  const text = String(value);
  return JSON.stringify(
    text.length > MAX_QUOTED_VALUE ? `${text.slice(0, MAX_QUOTED_VALUE)}…` : text,
  );
}
