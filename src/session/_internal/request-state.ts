/** Session state per request object, created on first use and released with the object; each call keeps its own map. */
export function createRequestState(): (request: object) => Record<string, unknown> {
  const states = new WeakMap<object, Record<string, unknown>>();
  return (request) => {
    const existing = states.get(request);
    if (existing) return existing;
    const created: Record<string, unknown> = Object.create(null);
    states.set(request, created);
    return created;
  };
}
