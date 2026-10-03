/** Concatenate multiple `Uint8Array`s into a single contiguous buffer. */
export function concatUint8Arrays(
  ...arrays: Readonly<Uint8Array<ArrayBuffer>[]>
): Uint8Array<ArrayBuffer> {
  const totalLength = arrays.reduce((length, arr) => length + arr.length, 0);
  const result = new Uint8Array(totalLength);

  let offset = 0;
  for (const arr of arrays) {
    result.set(arr, offset);
    offset += arr.length;
  }

  return result;
}

/** Wrap a value in an array; returns the array unchanged if already an array. */
export function maybeArray<T>(item: T | T[]): T[] {
  return Array.isArray(item) ? item : [item];
}
